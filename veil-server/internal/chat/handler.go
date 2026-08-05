package chat

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	defaultConversationPageLimit = 100
	absolutePageLimit            = 500
	// Keep this wire contract aligned with
	// veil-client::direct_history::DIRECT_HISTORY_RESPONSE_LIMIT. The encoded
	// body includes the same trailing newline as json.Encoder.
	maxMessageHistoryResponseBytes = 4 * 1024 * 1024
	// Bound database materialization and row encoding independently of the
	// legacy desktop request limit. Native Direct history requests 25 rows, and
	// larger legacy limits remain accepted but are served through keyset pages.
	maxMessageHistoryCandidateRows = 25
)

var errMessageHistoryRowExceedsWireBudget = errors.New("message history row exceeds wire budget")

type messageHistoryReactionJSON struct {
	Emoji    string `json:"emoji"`
	UserID   string `json:"user_id"`
	Username string `json:"username"`
}

type messageHistoryAttachmentJSON struct {
	MediaID      string `json:"media_id"`
	EncryptedKey string `json:"encrypted_key"`
	Nonce        string `json:"nonce"`
	Size         int64  `json:"size"`
	ContentType  string `json:"content_type"`
}

type messageHistoryMessageJSON struct {
	ID                        string                         `json:"id"`
	ConversationID            string                         `json:"conversation_id"`
	SenderID                  string                         `json:"sender_id"`
	SenderIdentityKey         string                         `json:"sender_identity_key"`
	SenderSigningKey          string                         `json:"sender_signing_key"`
	Ciphertext                string                         `json:"ciphertext"` // lowercase hex (legacy wire contract)
	Header                    string                         `json:"header"`     // lowercase hex (legacy wire contract)
	MsgType                   int16                          `json:"msg_type"`
	ReplyToID                 *string                        `json:"reply_to_id,omitempty"`
	ExpiresAt                 *string                        `json:"expires_at,omitempty"`
	EditedAt                  *string                        `json:"edited_at"`
	IsDeleted                 bool                           `json:"is_deleted"`
	IsExpired                 bool                           `json:"is_expired"`
	Reactions                 []messageHistoryReactionJSON   `json:"reactions"`
	Attachments               []messageHistoryAttachmentJSON `json:"attachments"`
	CreatedAt                 string                         `json:"created_at"`
	ServerTimestamp           int64                          `json:"server_timestamp"`
	RevisionTimestamp         int64                          `json:"revision_timestamp"`
	CryptoProfile             string                         `json:"crypto_profile"`
	CryptoEra                 string                         `json:"crypto_era,omitempty"`
	RosterVersion             string                         `json:"roster_version,omitempty"`
	RosterCommitment          string                         `json:"roster_commitment,omitempty"`
	MembershipEpoch           string                         `json:"membership_epoch,omitempty"`
	MembershipEpochHash       string                         `json:"membership_epoch_hash,omitempty"`
	SenderDeviceID            string                         `json:"sender_device_id,omitempty"`
	SenderBindingVersion      string                         `json:"sender_binding_version,omitempty"`
	SenderDeviceIdentityKey   string                         `json:"sender_device_identity_key,omitempty"`
	SenderDeviceSigningKey    string                         `json:"sender_device_signing_key,omitempty"`
	SenderDeviceCapabilities  string                         `json:"sender_device_capabilities,omitempty"`
	SenderDeviceBindingStatus uint8                          `json:"sender_device_binding_status,omitempty"`
	SenderAccountSignature    string                         `json:"sender_account_signature,omitempty"`
	TargetDeviceID            string                         `json:"target_device_id,omitempty"`
	TargetBindingVersion      string                         `json:"target_binding_version,omitempty"`
	DirectSessionID           string                         `json:"direct_session_id,omitempty"`
}

// Field order is intentional: encodeMessageHistoryPageWithinBudget accounts
// for this exact compact representation before the response is written.
type messageHistoryPageJSON struct {
	Count      int                         `json:"count"`
	Messages   []messageHistoryMessageJSON `json:"messages"`
	NextCursor *string                     `json:"next_cursor,omitempty"`
}

// Handler provides REST endpoints for the chat service.
// Message sync, conversation management.
type Handler struct {
	svc            *Service
	mw             *authmw.Middleware
	restDispatcher *authmw.RESTAuthVersionDispatcher
	rl             *authmw.RateLimit
}

// NewHandler builds the chat REST handler. A nil middleware is reserved for
// direct-handler unit tests; every server entry point installs REST v2.
func NewHandler(svc *Service, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return &Handler{svc: svc, mw: mw, rl: rl}
}

// SetRESTAuthVersionDispatcher activates mandatory REST v2 authentication for
// every signed chat route. A configured middleware without it fails closed.
func (h *Handler) SetRESTAuthVersionDispatcher(dispatcher *authmw.RESTAuthVersionDispatcher) {
	h.restDispatcher = dispatcher
}

// SigningKeyLookup returns an authmw.UserKeyLookup backed by the service's
// database, for use when constructing the shared signing middleware.
func (s *Service) SigningKeyLookup() authmw.UserKeyLookup {
	return authmw.LookupFunc(func(ctx context.Context, userID string) (ed25519.PublicKey, error) {
		if s == nil || s.db == nil || s.db.Pool == nil {
			return nil, errors.New("signing key lookup database is unavailable")
		}
		u, err := s.db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, authmw.NormalizeSigningKeyLookupError(ctx, err, pgx.ErrNoRows)
		}
		if u == nil {
			return nil, errors.New("signing key lookup returned no account row")
		}
		return ed25519.PublicKey(u.SigningKey), nil
	})
}

// RegisterRoutes registers chat REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(policy authmw.RESTAuthV2HTTPPolicy, f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.restDispatcher != nil {
			f = h.restDispatcher.RequireSigned(policy, f)
		} else if h.mw != nil {
			var unavailable *authmw.RESTAuthVersionDispatcher
			f = unavailable.RequireSigned(policy, f)
		}
		return f
	}
	jsonPolicy, err := authmw.NewRESTAuthV2JSONHTTPPolicy(64 * 1024)
	if err != nil {
		panic("invalid chat REST v2 JSON policy")
	}
	bodylessPolicy := authmw.RESTAuthV2BodylessHTTPPolicy()

	// no-store remains outermost so authenticated chat state cannot be cached
	// even when signature verification or rate limiting rejects the request.
	mux.HandleFunc("GET /v1/messages/{conversationID}", chatNoStore(signed(bodylessPolicy, h.GetMessages)))
	mux.HandleFunc("GET /v1/conversations", chatNoStore(signed(bodylessPolicy, h.ListConversations)))
	mux.HandleFunc("GET /v1/conversations/{conversationID}", chatNoStore(signed(bodylessPolicy, h.GetConversation)))
	mux.HandleFunc("POST /v1/conversations/dm", signed(jsonPolicy, h.CreateDM))
	mux.HandleFunc("GET /v1/conversations/{conversationID}/members", chatNoStore(signed(bodylessPolicy, h.GetMembers)))
	mux.HandleFunc("GET /v1/conversations/{conversationID}/device-directory", chatNoStore(signed(bodylessPolicy, h.GetDeviceDirectory)))
	mux.HandleFunc("GET /v1/conversations/{conversationID}/membership-epochs", chatNoStore(signed(bodylessPolicy, h.ListMembershipEpochsV1)))
	mux.HandleFunc("POST /v1/conversations/{conversationID}/membership-epochs", chatNoStore(signed(jsonPolicy, h.StoreMembershipEpochV1)))

	// Group endpoints
	mux.HandleFunc("POST /v1/groups", signed(jsonPolicy, h.CreateGroup))
	mux.HandleFunc("POST /v1/groups/{groupID}/members", signed(jsonPolicy, h.AddGroupMember))
	mux.HandleFunc("DELETE /v1/groups/{groupID}/members/{userID}", signed(bodylessPolicy, h.RemoveGroupMember))
	mux.HandleFunc("GET /v1/groups/{groupID}/members", chatNoStore(signed(bodylessPolicy, h.GetGroupMembers)))
}

func chatNoStore(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next(w, r)
	}
}

// --- Message Sync (store-and-forward) ---

func (h *Handler) GetMessages(w http.ResponseWriter, r *http.Request) {
	conversationID := r.PathValue("conversationID")
	conversationUUID, err := uuid.Parse(conversationID)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("conversation_id required"))
		return
	}
	conversationID = conversationUUID.String()

	// Caller must provide user_id header (set by gateway after auth)
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	maxLimit := configuredPageLimit(h.svc.cfg.MessageBatchLimit)
	requestedLimit, err := parsePageLimit(r.URL.Query().Get("limit"), maxLimit, maxLimit)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_page_limit", "invalid pagination limit", err,
		))
		return
	}
	candidateLimit := messageHistoryCandidateLimit(requestedLimit)

	// `since` is retained for compatibility.  New clients should use the
	// opaque keyset cursor because a timestamp alone cannot distinguish rows
	// created in the same database clock tick.
	sinceStr := r.URL.Query().Get("since")
	cursorStr := r.URL.Query().Get("cursor")
	if sinceStr != "" && cursorStr != "" {
		writeJSON(w, http.StatusBadRequest, errorResp("since and cursor are mutually exclusive"))
		return
	}

	after := time.Time{}
	afterID := ""
	if sinceStr != "" {
		after, err = time.Parse(time.RFC3339Nano, sinceStr)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("since must be an RFC3339 timestamp"))
			return
		}
	} else if cursorStr != "" {
		cursor, decodeErr := decodePageCursor(cursorStr, "messages", conversationID)
		if decodeErr != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid or out-of-scope cursor"))
			return
		}
		after = cursor.CreatedAt
		afterID = cursor.ID
	}

	history, err := h.svc.db.GetConversationHistoryPage(
		r.Context(), conversationID, userID, after, afterID, candidateLimit+1,
	)
	if err != nil {
		if errors.Is(err, db.ErrConversationAccessDenied) {
			writeJSON(w, http.StatusForbidden, errorResp("not a conversation member"))
			return
		}
		log.Printf("get messages error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch messages"))
		return
	}
	msgs := history.Messages

	rowsRemainAfterCandidateSet := len(msgs) > candidateLimit
	if rowsRemainAfterCandidateSet {
		msgs = msgs[:candidateLimit]
	}
	reactionsByMessage := make(map[string][]messageHistoryReactionJSON, len(msgs))
	attachmentsByMessage := make(map[string][]messageHistoryAttachmentJSON, len(msgs))
	if len(msgs) != 0 {
		for _, reaction := range history.Reactions {
			if reaction.ConversationID != conversationID {
				log.Printf(
					"reaction message_ref=%s has unexpected conversation_ref=%s",
					logsafe.Ref("message", reaction.MessageID),
					logsafe.Ref("conversation", reaction.ConversationID),
				)
				writeJSON(w, http.StatusInternalServerError, errorResp("invalid reaction state"))
				return
			}
			reactionsByMessage[reaction.MessageID] = append(reactionsByMessage[reaction.MessageID], messageHistoryReactionJSON{
				Emoji: reaction.Emoji, UserID: reaction.UserID, Username: reaction.Username,
			})
		}
		for _, attachment := range history.Attachments {
			attachmentsByMessage[attachment.MessageID] = append(
				attachmentsByMessage[attachment.MessageID],
				messageHistoryAttachmentJSON{
					MediaID:      attachment.FileID,
					EncryptedKey: base64.StdEncoding.EncodeToString(attachment.EncryptedKey),
					Nonce:        base64.StdEncoding.EncodeToString(attachment.Nonce),
					Size:         attachment.SizeBytes,
					ContentType:  "application/octet-stream",
				},
			)
		}
	}

	result := make([]messageHistoryMessageJSON, 0, len(msgs))
	now := time.Now()
	for _, m := range msgs {
		if len(m.SenderIdentityKey) != 32 || len(m.SenderSigningKey) != ed25519.PublicKeySize {
			log.Printf("message_ref=%s sender_ref=%s has invalid public key material", logsafe.Ref("message", m.ID), logsafe.Ref("user", m.SenderID))
			writeJSON(w, http.StatusInternalServerError, errorResp("sender cryptographic identity is invalid"))
			return
		}
		isExpired := m.ExpiresAt != nil && !m.ExpiresAt.After(now)
		ciphertext := ""
		header := ""
		if !m.IsDeleted && !isExpired {
			ciphertext = hex.EncodeToString(m.Ciphertext)
			header = hex.EncodeToString(m.Header)
		}
		reactions := reactionsByMessage[m.ID]
		if reactions == nil {
			reactions = make([]messageHistoryReactionJSON, 0)
		}
		attachments := make([]messageHistoryAttachmentJSON, 0)
		if !m.IsDeleted && !isExpired {
			attachments = attachmentsByMessage[m.ID]
			if attachments == nil {
				attachments = make([]messageHistoryAttachmentJSON, 0)
			}
		}
		revisionTimestamp := m.CreatedAt.UnixMilli()
		if m.EditedAt != nil {
			revisionTimestamp = m.EditedAt.UnixMilli()
		}
		mj := messageHistoryMessageJSON{
			ID:                m.ID,
			ConversationID:    m.ConversationID,
			SenderID:          m.SenderID,
			SenderIdentityKey: hex.EncodeToString(m.SenderIdentityKey),
			SenderSigningKey:  hex.EncodeToString(m.SenderSigningKey),
			Ciphertext:        ciphertext,
			Header:            header,
			MsgType:           m.MsgType,
			ReplyToID:         m.ReplyToID,
			IsDeleted:         m.IsDeleted,
			IsExpired:         isExpired,
			Reactions:         reactions,
			Attachments:       attachments,
			CreatedAt:         m.CreatedAt.UTC().Format(time.RFC3339Nano),
			ServerTimestamp:   m.CreatedAt.UnixMilli(),
			RevisionTimestamp: revisionTimestamp,
			CryptoProfile:     "legacy_unknown",
		}
		if m.SecurityContext != nil {
			security := m.SecurityContext
			mj.CryptoProfile = security.CryptoProfile
			mj.CryptoEra = strconv.FormatUint(security.CryptoEra, 10)
			mj.SenderDeviceID = hex.EncodeToString(security.SenderDeviceID)
			mj.SenderBindingVersion = strconv.FormatUint(security.SenderBindingVersion, 10)
			switch security.CryptoProfile {
			case db.MessageCryptoProfileSenderKeyV5:
				if security.CryptoEra != db.MessageCryptoEraSenderKeyV5 ||
					security.RosterVersion == 0 || len(security.RosterCommitment) != 32 ||
					len(security.SenderDeviceID) != 16 || security.SenderBindingVersion == 0 {
					log.Printf("message_ref=%s has invalid Sender-Key context", logsafe.Ref("message", m.ID))
					writeJSON(w, http.StatusInternalServerError, errorResp("message security context is invalid"))
					return
				}
				mj.RosterVersion = strconv.FormatUint(security.RosterVersion, 10)
				mj.RosterCommitment = hex.EncodeToString(security.RosterCommitment)
			case db.MessageCryptoProfileSenderKeyV6:
				if security.CryptoEra != db.MessageCryptoEraSenderKeyV6 ||
					security.RosterVersion == 0 || len(security.RosterCommitment) != 32 ||
					security.MembershipEpoch == 0 || len(security.MembershipEpochHash) != 32 ||
					len(security.SenderDeviceID) != 16 || security.SenderBindingVersion == 0 {
					log.Printf("message_ref=%s has invalid Sender-Key v6 context", logsafe.Ref("message", m.ID))
					writeJSON(w, http.StatusInternalServerError, errorResp("message security context is invalid"))
					return
				}
				mj.RosterVersion = strconv.FormatUint(security.RosterVersion, 10)
				mj.RosterCommitment = hex.EncodeToString(security.RosterCommitment)
				mj.MembershipEpoch = strconv.FormatUint(security.MembershipEpoch, 10)
				mj.MembershipEpochHash = hex.EncodeToString(security.MembershipEpochHash)
			case db.MessageCryptoProfileDirectV2:
				if security.CryptoEra != db.MessageCryptoEraDirectV2 ||
					len(security.SenderDeviceID) != 16 || security.SenderBindingVersion == 0 ||
					len(security.SenderDeviceIdentityKey) != 32 ||
					len(security.SenderDeviceSigningKey) != 32 ||
					security.SenderDeviceCapabilities == 0 ||
					security.SenderDeviceBindingStatus != db.DeviceBindingActive ||
					len(security.SenderAccountSignature) != 64 ||
					len(security.TargetDeviceID) != 16 || security.TargetBindingVersion == 0 ||
					len(security.DirectSessionID) != 32 {
					log.Printf("message_ref=%s has invalid Direct v2 context", logsafe.Ref("message", m.ID))
					writeJSON(w, http.StatusInternalServerError, errorResp("message security context is invalid"))
					return
				}
				mj.SenderDeviceIdentityKey = hex.EncodeToString(security.SenderDeviceIdentityKey)
				mj.SenderDeviceSigningKey = hex.EncodeToString(security.SenderDeviceSigningKey)
				mj.SenderDeviceCapabilities = strconv.FormatUint(security.SenderDeviceCapabilities, 10)
				mj.SenderDeviceBindingStatus = uint8(security.SenderDeviceBindingStatus)
				mj.SenderAccountSignature = hex.EncodeToString(security.SenderAccountSignature)
				mj.TargetDeviceID = hex.EncodeToString(security.TargetDeviceID)
				mj.TargetBindingVersion = strconv.FormatUint(security.TargetBindingVersion, 10)
				mj.DirectSessionID = hex.EncodeToString(security.DirectSessionID)
			default:
				log.Printf("message_ref=%s has unknown persisted security context", logsafe.Ref("message", m.ID))
				writeJSON(w, http.StatusInternalServerError, errorResp("message security context is invalid"))
				return
			}
		}
		if m.ExpiresAt != nil {
			t := m.ExpiresAt.UTC().Format(time.RFC3339)
			mj.ExpiresAt = &t
		}
		if m.EditedAt != nil {
			t := m.EditedAt.UTC().Format(time.RFC3339Nano)
			mj.EditedAt = &t
		}
		result = append(result, mj)
	}

	encoded, _, encodeErr := encodeMessageHistoryPageWithinBudget(
		result,
		msgs,
		rowsRemainAfterCandidateSet,
		maxMessageHistoryResponseBytes,
	)
	if encodeErr != nil {
		log.Printf("encode message page: class=%s", logsafe.ErrorClass(encodeErr))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to paginate messages"))
		return
	}
	writeEncodedJSON(w, http.StatusOK, encoded)
}

// --- Offline conversation discovery ---

type conversationMemberJSON struct {
	UserID      string `json:"user_id"`
	Username    string `json:"username"`
	IdentityKey string `json:"identity_key"`
	SigningKey  string `json:"signing_key"`
	Role        int16  `json:"role"`
	JoinedAt    string `json:"joined_at"`
}

type conversationJSON struct {
	ID        string                   `json:"id"`
	ConvType  int16                    `json:"conv_type"`
	Name      *string                  `json:"name"`
	ServerID  *string                  `json:"server_id"`
	CreatedAt string                   `json:"created_at"`
	Members   []conversationMemberJSON `json:"members"`
}

func publicConversation(conversation db.ConversationDiscovery) (conversationJSON, error) {
	members := make([]conversationMemberJSON, 0, len(conversation.Members))
	for _, member := range conversation.Members {
		if len(member.IdentityKey) != 32 || len(member.SigningKey) != ed25519.PublicKeySize {
			return conversationJSON{}, errors.New("member cryptographic identity is invalid")
		}
		members = append(members, conversationMemberJSON{
			UserID:      member.UserID,
			Username:    member.Username,
			IdentityKey: hex.EncodeToString(member.IdentityKey),
			SigningKey:  hex.EncodeToString(member.SigningKey),
			Role:        member.Role,
			JoinedAt:    member.JoinedAt.UTC().Format(time.RFC3339Nano),
		})
	}
	return conversationJSON{
		ID:        conversation.ID,
		ConvType:  conversation.ConvType,
		Name:      conversation.Name,
		ServerID:  conversation.ServerID,
		CreatedAt: conversation.CreatedAt.UTC().Format(time.RFC3339Nano),
		Members:   members,
	}, nil
}

// GetConversation is the bounded live-discovery counterpart to paginated
// offline sync. A bare WS hint never supplies metadata: the signed client must
// resolve this exact UUID through its current membership and channel ACL.
func (h *Handler) GetConversation(w http.ResponseWriter, r *http.Request) {
	userUUID, err := uuid.Parse(r.Header.Get("X-User-ID"))
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	conversationUUID, err := uuid.Parse(r.PathValue("conversationID"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("conversation_id required"))
		return
	}

	conversation, err := h.svc.db.GetUserConversation(
		r.Context(), userUUID.String(), conversationUUID.String(),
	)
	if errors.Is(err, db.ErrConversationAccessDenied) {
		// Do not provide an existence oracle for another account's UUID.
		writeJSON(w, http.StatusNotFound, errorResp("conversation not found"))
		return
	}
	if err != nil {
		log.Printf("get conversation error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch conversation"))
		return
	}
	result, err := publicConversation(*conversation)
	if err != nil {
		log.Printf(
			"conversation_ref=%s has invalid public member key material",
			logsafe.Ref("conversation", conversation.ID),
		)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to serialize conversation"))
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (h *Handler) ListConversations(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	userUUID, err := uuid.Parse(userID)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}
	userID = userUUID.String()

	limit, err := parsePageLimit(r.URL.Query().Get("limit"), defaultConversationPageLimit, defaultConversationPageLimit)
	if err != nil {
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_page_limit", "invalid pagination limit", err,
		))
		return
	}

	after := time.Time{}
	afterID := ""
	if rawCursor := r.URL.Query().Get("cursor"); rawCursor != "" {
		cursor, decodeErr := decodePageCursor(rawCursor, "conversations", userID)
		if decodeErr != nil {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid or out-of-scope cursor"))
			return
		}
		after = cursor.CreatedAt
		afterID = cursor.ID
	}

	conversations, err := h.svc.db.ListUserConversations(r.Context(), userID, after, afterID, limit+1)
	if err != nil {
		log.Printf("list conversations error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch conversations"))
		return
	}

	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}
	result := make([]conversationJSON, 0, len(conversations))
	for _, conversation := range conversations {
		public, err := publicConversation(conversation)
		if err != nil {
			log.Printf(
				"conversation_ref=%s has invalid public member key material",
				logsafe.Ref("conversation", conversation.ID),
			)
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to serialize conversation"))
			return
		}
		result = append(result, public)
	}

	response := map[string]any{
		"conversations": result,
		"count":         len(result),
	}
	if hasMore && len(conversations) != 0 {
		last := conversations[len(conversations)-1]
		nextCursor, encodeErr := encodePageCursor("conversations", userID, last.CreatedAt, last.ID)
		if encodeErr != nil {
			log.Printf("encode conversation cursor: class=%s", logsafe.ErrorClass(encodeErr))
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to paginate conversations"))
			return
		}
		response["next_cursor"] = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

// --- Create DM Conversation ---

type CreateDMRequest struct {
	// PeerUserID is the canonical request field. UserID1/UserID2 are kept for
	// one compatibility window, but one of them must equal the authenticated
	// caller; a caller can never create a conversation between third parties.
	PeerUserID string `json:"peer_user_id"`
	UserID1    string `json:"user_id_1,omitempty"`
	UserID2    string `json:"user_id_2,omitempty"`
}

var errDMPrincipalMismatch = errors.New("DM participants must include authenticated user")

func (h *Handler) CreateDM(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	var req CreateDMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	peerID, err := resolveDMPeer(requesterID, req)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errDMPrincipalMismatch) {
			status = http.StatusForbidden
		}
		mapped := publicerr.New(status, "invalid_dm_request", "invalid DM request", err)
		if errors.Is(err, errDMPrincipalMismatch) {
			mapped = publicerr.New(status, "dm_principal_mismatch", "DM participants must include authenticated user", err)
		}
		publicerr.Write(w, status, mapped)
		return
	}

	peer, err := h.svc.db.FindUserByID(r.Context(), peerID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("peer user not found"))
		return
	}
	if len(peer.IdentityKey) != 32 || len(peer.SigningKey) != ed25519.PublicKeySize {
		log.Printf("create DM peer_ref=%s has invalid public key material", logsafe.Ref("user", peerID))
		writeJSON(w, http.StatusConflict, errorResp("peer cryptographic identity is invalid"))
		return
	}

	convID, created, err := h.svc.db.FindOrCreateDM(r.Context(), requesterID, peerID)
	if err != nil {
		log.Printf("create DM error: class=%s", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to create DM"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id":   convID,
		"created":           created,
		"peer_identity_key": base64.StdEncoding.EncodeToString(peer.IdentityKey),
		"peer_signing_key":  base64.StdEncoding.EncodeToString(peer.SigningKey),
	})
}

// --- Conversation Members ---

func (h *Handler) GetMembers(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("authenticated user required"))
		return
	}

	conversationID := r.PathValue("conversationID")
	if conversationID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("conversation_id required"))
		return
	}
	members, err := h.svc.db.GetConversationMemberBindingsForRequester(
		r.Context(), conversationID, requesterID, db.ChannelReadPermissions,
	)
	if err != nil {
		if errors.Is(err, db.ErrConversationAccessDenied) {
			writeJSON(w, http.StatusForbidden, errorResp("not a conversation member"))
			return
		}
		writeJSON(w, http.StatusNotFound, errorResp("conversation not found"))
		return
	}

	type memberJSON struct {
		UserID      string `json:"user_id"`
		Username    string `json:"username"`
		IdentityKey string `json:"identity_key"`
		SigningKey  string `json:"signing_key"`
		Role        int16  `json:"role"`
		JoinedAt    string `json:"joined_at"`
	}
	result := make([]memberJSON, 0, len(members))
	for _, member := range members {
		if len(member.IdentityKey) != 32 || len(member.SigningKey) != ed25519.PublicKeySize {
			log.Printf(
				"conversation_ref=%s member_ref=%s has invalid public key material",
				logsafe.Ref("conversation", conversationID),
				logsafe.Ref("user", member.UserID),
			)
			writeJSON(w, http.StatusInternalServerError, errorResp("member cryptographic identity is invalid"))
			return
		}
		result = append(result, memberJSON{
			UserID:      member.UserID,
			Username:    member.Username,
			IdentityKey: hex.EncodeToString(member.IdentityKey),
			SigningKey:  hex.EncodeToString(member.SigningKey),
			Role:        member.Role,
			JoinedAt:    member.JoinedAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id": conversationID,
		"members":         result,
	})
}

func resolveDMPeer(authenticatedUserID string, req CreateDMRequest) (string, error) {
	if authenticatedUserID == "" {
		return "", errors.New("authenticated user required")
	}

	peerID := req.PeerUserID
	if peerID != "" {
		// Do not silently accept conflicting legacy participant fields: that
		// makes audit logs and client intent ambiguous.
		if req.UserID1 != "" || req.UserID2 != "" {
			return "", errors.New("use peer_user_id or legacy participant fields, not both")
		}
	} else {
		switch {
		case req.UserID1 == authenticatedUserID && req.UserID2 != "":
			peerID = req.UserID2
		case req.UserID2 == authenticatedUserID && req.UserID1 != "":
			peerID = req.UserID1
		case req.UserID1 != "" && req.UserID2 != "":
			return "", errDMPrincipalMismatch
		default:
			return "", errors.New("peer_user_id required")
		}
	}

	if peerID == authenticatedUserID {
		return "", errors.New("cannot create a DM with yourself")
	}
	return peerID, nil
}

// --- Helpers ---

// encodeMessageHistoryPageWithinBudget returns the largest non-empty prefix
// whose exact compact JSON representation fits budget. cursorRows is aligned
// with messages and supplies the authenticated keyset boundary for each
// possible prefix. rowsRemainAfterCandidateSet means the database returned the
// requested row limit plus one.
func encodeMessageHistoryPageWithinBudget(
	messages []messageHistoryMessageJSON,
	cursorRows []db.Message,
	rowsRemainAfterCandidateSet bool,
	budget int,
) ([]byte, int, error) {
	if budget <= 0 || len(messages) != len(cursorRows) || (len(messages) == 0 && rowsRemainAfterCandidateSet) {
		return nil, 0, errors.New("invalid message history page encoding input")
	}
	if len(messages) == 0 {
		empty := make([]messageHistoryMessageJSON, 0)
		encoded, err := marshalMessageHistoryPage(messageHistoryPageJSON{
			Count:    0,
			Messages: empty,
		})
		if err != nil {
			return nil, 0, err
		}
		if len(encoded) > budget {
			return nil, 0, errors.New("message history wire budget cannot encode an empty page")
		}
		return encoded, 0, nil
	}

	rowWireBytes := 0
	chosenCount := 0
	chosenSize := 0
	chosenHasCursor := false
	chosenCursor := ""
	for index, message := range messages {
		encodedRow, err := json.Marshal(message)
		if err != nil {
			return nil, 0, fmt.Errorf("encode message history row: %w", err)
		}
		if index != 0 {
			rowWireBytes++ // comma between array entries
		}
		rowWireBytes += len(encodedRow)

		count := index + 1
		hasMore := count < len(messages) || rowsRemainAfterCandidateSet
		var nextCursor *string
		if hasMore {
			cursor, err := encodePageCursor(
				"messages",
				cursorRows[index].ConversationID,
				cursorRows[index].CreatedAt,
				cursorRows[index].ID,
			)
			if err != nil {
				return nil, 0, fmt.Errorf("encode message cursor: %w", err)
			}
			nextCursor = &cursor
		}
		size, err := messageHistoryPageEncodedSize(count, rowWireBytes, nextCursor)
		if err != nil {
			return nil, 0, err
		}
		if size <= budget {
			chosenCount = count
			chosenSize = size
			chosenHasCursor = hasMore
			if hasMore {
				chosenCursor = *nextCursor
			} else {
				chosenCursor = ""
			}
		}
	}

	if chosenCount == 0 {
		return nil, 0, errMessageHistoryRowExceedsWireBudget
	}
	var nextCursor *string
	if chosenHasCursor {
		nextCursor = &chosenCursor
	}
	encoded, err := marshalMessageHistoryPage(messageHistoryPageJSON{
		Count:      chosenCount,
		Messages:   messages[:chosenCount],
		NextCursor: nextCursor,
	})
	if err != nil {
		return nil, 0, err
	}
	if len(encoded) != chosenSize || len(encoded) > budget {
		return nil, 0, errors.New("message history page size accounting mismatch")
	}
	return encoded, chosenCount, nil
}

func messageHistoryPageEncodedSize(count, rowWireBytes int, nextCursor *string) (int, error) {
	size := len(`{"count":`) + len(strconv.Itoa(count)) +
		len(`,"messages":[`) + rowWireBytes + len(`]`)
	if nextCursor != nil {
		encodedCursor, err := json.Marshal(*nextCursor)
		if err != nil {
			return 0, fmt.Errorf("encode message cursor string: %w", err)
		}
		size += len(`,"next_cursor":`) + len(encodedCursor)
	}
	return size + len("}\n"), nil
}

func marshalMessageHistoryPage(page messageHistoryPageJSON) ([]byte, error) {
	encoded, err := json.Marshal(page)
	if err != nil {
		return nil, fmt.Errorf("encode message history page: %w", err)
	}
	return append(encoded, '\n'), nil
}

func writeEncodedJSON(w http.ResponseWriter, status int, encoded []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(encoded)
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func errorResp(msg string) map[string]string {
	return map[string]string{"error": msg}
}

type pageCursor struct {
	Version   int       `json:"v"`
	Kind      string    `json:"kind"`
	Scope     string    `json:"scope"`
	CreatedAt time.Time `json:"created_at"`
	ID        string    `json:"id"`
}

func configuredPageLimit(configured int) int {
	if configured <= 0 {
		return defaultConversationPageLimit
	}
	if configured > absolutePageLimit {
		return absolutePageLimit
	}
	return configured
}

func messageHistoryCandidateLimit(requested int) int {
	if requested > maxMessageHistoryCandidateRows {
		return maxMessageHistoryCandidateRows
	}
	return requested
}

func parsePageLimit(raw string, fallback, maximum int) (int, error) {
	if fallback <= 0 || maximum <= 0 || fallback > maximum {
		return 0, errors.New("invalid server pagination configuration")
	}
	if raw == "" {
		return fallback, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit <= 0 || limit > maximum {
		return 0, fmt.Errorf("limit must be an integer between 1 and %d", maximum)
	}
	return limit, nil
}

func encodePageCursor(kind, scope string, createdAt time.Time, id string) (string, error) {
	parsedID, err := uuid.Parse(id)
	if err != nil || kind == "" || scope == "" || createdAt.IsZero() {
		return "", errors.New("invalid cursor components")
	}
	payload, err := json.Marshal(pageCursor{
		Version:   1,
		Kind:      kind,
		Scope:     scope,
		CreatedAt: createdAt.UTC(),
		ID:        parsedID.String(),
	})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(payload), nil
}

func decodePageCursor(raw, expectedKind, expectedScope string) (pageCursor, error) {
	var cursor pageCursor
	if raw == "" || len(raw) > 1024 || expectedKind == "" || expectedScope == "" {
		return cursor, errors.New("invalid cursor")
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(raw)
	if err != nil || len(payload) > 512 {
		return cursor, errors.New("invalid cursor encoding")
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil {
		return pageCursor{}, errors.New("invalid cursor payload")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return pageCursor{}, errors.New("invalid cursor payload")
	}
	parsedID, err := uuid.Parse(cursor.ID)
	if err != nil || cursor.Version != 1 || cursor.Kind != expectedKind ||
		cursor.Scope != expectedScope || cursor.CreatedAt.IsZero() {
		return pageCursor{}, errors.New("invalid or out-of-scope cursor")
	}
	cursor.ID = parsedID.String()
	cursor.CreatedAt = cursor.CreatedAt.UTC()
	return cursor, nil
}

// --- Group Handlers ---

type CreateGroupRequest struct {
	Name    string `json:"name"`
	Members []struct {
		UserID      string `json:"user_id"`
		IdentityKey string `json:"identity_key"`
	} `json:"members"`
}

func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	var req CreateGroupRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}
	members := make([]db.GroupMemberLocator, 0, len(req.Members))
	for _, member := range req.Members {
		identityKey, err := hex.DecodeString(member.IdentityKey)
		if err != nil || len(identityKey) != ed25519.PublicKeySize {
			writeJSON(w, http.StatusBadRequest, errorResp("invalid initial Circle member locator"))
			return
		}
		members = append(members, db.GroupMemberLocator{UserID: member.UserID, IdentityKey: identityKey})
	}

	convID, err := h.svc.CreateCircle(r.Context(), req.Name, userID, members)
	if err != nil {
		log.Printf("create group error: class=%s", logsafe.ErrorClass(err))
		publicerr.Write(w, http.StatusBadRequest, publicerr.New(
			http.StatusBadRequest, "invalid_group", "invalid group request", err,
		))
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"conversation_id": convID,
		"name":            req.Name,
	})
}

type AddMemberRequest struct {
	UserID string `json:"user_id"`
}

func (h *Handler) AddGroupMember(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	groupID := r.PathValue("groupID")
	if groupID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("group_id required"))
		return
	}

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	if req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("user_id required"))
		return
	}

	if err := h.svc.AddGroupMember(r.Context(), groupID, requesterID, req.UserID); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNotMember) || errors.Is(err, ErrInsufficientPermissions) {
			status = http.StatusForbidden
		}
		publicerr.Write(w, status, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "added"})
}

func (h *Handler) RemoveGroupMember(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	groupID := r.PathValue("groupID")
	targetUserID := r.PathValue("userID")

	if groupID == "" || targetUserID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("group_id and user_id required"))
		return
	}

	if err := h.svc.RemoveGroupMember(r.Context(), groupID, requesterID, targetUserID); err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, ErrNotMember) || errors.Is(err, ErrInsufficientPermissions) {
			status = http.StatusForbidden
		}
		publicerr.Write(w, status, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "removed"})
}

func (h *Handler) GetGroupMembers(w http.ResponseWriter, r *http.Request) {
	requesterID := r.Header.Get("X-User-ID")
	if requesterID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	groupID := r.PathValue("groupID")
	if groupID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("group_id required"))
		return
	}

	members, err := h.svc.GetGroupMembers(r.Context(), groupID, requesterID)
	if err != nil {
		publicerr.Write(w, http.StatusForbidden, err)
		return
	}

	type memberJSON struct {
		UserID      string `json:"user_id"`
		IdentityKey string `json:"identity_key"`
		SigningKey  string `json:"signing_key"`
		Username    string `json:"username"`
		Role        int16  `json:"role"`
		JoinedAt    string `json:"joined_at"`
	}

	var result []memberJSON
	for _, m := range members {
		result = append(result, memberJSON{
			UserID:      m.UserID,
			IdentityKey: hex.EncodeToString(m.IdentityKey),
			SigningKey:  hex.EncodeToString(m.SigningKey),
			Username:    m.Username,
			Role:        m.Role,
			JoinedAt:    m.JoinedAt.UTC().Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id": groupID,
		"members":         result,
	})
}
