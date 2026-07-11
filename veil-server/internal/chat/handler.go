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

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/google/uuid"
)

const (
	defaultConversationPageLimit = 100
	absolutePageLimit            = 500
)

// Handler provides REST endpoints for the chat service.
// Message sync, conversation management.
type Handler struct {
	svc *Service
	mw  *authmw.Middleware
	rl  *authmw.RateLimit
}

// NewHandler builds the chat REST handler. mw and rl may be nil to disable
// signature checks / rate limiting (used in tests and the all-in-one binary).
func NewHandler(svc *Service, mw *authmw.Middleware, rl *authmw.RateLimit) *Handler {
	return &Handler{svc: svc, mw: mw, rl: rl}
}

// SigningKeyLookup returns an authmw.UserKeyLookup backed by the service's
// database, for use when constructing the shared signing middleware.
func (s *Service) SigningKeyLookup() authmw.UserKeyLookup {
	return authmw.LookupFunc(func(ctx context.Context, userID string) (ed25519.PublicKey, error) {
		u, err := s.db.FindUserByID(ctx, userID)
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(u.SigningKey), nil
	})
}

// RegisterRoutes registers chat REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if h.rl != nil {
			f = h.rl.Wrap(f)
		}
		if h.mw != nil {
			// Verify first; the limiter keys from verified principal context.
			f = h.mw.RequireSigned(f)
		}
		return f
	}

	mux.HandleFunc("GET /v1/messages/{conversationID}", signed(h.GetMessages))
	mux.HandleFunc("GET /v1/conversations", signed(h.ListConversations))
	mux.HandleFunc("POST /v1/conversations/dm", signed(h.CreateDM))
	mux.HandleFunc("GET /v1/conversations/{conversationID}/members", signed(h.GetMembers))

	// Group endpoints
	mux.HandleFunc("POST /v1/groups", signed(h.CreateGroup))
	mux.HandleFunc("POST /v1/groups/{groupID}/members", signed(h.AddGroupMember))
	mux.HandleFunc("DELETE /v1/groups/{groupID}/members/{userID}", signed(h.RemoveGroupMember))
	mux.HandleFunc("GET /v1/groups/{groupID}/members", signed(h.GetGroupMembers))
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

	// Check membership
	isMember, err := h.svc.db.CanAccessConversation(
		r.Context(), conversationID, userID, db.ChannelReadPermissions,
	)
	if err != nil || !isMember {
		writeJSON(w, http.StatusForbidden, errorResp("not a conversation member"))
		return
	}

	maxLimit := configuredPageLimit(h.svc.cfg.MessageBatchLimit)
	limit, err := parsePageLimit(r.URL.Query().Get("limit"), maxLimit, maxLimit)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
		return
	}

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

	msgs, err := h.svc.db.GetPendingMessages(r.Context(), conversationID, userID, after, afterID, limit+1)
	if err != nil {
		log.Printf("get messages error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch messages"))
		return
	}

	type reactionJSON struct {
		Emoji    string `json:"emoji"`
		UserID   string `json:"user_id"`
		Username string `json:"username"`
	}
	type attachmentJSON struct {
		MediaID      string `json:"media_id"`
		EncryptedKey string `json:"encrypted_key"`
		Nonce        string `json:"nonce"`
		Size         int64  `json:"size"`
		ContentType  string `json:"content_type"`
	}
	type msgJSON struct {
		ID                string           `json:"id"`
		ConversationID    string           `json:"conversation_id"`
		SenderID          string           `json:"sender_id"`
		SenderIdentityKey string           `json:"sender_identity_key"`
		SenderSigningKey  string           `json:"sender_signing_key"`
		Ciphertext        string           `json:"ciphertext"` // lowercase hex (legacy wire contract)
		Header            string           `json:"header"`     // lowercase hex (legacy wire contract)
		MsgType           int16            `json:"msg_type"`
		ReplyToID         *string          `json:"reply_to_id,omitempty"`
		ExpiresAt         *string          `json:"expires_at,omitempty"`
		EditedAt          *string          `json:"edited_at"`
		IsDeleted         bool             `json:"is_deleted"`
		IsExpired         bool             `json:"is_expired"`
		Reactions         []reactionJSON   `json:"reactions"`
		Attachments       []attachmentJSON `json:"attachments"`
		CreatedAt         string           `json:"created_at"`
		ServerTimestamp   int64            `json:"server_timestamp"`
		RevisionTimestamp int64            `json:"revision_timestamp"`
	}

	hasMore := len(msgs) > limit
	if hasMore {
		msgs = msgs[:limit]
	}
	reactionsByMessage := make(map[string][]reactionJSON, len(msgs))
	attachmentsByMessage := make(map[string][]attachmentJSON, len(msgs))
	if len(msgs) != 0 {
		messageIDs := make([]string, 0, len(msgs))
		for _, message := range msgs {
			messageIDs = append(messageIDs, message.ID)
		}
		storedReactions, reactionErr := h.svc.db.GetReactionsForMessages(r.Context(), messageIDs)
		if reactionErr != nil {
			log.Printf("get message reactions error: %v", reactionErr)
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch message reactions"))
			return
		}
		for _, reaction := range storedReactions {
			if reaction.ConversationID != conversationID {
				log.Printf("reaction %s has unexpected conversation %s", reaction.MessageID, reaction.ConversationID)
				writeJSON(w, http.StatusInternalServerError, errorResp("invalid reaction state"))
				return
			}
			reactionsByMessage[reaction.MessageID] = append(reactionsByMessage[reaction.MessageID], reactionJSON{
				Emoji: reaction.Emoji, UserID: reaction.UserID, Username: reaction.Username,
			})
		}
		storedAttachments, attachmentErr := h.svc.db.GetAttachmentsForMessages(r.Context(), messageIDs)
		if attachmentErr != nil {
			log.Printf("get message attachments error: %v", attachmentErr)
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch message attachments"))
			return
		}
		for _, attachment := range storedAttachments {
			attachmentsByMessage[attachment.MessageID] = append(
				attachmentsByMessage[attachment.MessageID],
				attachmentJSON{
					MediaID:      attachment.FileID,
					EncryptedKey: base64.StdEncoding.EncodeToString(attachment.EncryptedKey),
					Nonce:        base64.StdEncoding.EncodeToString(attachment.Nonce),
					Size:         attachment.SizeBytes,
					ContentType:  "application/octet-stream",
				},
			)
		}
	}

	result := make([]msgJSON, 0, len(msgs))
	now := time.Now()
	for _, m := range msgs {
		if len(m.SenderIdentityKey) != 32 || len(m.SenderSigningKey) != ed25519.PublicKeySize {
			log.Printf("message %s sender %s has invalid public key material", m.ID, m.SenderID)
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
			reactions = make([]reactionJSON, 0)
		}
		attachments := make([]attachmentJSON, 0)
		if !m.IsDeleted && !isExpired {
			attachments = attachmentsByMessage[m.ID]
			if attachments == nil {
				attachments = make([]attachmentJSON, 0)
			}
		}
		revisionTimestamp := m.CreatedAt.UnixMilli()
		if m.EditedAt != nil {
			revisionTimestamp = m.EditedAt.UnixMilli()
		}
		mj := msgJSON{
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
			CreatedAt:         m.CreatedAt.Format(time.RFC3339Nano),
			ServerTimestamp:   m.CreatedAt.UnixMilli(),
			RevisionTimestamp: revisionTimestamp,
		}
		if m.ExpiresAt != nil {
			t := m.ExpiresAt.Format(time.RFC3339)
			mj.ExpiresAt = &t
		}
		if m.EditedAt != nil {
			t := m.EditedAt.Format(time.RFC3339Nano)
			mj.EditedAt = &t
		}
		result = append(result, mj)
	}

	response := map[string]any{
		"messages": result,
		"count":    len(result),
	}
	if hasMore && len(msgs) != 0 {
		last := msgs[len(msgs)-1]
		nextCursor, encodeErr := encodePageCursor("messages", conversationID, last.CreatedAt, last.ID)
		if encodeErr != nil {
			log.Printf("encode message cursor: %v", encodeErr)
			writeJSON(w, http.StatusInternalServerError, errorResp("failed to paginate messages"))
			return
		}
		response["next_cursor"] = nextCursor
	}
	writeJSON(w, http.StatusOK, response)
}

// --- Offline conversation discovery ---

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
		writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
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
		log.Printf("list conversations error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch conversations"))
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
	type conversationJSON struct {
		ID        string       `json:"id"`
		ConvType  int16        `json:"conv_type"`
		Name      *string      `json:"name"`
		ServerID  *string      `json:"server_id"`
		CreatedAt string       `json:"created_at"`
		Members   []memberJSON `json:"members"`
	}

	hasMore := len(conversations) > limit
	if hasMore {
		conversations = conversations[:limit]
	}
	result := make([]conversationJSON, 0, len(conversations))
	for _, conversation := range conversations {
		members := make([]memberJSON, 0, len(conversation.Members))
		for _, member := range conversation.Members {
			if len(member.IdentityKey) != 32 || len(member.SigningKey) != ed25519.PublicKeySize {
				log.Printf("conversation %s member %s has invalid public key material", conversation.ID, member.UserID)
				writeJSON(w, http.StatusInternalServerError, errorResp("member cryptographic identity is invalid"))
				return
			}
			members = append(members, memberJSON{
				UserID:      member.UserID,
				Username:    member.Username,
				IdentityKey: hex.EncodeToString(member.IdentityKey),
				SigningKey:  hex.EncodeToString(member.SigningKey),
				Role:        member.Role,
				JoinedAt:    member.JoinedAt.Format(time.RFC3339Nano),
			})
		}
		result = append(result, conversationJSON{
			ID:        conversation.ID,
			ConvType:  conversation.ConvType,
			Name:      conversation.Name,
			ServerID:  conversation.ServerID,
			CreatedAt: conversation.CreatedAt.Format(time.RFC3339Nano),
			Members:   members,
		})
	}

	response := map[string]any{
		"conversations": result,
		"count":         len(result),
	}
	if hasMore && len(conversations) != 0 {
		last := conversations[len(conversations)-1]
		nextCursor, encodeErr := encodePageCursor("conversations", userID, last.CreatedAt, last.ID)
		if encodeErr != nil {
			log.Printf("encode conversation cursor: %v", encodeErr)
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
		writeJSON(w, status, errorResp(err.Error()))
		return
	}

	peer, err := h.svc.db.FindUserByID(r.Context(), peerID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("peer user not found"))
		return
	}
	if len(peer.IdentityKey) != 32 || len(peer.SigningKey) != ed25519.PublicKeySize {
		log.Printf("create DM peer %s has invalid public key material", peerID)
		writeJSON(w, http.StatusConflict, errorResp("peer cryptographic identity is invalid"))
		return
	}

	convID, created, err := h.svc.db.FindOrCreateDM(r.Context(), requesterID, peerID)
	if err != nil {
		log.Printf("create DM error: %v", err)
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
	isMember, err := h.svc.db.CanAccessConversation(
		r.Context(), conversationID, requesterID, db.ChannelReadPermissions,
	)
	if err != nil || !isMember {
		writeJSON(w, http.StatusForbidden, errorResp("not a conversation member"))
		return
	}

	members, err := h.svc.db.GetAuthorizedConversationMemberBindings(
		r.Context(), conversationID, db.ChannelReadPermissions,
	)
	if err != nil {
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
			log.Printf("conversation %s member %s has invalid public key material", conversationID, member.UserID)
			writeJSON(w, http.StatusInternalServerError, errorResp("member cryptographic identity is invalid"))
			return
		}
		result = append(result, memberJSON{
			UserID:      member.UserID,
			Username:    member.Username,
			IdentityKey: hex.EncodeToString(member.IdentityKey),
			SigningKey:  hex.EncodeToString(member.SigningKey),
			Role:        member.Role,
			JoinedAt:    member.JoinedAt.Format(time.RFC3339),
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
	Name string `json:"name"`
}

func (h *Handler) CreateGroup(w http.ResponseWriter, r *http.Request) {
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	var req CreateGroupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	convID, err := h.svc.CreateGroup(r.Context(), req.Name, userID)
	if err != nil {
		log.Printf("create group error: %v", err)
		writeJSON(w, http.StatusBadRequest, errorResp(err.Error()))
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
		if errors.Is(err, ErrNotMember) || err.Error() == "insufficient permissions" {
			status = http.StatusForbidden
		}
		writeJSON(w, status, errorResp(err.Error()))
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
		if errors.Is(err, ErrNotMember) || err.Error() == "insufficient permissions" {
			status = http.StatusForbidden
		}
		writeJSON(w, status, errorResp(err.Error()))
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
		writeJSON(w, http.StatusForbidden, errorResp(err.Error()))
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
			JoinedAt:    m.JoinedAt.Format(time.RFC3339),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id": groupID,
		"members":         result,
	})
}
