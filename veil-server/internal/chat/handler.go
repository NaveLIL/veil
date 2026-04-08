package chat

import (
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Handler provides REST endpoints for the chat service.
// Message sync, conversation management.
type Handler struct {
	svc *Service
}

func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers chat REST endpoints on the given mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/messages/{conversationID}", h.GetMessages)
	mux.HandleFunc("POST /v1/conversations/dm", h.CreateDM)
	mux.HandleFunc("GET /v1/conversations/{conversationID}/members", h.GetMembers)
}

// --- Message Sync (store-and-forward) ---

func (h *Handler) GetMessages(w http.ResponseWriter, r *http.Request) {
	conversationID := r.PathValue("conversationID")
	if conversationID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("conversation_id required"))
		return
	}

	// Caller must provide user_id header (set by gateway after auth)
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		writeJSON(w, http.StatusUnauthorized, errorResp("X-User-ID header required"))
		return
	}

	// Check membership
	isMember, err := h.svc.db.IsConversationMember(r.Context(), conversationID, userID)
	if err != nil || !isMember {
		writeJSON(w, http.StatusForbidden, errorResp("not a conversation member"))
		return
	}

	// Parse optional since parameter
	sinceStr := r.URL.Query().Get("since")
	since := time.Time{} // zero = from beginning
	if sinceStr != "" {
		parsed, err := time.Parse(time.RFC3339, sinceStr)
		if err == nil {
			since = parsed
		}
	}

	limitStr := r.URL.Query().Get("limit")
	limit := h.svc.cfg.MessageBatchLimit
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= h.svc.cfg.MessageBatchLimit {
			limit = n
		}
	}

	msgs, err := h.svc.db.GetPendingMessages(r.Context(), userID, since, limit)
	if err != nil {
		log.Printf("get messages error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to fetch messages"))
		return
	}

	type msgJSON struct {
		ID             string  `json:"id"`
		ConversationID string  `json:"conversation_id"`
		SenderID       string  `json:"sender_id"`
		Ciphertext     string  `json:"ciphertext"` // base64
		Header         string  `json:"header"`     // base64
		MsgType        int16   `json:"msg_type"`
		ReplyToID      *string `json:"reply_to_id,omitempty"`
		ExpiresAt      *string `json:"expires_at,omitempty"`
		CreatedAt      string  `json:"created_at"`
	}

	var result []msgJSON
	for _, m := range msgs {
		mj := msgJSON{
			ID:             m.ID,
			ConversationID: m.ConversationID,
			SenderID:       m.SenderID,
			Ciphertext:     hex.EncodeToString(m.Ciphertext),
			Header:         hex.EncodeToString(m.Header),
			MsgType:        m.MsgType,
			ReplyToID:      m.ReplyToID,
			CreatedAt:      m.CreatedAt.Format(time.RFC3339Nano),
		}
		if m.ExpiresAt != nil {
			t := m.ExpiresAt.Format(time.RFC3339)
			mj.ExpiresAt = &t
		}
		result = append(result, mj)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"messages": result,
		"count":    len(result),
	})
}

// --- Create DM Conversation ---

type CreateDMRequest struct {
	UserID1 string `json:"user_id_1"`
	UserID2 string `json:"user_id_2"`
}

func (h *Handler) CreateDM(w http.ResponseWriter, r *http.Request) {
	var req CreateDMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResp("invalid JSON"))
		return
	}

	if req.UserID1 == "" || req.UserID2 == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("both user_id_1 and user_id_2 required"))
		return
	}

	convID, err := h.svc.db.FindOrCreateDM(r.Context(), req.UserID1, req.UserID2)
	if err != nil {
		log.Printf("create DM error: %v", err)
		writeJSON(w, http.StatusInternalServerError, errorResp("failed to create DM"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id": convID,
	})
}

// --- Conversation Members ---

func (h *Handler) GetMembers(w http.ResponseWriter, r *http.Request) {
	conversationID := r.PathValue("conversationID")
	if conversationID == "" {
		writeJSON(w, http.StatusBadRequest, errorResp("conversation_id required"))
		return
	}

	members, err := h.svc.db.GetConversationMembers(r.Context(), conversationID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, errorResp("conversation not found"))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"conversation_id": conversationID,
		"members":         members,
	})
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
