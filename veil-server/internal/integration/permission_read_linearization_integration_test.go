//go:build integration

package integration

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/db"
)

// TestPermissionSensitiveReadsFailAfterCommittedRevoke guards against the
// handler pattern "authorize, then read on a later snapshot". The explicit
// prechecks below emulate a request paused at that old boundary; every actual
// ciphertext/directory/blob read must still reject after the revoke commits.
func TestPermissionSensitiveReadsFailAfterCommittedRevoke(t *testing.T) {
	h := New(t)
	ctx := context.Background()
	owner := h.CreateUser("read-linearization-owner")
	target := h.CreateUser("read-linearization-target")
	serverID := mkServer(t, h, owner, "read-linearization-server")
	joinViaInvite(t, h, target, mkInviteCode(t, h, owner, serverID))

	var channelID, conversationID string
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT id::text, conversation_id::text
		 FROM channels
		 WHERE server_id = $1::uuid AND channel_type = 0
		 ORDER BY position, id LIMIT 1`, serverID,
	).Scan(&channelID, &conversationID); err != nil {
		t.Fatal(err)
	}
	var messageID string
	if err := h.DB.Pool.QueryRow(ctx,
		`INSERT INTO messages (
		   conversation_id, sender_id, ciphertext,
		   crypto_profile, crypto_era, roster_version, roster_commitment,
		   sender_device_id, sender_binding_version, expires_at, edited_at
		 ) VALUES (
		   $1::uuid, $2::uuid, $3, 'sender_key_v5', 1, 1, $4, $5, 1,
		   now() + interval '1 hour', now()
		 ) RETURNING id::text`,
		conversationID, owner.ID, []byte("ciphertext-after-revoke-guard"),
		bytes.Repeat([]byte{0x41}, 32), bytes.Repeat([]byte{0x42}, 16),
	).Scan(&messageID); err != nil {
		t.Fatal(err)
	}
	fileID := "read-linearization-opaque-upload"
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO tus_uploads (
		   file_id, user_id, size_bytes, received_bytes, backend,
		   finished_at, expires_at
		 ) VALUES ($1, $2::uuid, 7, 7, 'local', now(), now() + interval '1 hour')`,
		fileID, owner.ID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO message_attachments (
		   message_id, file_id, position, encrypted_key, nonce,
		   size_bytes, content_type
		 ) VALUES ($1::uuid, $2, 0, '\x01', '\x02', 7, 'application/octet-stream')`,
		messageID, fileID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO reactions (message_id, conversation_id, user_id, emoji)
		 VALUES ($1::uuid, $2::uuid, $3::uuid, 'lock')`,
		messageID, conversationID, owner.ID,
	); err != nil {
		t.Fatal(err)
	}

	for _, precheck := range []struct {
		name string
		fn   func() (bool, error)
	}{
		{name: "history", fn: func() (bool, error) {
			return h.DB.CanAccessConversation(ctx, conversationID, target.ID, db.ChannelReadPermissions)
		}},
		{name: "upload", fn: func() (bool, error) {
			return h.DB.CanDownloadTusUpload(ctx, fileID, target.ID)
		}},
	} {
		allowed, err := precheck.fn()
		if err != nil || !allowed {
			t.Fatalf("%s precheck allowed=%v err=%v, want true", precheck.name, allowed, err)
		}
	}
	status, _, before := h.Do(target, http.MethodGet, "/v1/messages/"+conversationID+"?limit=10", nil)
	if status != http.StatusOK {
		t.Fatalf("history before revoke status=%d body=%v", status, before)
	}
	beforeMessages, ok := before["messages"].([]any)
	if !ok || len(beforeMessages) != 1 {
		t.Fatalf("history before revoke=%v", before)
	}
	createdAt, _ := beforeMessages[0].(map[string]any)["created_at"].(string)
	if !strings.HasSuffix(createdAt, "Z") {
		t.Fatalf("sync created_at=%q, want canonical UTC Z", createdAt)
	}
	for _, field := range []string{"expires_at", "edited_at"} {
		value, _ := beforeMessages[0].(map[string]any)[field].(string)
		if !strings.HasSuffix(value, "Z") {
			t.Fatalf("sync %s=%q, want canonical UTC Z", field, value)
		}
	}
	status, _, discovery := h.Do(target, http.MethodGet, "/v1/conversations?limit=50", nil)
	if status != http.StatusOK {
		t.Fatalf("conversation discovery status=%d body=%v", status, discovery)
	}
	discovered, _ := discovery["conversations"].([]any)
	foundConversation := false
	for _, rawConversation := range discovered {
		conversation, _ := rawConversation.(map[string]any)
		if conversation["id"] != conversationID {
			continue
		}
		foundConversation = true
		createdAt, _ := conversation["created_at"].(string)
		if !strings.HasSuffix(createdAt, "Z") {
			t.Fatalf("conversation created_at=%q, want canonical UTC Z", createdAt)
		}
		members, _ := conversation["members"].([]any)
		for _, rawMember := range members {
			member, _ := rawMember.(map[string]any)
			joinedAt, _ := member["joined_at"].(string)
			if !strings.HasSuffix(joinedAt, "Z") {
				t.Fatalf("conversation member joined_at=%q, want canonical UTC Z", joinedAt)
			}
		}
	}
	if !foundConversation {
		t.Fatalf("authorized channel missing from conversation discovery: %v", discovery)
	}

	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channelID, TargetID: target.ID,
		TargetType: db.ChannelOverwriteUser, Deny: db.ChannelReadPermissions,
	}); err != nil {
		t.Fatal(err)
	}
	if allowed, err := h.DB.CanAccessConversation(
		ctx, conversationID, target.ID, db.ChannelReadPermissions,
	); err != nil || allowed {
		t.Fatalf("committed revoke allowed=%v err=%v, want false", allowed, err)
	}

	if messages, err := h.DB.GetPendingMessages(
		ctx, conversationID, target.ID, time.Time{}, "", 10,
	); !errors.Is(err, db.ErrConversationAccessDenied) || len(messages) != 0 {
		t.Fatalf("post-revoke ciphertext read messages=%v err=%v", messages, err)
	}
	if page, err := h.DB.GetConversationHistoryPage(
		ctx, conversationID, target.ID, time.Time{}, "", 10,
	); !errors.Is(err, db.ErrConversationAccessDenied) || page != nil {
		t.Fatalf("post-revoke aggregate history page=%v err=%v", page, err)
	}
	if members, err := h.DB.GetConversationMemberBindingsForRequester(
		ctx, conversationID, target.ID, db.ChannelReadPermissions,
	); !errors.Is(err, db.ErrConversationAccessDenied) || len(members) != 0 {
		t.Fatalf("post-revoke member directory members=%v err=%v", members, err)
	}
	if roster, err := h.DB.ResolveConversationDeviceRosterForRequester(
		ctx, conversationID, target.ID, db.RequiredChannelCapabilities,
	); !errors.Is(err, db.ErrConversationAccessDenied) || roster != nil {
		t.Fatalf("post-revoke device directory roster=%v err=%v", roster, err)
	}
	if allowed, err := h.DB.CanDownloadTusUpload(ctx, fileID, target.ID); err != nil || allowed {
		t.Fatalf("post-revoke upload allowed=%v err=%v, want false", allowed, err)
	}
	for _, endpoint := range []string{
		"/v1/messages/" + conversationID + "?limit=10",
		"/v1/conversations/" + conversationID + "/members",
		"/v1/conversations/" + conversationID + "/device-directory",
	} {
		status, raw, _ := h.Do(target, http.MethodGet, endpoint, nil)
		if status != http.StatusForbidden {
			t.Fatalf("post-revoke GET %s status=%d body=%s, want 403", endpoint, status, raw)
		}
	}
}
