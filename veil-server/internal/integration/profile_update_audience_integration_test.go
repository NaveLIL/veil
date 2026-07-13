//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/profiles"
)

func TestProfileUpdateAudienceIsRelationshipScoped(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("profile-owner")
	friend := h.CreateUser("profile-friend")
	conversationPeer := h.CreateUser("profile-conversation-peer")
	serverPeer := h.CreateUser("profile-server-peer")
	stranger := h.CreateUser("profile-stranger")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO friendships (user_id_1, user_id_2)
		 VALUES (LEAST($1::uuid, $2::uuid), GREATEST($1::uuid, $2::uuid))`,
		owner.ID, friend.ID,
	); err != nil {
		t.Fatalf("insert friendship: %v", err)
	}
	var conversationID string
	if err := h.DB.Pool.QueryRow(ctx,
		`INSERT INTO conversations (conv_type, name) VALUES (1, 'profile audience') RETURNING id::text`,
	).Scan(&conversationID); err != nil {
		t.Fatalf("insert conversation: %v", err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO conversation_members (conversation_id, user_id)
		 VALUES ($1::uuid, $2::uuid), ($1::uuid, $3::uuid)`,
		conversationID, owner.ID, conversationPeer.ID,
	); err != nil {
		t.Fatalf("insert conversation members: %v", err)
	}
	server, err := h.DB.CreateServer(ctx, "profile audience", owner.ID)
	if err != nil {
		t.Fatalf("create server: %v", err)
	}
	if err := h.DB.AddServerMember(ctx, server.ID, serverPeer.ID); err != nil {
		t.Fatalf("add server peer: %v", err)
	}

	recipients, err := profiles.NewPostgresStore(h.DB.Pool).ProfileUpdateRecipients(ctx, owner.ID)
	if err != nil {
		t.Fatalf("profile audience: %v", err)
	}
	got := make(map[string]bool, len(recipients))
	for _, recipient := range recipients {
		if got[recipient] {
			t.Fatalf("duplicate recipient %s in %v", recipient, recipients)
		}
		got[recipient] = true
	}
	for _, expected := range []string{owner.ID, friend.ID, conversationPeer.ID, serverPeer.ID} {
		if !got[expected] {
			t.Fatalf("missing related recipient %s in %v", expected, recipients)
		}
	}
	if got[stranger.ID] || len(got) != 4 {
		t.Fatalf("unrelated account leaked into audience: stranger=%s recipients=%v", stranger.ID, recipients)
	}
}
