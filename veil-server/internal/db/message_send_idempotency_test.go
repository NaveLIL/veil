package db

import (
	"context"
	"crypto/sha256"
	"testing"
)

func TestMessageSendLedgerRejectsNoncanonicalUUIDsBeforeDatabaseUse(t *testing.T) {
	t.Parallel()

	database := &DB{}
	digest := make([]byte, sha256.Size)
	canonicalSender := "11111111-1111-4111-8111-111111111111"
	canonicalClientID := "22222222-2222-4222-8222-222222222222"
	invalid := []string{
		"",
		"00000000-0000-0000-0000-000000000000",
		"AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA",
		"{aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa}",
	}
	for _, value := range invalid {
		value := value
		t.Run("sender_"+value, func(t *testing.T) {
			t.Parallel()
			message := &Message{
				ConversationID: "33333333-3333-4333-8333-333333333333",
				SenderID:       value,
				Ciphertext:     []byte("ciphertext"),
			}
			if _, err := database.StoreMessageIdempotent(
				context.Background(), message, canonicalClientID, digest,
			); err == nil {
				t.Fatalf("StoreMessageIdempotent accepted sender %q", value)
			}
			if _, err := database.LookupMessageSendOutcome(
				context.Background(), value, canonicalClientID, digest,
			); err == nil {
				t.Fatalf("LookupMessageSendOutcome accepted sender %q", value)
			}
		})
		t.Run("client_"+value, func(t *testing.T) {
			t.Parallel()
			message := &Message{
				ConversationID: "33333333-3333-4333-8333-333333333333",
				SenderID:       canonicalSender,
				Ciphertext:     []byte("ciphertext"),
			}
			if _, err := database.StoreMessageIdempotent(
				context.Background(), message, value, digest,
			); err == nil {
				t.Fatalf("StoreMessageIdempotent accepted client ID %q", value)
			}
			if _, err := database.LookupMessageSendOutcome(
				context.Background(), canonicalSender, value, digest,
			); err == nil {
				t.Fatalf("LookupMessageSendOutcome accepted client ID %q", value)
			}
		})
	}
}
