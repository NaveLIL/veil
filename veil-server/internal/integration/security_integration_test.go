//go:build integration

package integration

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/servers"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	"golang.org/x/crypto/curve25519"
)

func integrationPushInput(endpoint, label string) db.NewPushSubscription {
	tokenHash := sha256.Sum256([]byte(endpoint))
	return db.NewPushSubscription{
		EndpointURL:         endpoint,
		PublicKey:           base64.RawURLEncoding.EncodeToString(append([]byte{4}, make([]byte, 64)...)),
		AuthSecret:          base64.RawURLEncoding.EncodeToString(make([]byte, 16)),
		DeviceLabel:         label,
		PushKind:            "unifiedpush",
		ValidationTokenHash: tokenHash[:],
		ValidationExpiresAt: time.Now().Add(time.Hour),
	}
}

// TestSecurityPrincipalBinding exercises the authorization boundaries that
// previously allowed account/device takeover and cross-conversation access.
// It intentionally uses one harness so the security suite only starts one
// ephemeral PostgreSQL container.
func TestSecurityPrincipalBinding(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("security-alice")
	bob := h.CreateUser("security-bob")
	mallory := h.CreateUser("security-mallory")

	t.Run("websocket auth registers only with a valid X25519 proof", func(t *testing.T) {
		cfg := &config.Config{AuthChallengeTTL: 5 * time.Second, AuthMaxAttempts: 3}
		svc := auth.NewService(h.DB, cfg)
		serverPublic, err := svc.CreateChallenge("valid-registration")
		if err != nil {
			t.Fatal(err)
		}
		identityPublic, identityPrivate := randomX25519KeyPair(t)
		signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		shared, err := curve25519.X25519(identityPrivate, serverPublic[:])
		if err != nil {
			t.Fatal(err)
		}
		message, err := auth.WSAuthSigningMessage(serverPublic[:], shared)
		if err != nil {
			t.Fatal(err)
		}
		result, err := svc.VerifyResponse(context.Background(), "valid-registration",
			identityPublic, signingPublic, ed25519.Sign(signingPrivate, message),
			randomBytes(t, 16), "valid-device")
		if err != nil {
			t.Fatalf("valid registration rejected: %v", err)
		}
		if !result.IsNew {
			t.Fatal("valid registration was not marked new")
		}
	})

	t.Run("websocket auth rejects a replacement signing key", func(t *testing.T) {
		cfg := &config.Config{AuthChallengeTTL: 5 * time.Second, AuthMaxAttempts: 3}
		svc := auth.NewService(h.DB, cfg)
		serverPublic, err := svc.CreateChallenge("takeover-attempt")
		if err != nil {
			t.Fatal(err)
		}
		attackerPublic, attackerPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		deviceKey := randomBytes(t, 16)
		shared, err := curve25519.X25519(alice.IdentityPrivate, serverPublic[:])
		if err != nil {
			t.Fatal(err)
		}
		signingMessage, err := auth.WSAuthSigningMessage(serverPublic[:], shared)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.VerifyResponse(context.Background(), "takeover-attempt",
			alice.IdentityKey, attackerPublic, ed25519.Sign(attackerPrivate, signingMessage),
			deviceKey, "attacker-device")
		if !errors.Is(err, auth.ErrSigningKeyMismatch) {
			t.Fatalf("takeover error = %v, want ErrSigningKeyMismatch", err)
		}
	})

	t.Run("websocket auth requires X25519 private key possession", func(t *testing.T) {
		cfg := &config.Config{AuthChallengeTTL: 5 * time.Second, AuthMaxAttempts: 3}
		svc := auth.NewService(h.DB, cfg)
		serverPublic, err := svc.CreateChallenge("no-x25519-private")
		if err != nil {
			t.Fatal(err)
		}
		_, wrongIdentityPrivate := randomX25519KeyPair(t)
		wrongShared, err := curve25519.X25519(wrongIdentityPrivate, serverPublic[:])
		if err != nil {
			t.Fatal(err)
		}
		message, err := auth.WSAuthSigningMessage(serverPublic[:], wrongShared)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.VerifyResponse(context.Background(), "no-x25519-private",
			alice.IdentityKey, alice.SigningPublic, ed25519.Sign(alice.SigningKey, message),
			randomBytes(t, 16), "forged-device")
		if !errors.Is(err, auth.ErrBadSignature) {
			t.Fatalf("missing X25519 private proof error = %v, want ErrBadSignature", err)
		}
	})

	aliceDeviceKey := randomBytes(t, 16)
	aliceDevice, err := h.DB.CreateDevice(context.Background(), alice.ID, aliceDeviceKey, "alice-device")
	if err != nil {
		t.Fatalf("create device: %v", err)
	}
	aliceDeviceKeys := newIntegrationDeviceKeys(t)
	_, aliceBindingPayload := signedDeviceBinding(
		t, alice, aliceDeviceKey, aliceDeviceKeys, 1,
		db.RequiredChannelCapabilities, db.DeviceBindingActive,
	)
	putDeviceBinding(t, h, alice, aliceDeviceKey, aliceBindingPayload, http.StatusOK)

	bobDeviceKey := randomBytes(t, 16)
	bobDevice, err := h.DB.CreateDevice(context.Background(), bob.ID, bobDeviceKey, "bob-device")
	if err != nil {
		t.Fatalf("create bob device: %v", err)
	}
	bobDeviceKeys := newIntegrationDeviceKeys(t)
	_, bobBindingPayload := signedDeviceBinding(
		t, bob, bobDeviceKey, bobDeviceKeys, 1,
		db.RequiredChannelCapabilities, db.DeviceBindingActive,
	)
	putDeviceBinding(t, h, bob, bobDeviceKey, bobBindingPayload, http.StatusOK)

	spk := randomBytes(t, 32)
	spkSigningMessage, err := auth.SignedPreKeySigningMessage(spk)
	if err != nil {
		t.Fatal(err)
	}
	validSPKSig := ed25519.Sign(alice.SigningKey, spkSigningMessage)
	validUpload := map[string]any{
		"device_id": hex.EncodeToString(aliceDeviceKey),
		"signed_prekey": map[string]any{
			"key_id": 777, "public_key": base64.StdEncoding.EncodeToString(spk),
			"signature": base64.StdEncoding.EncodeToString(validSPKSig),
		},
		"one_time_prekeys": []map[string]any{{
			"key_id": 888, "public_key": base64.StdEncoding.EncodeToString(randomBytes(t, 32)),
		}},
	}

	t.Run("prekey upload is device-owner only", func(t *testing.T) {
		status, _, _ := h.Do(bob, http.MethodPost, "/v1/prekeys", validUpload)
		if status != http.StatusForbidden {
			t.Fatalf("foreign-device upload status = %d, want 403", status)
		}
	})

	t.Run("prekey upload validates signature and preserves protocol ids", func(t *testing.T) {
		badUpload := map[string]any{
			"device_id": hex.EncodeToString(aliceDeviceKey),
			"signed_prekey": map[string]any{
				"key_id": 777, "public_key": base64.StdEncoding.EncodeToString(spk),
				"signature": base64.StdEncoding.EncodeToString(ed25519.Sign(mallory.SigningKey, spkSigningMessage)),
			},
		}
		status, _, _ := h.Do(alice, http.MethodPost, "/v1/prekeys", badUpload)
		if status != http.StatusBadRequest {
			t.Fatalf("bad signed prekey status = %d, want 400", status)
		}

		status, _, body := h.Do(alice, http.MethodPost, "/v1/prekeys", validUpload)
		if status != http.StatusOK {
			t.Fatalf("valid prekey upload status = %d body=%v", status, body)
		}
		beforeUnauthorizedClaim, err := h.DB.CountUnusedOPKs(context.Background(), aliceDevice.ID)
		if err != nil {
			t.Fatal(err)
		}
		status, _, _ = h.Do(mallory, http.MethodGet,
			"/v1/prekeys/"+hex.EncodeToString(alice.IdentityKey), nil)
		if status != http.StatusForbidden {
			t.Fatalf("unrelated prekey fetch status = %d, want 403", status)
		}
		afterUnauthorizedClaim, err := h.DB.CountUnusedOPKs(context.Background(), aliceDevice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if afterUnauthorizedClaim != beforeUnauthorizedClaim {
			t.Fatalf("unauthorized fetch depleted OPKs: before=%d after=%d", beforeUnauthorizedClaim, afterUnauthorizedClaim)
		}
		if _, _, err := h.DB.FindOrCreateDM(context.Background(), alice.ID, bob.ID); err != nil {
			t.Fatalf("establish prekey access relation: %v", err)
		}
		status, _, bundle := h.Do(bob, http.MethodGet,
			"/v1/prekeys/"+hex.EncodeToString(alice.IdentityKey), nil)
		if status != http.StatusOK {
			t.Fatalf("prekey fetch status = %d body=%v", status, bundle)
		}
		if got := uint32(bundle["signed_prekey_id"].(float64)); got != 777 {
			t.Fatalf("signed_prekey_id = %d, want protocol id 777", got)
		}
		if got := uint32(bundle["one_time_prekey_id"].(float64)); got != 888 {
			t.Fatalf("one_time_prekey_id = %d, want protocol id 888", got)
		}
	})

	t.Run("prekey replenishment bounds unused rows without deleting claimed keys", func(t *testing.T) {
		keys := make([]db.PreKey, 0, 105)
		for i := 0; i < 105; i++ {
			keys = append(keys, db.PreKey{
				KeyType:       1,
				ProtocolKeyID: uint32(1000 + i),
				PublicKey:     randomBytes(t, 32),
			})
		}
		if err := h.DB.StorePreKeys(context.Background(), aliceDevice.ID, keys); err != nil {
			t.Fatalf("bulk replenish OPKs: %v", err)
		}
		unused, err := h.DB.CountUnusedOPKs(context.Background(), aliceDevice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if unused != 100 {
			t.Fatalf("unused OPK retention = %d, want 100", unused)
		}
		var claimedStillPresent bool
		if err := h.DB.Pool.QueryRow(context.Background(),
			`SELECT EXISTS(
			   SELECT 1 FROM prekeys
			   WHERE device_id = $1::uuid AND key_type = 1 AND protocol_key_id = 888 AND used = true
			 )`,
			aliceDevice.ID,
		).Scan(&claimedStillPresent); err != nil {
			t.Fatal(err)
		}
		if !claimedStillPresent {
			t.Fatal("unused-key pruning deleted an already claimed OPK")
		}
	})

	t.Run("device lists are private", func(t *testing.T) {
		status, _, _ := h.Do(bob, http.MethodGet, "/v1/devices/"+alice.ID, nil)
		if status != http.StatusForbidden {
			t.Fatalf("foreign device list status = %d, want 403", status)
		}
	})

	t.Run("DM creation is bound to caller", func(t *testing.T) {
		status, _, _ := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
			"user_id_1": bob.ID,
			"user_id_2": mallory.ID,
		})
		if status != http.StatusForbidden {
			t.Fatalf("third-party DM status = %d, want 403", status)
		}
	})

	var aliceBobConversationID string
	t.Run("conversation member list is member-only", func(t *testing.T) {
		status, _, body := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
			"peer_user_id": bob.ID,
		})
		if status != http.StatusOK {
			t.Fatalf("create DM status = %d body=%v", status, body)
		}
		for _, field := range []string{"peer_identity_key", "peer_signing_key"} {
			encoded, ok := body[field].(string)
			if !ok {
				t.Fatalf("create DM response missing %s: %v", field, body)
			}
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil || len(decoded) != 32 {
				t.Fatalf("create DM %s is not a base64 32-byte key", field)
			}
		}
		conversationID := body["conversation_id"].(string)
		aliceBobConversationID = conversationID
		status, _, _ = h.Do(mallory, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusForbidden {
			t.Fatalf("foreign member list status = %d, want 403", status)
		}
	})

	bobMalloryConversationID, _, err := h.DB.FindOrCreateDM(context.Background(), bob.ID, mallory.ID)
	if err != nil {
		t.Fatalf("create bob/mallory DM: %v", err)
	}

	t.Run("offline conversation discovery is signed and user scoped", func(t *testing.T) {
		status, _ := h.DoUnsigned(http.MethodGet, "/v1/conversations", nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("unsigned conversation discovery status = %d, want 401", status)
		}

		status, _, body := h.Do(alice, http.MethodGet, "/v1/conversations", nil)
		if status != http.StatusOK {
			t.Fatalf("alice conversation discovery status = %d body=%v", status, body)
		}
		conversations, _ := body["conversations"].([]any)
		if len(conversations) != 1 {
			t.Fatalf("alice conversations = %d, want only alice/bob: %v", len(conversations), body)
		}
		conversation, _ := conversations[0].(map[string]any)
		if conversation["id"] != aliceBobConversationID || int(conversation["conv_type"].(float64)) != 0 {
			t.Fatalf("unexpected discovered conversation: %v", conversation)
		}
		members, _ := conversation["members"].([]any)
		if len(members) != 2 {
			t.Fatalf("discovered member count = %d, want 2: %v", len(members), conversation)
		}
		seen := map[string]bool{}
		for _, raw := range members {
			member := raw.(map[string]any)
			userID := member["user_id"].(string)
			seen[userID] = true
			if len(member["identity_key"].(string)) != 64 || len(member["signing_key"].(string)) != 64 {
				t.Fatalf("member has malformed pinned keys: %v", member)
			}
		}
		if !seen[alice.ID] || !seen[bob.ID] || seen[mallory.ID] {
			t.Fatalf("cross-user member binding leaked: %v", members)
		}

		// Bob belongs to two DMs, so limit=1 produces a user-scoped cursor.
		status, _, bobPage := h.Do(bob, http.MethodGet, "/v1/conversations?limit=1", nil)
		if status != http.StatusOK {
			t.Fatalf("bob first discovery page status = %d body=%v", status, bobPage)
		}
		bobCursor, _ := bobPage["next_cursor"].(string)
		if bobCursor == "" {
			t.Fatalf("bob first discovery page missing next_cursor: %v", bobPage)
		}
		status, _, _ = h.Do(alice, http.MethodGet, "/v1/conversations?limit=1&cursor="+bobCursor, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("cross-user conversation cursor status = %d, want 400", status)
		}
	})

	t.Run("message sync binds sender keys and conversation scoped cursor", func(t *testing.T) {
		first := &db.Message{
			ConversationID: aliceBobConversationID,
			SenderID:       alice.ID,
			Ciphertext:     []byte("ciphertext-one"),
			Header:         []byte("header-one"),
		}
		second := &db.Message{
			ConversationID: aliceBobConversationID,
			SenderID:       alice.ID,
			Ciphertext:     []byte("ciphertext-two"),
			Header:         []byte("header-two"),
		}
		for _, message := range []*db.Message{first, second} {
			if err := h.DB.StoreMessage(context.Background(), message); err != nil {
				t.Fatalf("store paginated message: %v", err)
			}
		}
		// Deliberately force an identical timestamp.  Pagination must use the
		// message UUID tie-breaker and return both rows exactly once.
		fixedTime := time.Now().Add(-time.Hour).Truncate(time.Millisecond)
		if _, err := h.DB.Pool.Exec(context.Background(),
			`UPDATE messages SET created_at = $1 WHERE id = ANY($2::uuid[])`,
			fixedTime, []string{first.ID, second.ID}); err != nil {
			t.Fatalf("align message timestamps: %v", err)
		}

		status, _, ownMessages := h.Do(alice, http.MethodGet,
			"/v1/messages/"+aliceBobConversationID, nil)
		ownMessageList, _ := ownMessages["messages"].([]any)
		if status != http.StatusOK || len(ownMessageList) != 2 {
			t.Fatalf("sender-owned rows missing from current-state sync: status=%d body=%v", status, ownMessages)
		}

		status, _, pageOne := h.Do(bob, http.MethodGet,
			"/v1/messages/"+aliceBobConversationID+"?limit=1", nil)
		if status != http.StatusOK {
			t.Fatalf("first message page status = %d body=%v", status, pageOne)
		}
		messages, _ := pageOne["messages"].([]any)
		if len(messages) != 1 {
			t.Fatalf("first page messages = %d, want 1: %v", len(messages), pageOne)
		}
		message := messages[0].(map[string]any)
		if message["sender_identity_key"] != hex.EncodeToString(alice.IdentityKey) ||
			message["sender_signing_key"] != hex.EncodeToString(alice.SigningPublic) {
			t.Fatalf("message sender binding mismatch: %v", message)
		}
		if int64(message["server_timestamp"].(float64)) != fixedTime.UnixMilli() {
			t.Fatalf("server_timestamp = %v, want %d", message["server_timestamp"], fixedTime.UnixMilli())
		}
		cursor, _ := pageOne["next_cursor"].(string)
		if cursor == "" {
			t.Fatalf("first message page missing next_cursor: %v", pageOne)
		}

		status, _, pageTwo := h.Do(bob, http.MethodGet,
			"/v1/messages/"+aliceBobConversationID+"?limit=1&cursor="+cursor, nil)
		if status != http.StatusOK {
			t.Fatalf("second message page status = %d body=%v", status, pageTwo)
		}
		secondMessages, _ := pageTwo["messages"].([]any)
		if len(secondMessages) != 1 || secondMessages[0].(map[string]any)["id"] == message["id"] {
			t.Fatalf("timestamp tie was skipped or duplicated: first=%v second=%v", pageOne, pageTwo)
		}

		// Bob is a member of both conversations, but a cursor is bound to one
		// conversation and cannot be replayed against the other.
		status, _, _ = h.Do(bob, http.MethodGet,
			"/v1/messages/"+bobMalloryConversationID+"?limit=1&cursor="+cursor, nil)
		if status != http.StatusBadRequest {
			t.Fatalf("cross-conversation cursor status = %d, want 400", status)
		}
		status, _, _ = h.Do(mallory, http.MethodGet, "/v1/messages/"+aliceBobConversationID, nil)
		if status != http.StatusForbidden {
			t.Fatalf("non-member message sync status = %d, want 403", status)
		}

		editedCiphertext := []byte("edited-current-ciphertext")
		editedHeader := []byte("edited-current-header")
		if _, _, _, err := h.Chat.HandleEditMessage(context.Background(), alice.ID, &pb.EditMessage{
			MessageId: first.ID, ConversationId: aliceBobConversationID,
			NewCiphertext: editedCiphertext, NewHeader: editedHeader,
		}); err != nil {
			t.Fatalf("edit reconciliation fixture: %v", err)
		}
		if _, err := h.Chat.HandleReaction(context.Background(), bob.ID, &pb.ReactionUpdate{
			MessageId: first.ID, ConversationId: aliceBobConversationID, Emoji: "fire", Add: true,
		}); err != nil {
			t.Fatalf("reaction reconciliation fixture: %v", err)
		}
		_, deletedAt, _, err := h.Chat.HandleDeleteMessage(context.Background(), alice.ID, &pb.DeleteMessage{
			MessageId: second.ID, ConversationId: aliceBobConversationID,
		})
		if err != nil {
			t.Fatalf("soft delete reconciliation fixture: %v", err)
		}
		bobOwned := &db.Message{
			ConversationID: aliceBobConversationID, SenderID: bob.ID,
			Ciphertext: []byte("bob-owned-ciphertext"), Header: []byte("bob-owned-header"),
		}
		if err := h.DB.StoreMessage(context.Background(), bobOwned); err != nil {
			t.Fatalf("store caller-owned reconciliation fixture: %v", err)
		}
		expiredAt := time.Now().Add(-time.Hour)
		expired := &db.Message{
			ConversationID: aliceBobConversationID, SenderID: alice.ID,
			Ciphertext: []byte("must-not-leak-expired"), Header: []byte("must-not-leak-expired-header"),
			ExpiresAt: &expiredAt,
		}
		if err := h.DB.StoreMessage(context.Background(), expired); err != nil {
			t.Fatalf("store expired reconciliation fixture: %v", err)
		}

		status, _, reconciled := h.Do(bob, http.MethodGet,
			"/v1/messages/"+aliceBobConversationID, nil)
		if status != http.StatusOK {
			t.Fatalf("current-state sync status = %d body=%v", status, reconciled)
		}
		reconciledMessages, _ := reconciled["messages"].([]any)
		if len(reconciledMessages) != 4 {
			t.Fatalf("current-state sync rows = %d, want 4: %v", len(reconciledMessages), reconciled)
		}
		byID := make(map[string]map[string]any, len(reconciledMessages))
		for _, raw := range reconciledMessages {
			row := raw.(map[string]any)
			byID[row["id"].(string)] = row
		}
		editedRow := byID[first.ID]
		if editedRow["ciphertext"] != hex.EncodeToString(editedCiphertext) ||
			editedRow["header"] != hex.EncodeToString(editedHeader) ||
			editedRow["edited_at"] == nil || editedRow["is_deleted"] != false || editedRow["is_expired"] != false {
			t.Fatalf("edited row is not authoritative current state: %v", editedRow)
		}
		if editedRow["revision_timestamp"].(float64) <= editedRow["server_timestamp"].(float64) {
			t.Fatalf("edited row revision timestamp did not advance: %v", editedRow)
		}
		reactions, _ := editedRow["reactions"].([]any)
		if len(reactions) != 1 {
			t.Fatalf("authoritative reactions missing: %v", editedRow)
		}
		reaction := reactions[0].(map[string]any)
		if reaction["emoji"] != "fire" || reaction["user_id"] != bob.ID || reaction["username"] != bob.Username {
			t.Fatalf("reaction binding mismatch: %v", reaction)
		}
		deletedRow := byID[second.ID]
		if deletedRow["is_deleted"] != true || deletedRow["ciphertext"] != "" || deletedRow["header"] != "" {
			t.Fatalf("deleted row is not a ciphertext-free tombstone: %v", deletedRow)
		}
		if deletedRow["edited_at"] == nil || deletedRow["revision_timestamp"].(float64) <= deletedRow["server_timestamp"].(float64) {
			t.Fatalf("deleted tombstone has no authoritative revision timestamp: %v", deletedRow)
		}
		if got := int64(deletedRow["revision_timestamp"].(float64)); got != deletedAt.UnixMilli() {
			t.Fatalf("REST delete revision = %d, authoritative DB/WS revision = %d", got, deletedAt.UnixMilli())
		}
		ownRow := byID[bobOwned.ID]
		if ownRow["sender_id"] != bob.ID || ownRow["ciphertext"] == "" {
			t.Fatalf("caller-owned mutation state missing: %v", ownRow)
		}
		expiredRow := byID[expired.ID]
		if expiredRow["is_expired"] != true || expiredRow["is_deleted"] != false ||
			expiredRow["ciphertext"] != "" || expiredRow["header"] != "" {
			t.Fatalf("expired row leaked ciphertext instead of tombstone: %v", expiredRow)
		}
	})

	t.Run("reactions require membership and correct message conversation", func(t *testing.T) {
		message := &db.Message{
			ConversationID: aliceBobConversationID,
			SenderID:       alice.ID,
			Ciphertext:     []byte("ciphertext"),
			Header:         []byte("header"),
		}
		if err := h.DB.StoreMessage(context.Background(), message); err != nil {
			t.Fatalf("store message: %v", err)
		}

		_, _, _, err := h.Chat.HandleSendMessage(context.Background(), bob.ID, &pb.SendMessage{
			ConversationId: bobMalloryConversationID,
			Ciphertext:     []byte("encrypted cross-conversation reply"),
			ReplyToId:      &message.ID,
		})
		if !errors.Is(err, chat.ErrMessageConversationMismatch) {
			t.Fatalf("cross-conversation reply error = %v, want mismatch (gateway maps this to 400)", err)
		}

		_, _, _, err = h.Chat.HandleEditMessage(context.Background(), alice.ID, &pb.EditMessage{
			MessageId:      message.ID,
			ConversationId: bobMalloryConversationID,
			NewCiphertext:  []byte("malicious edit"),
			NewHeader:      []byte("malicious header"),
		})
		if !errors.Is(err, chat.ErrNotMember) {
			t.Fatalf("cross-conversation edit error = %v, want membership denial without a message-existence oracle", err)
		}
		_, _, _, err = h.Chat.HandleDeleteMessage(context.Background(), alice.ID, &pb.DeleteMessage{
			MessageId:      message.ID,
			ConversationId: bobMalloryConversationID,
		})
		if !errors.Is(err, chat.ErrMessageConversationMismatch) {
			t.Fatalf("cross-conversation delete error = %v, want mismatch", err)
		}

		_, err = h.Chat.HandleReaction(context.Background(), mallory.ID, &pb.ReactionUpdate{
			MessageId: message.ID, ConversationId: aliceBobConversationID, Emoji: "👍", Add: true,
		})
		if !errors.Is(err, chat.ErrNotMember) {
			t.Fatalf("non-member reaction error = %v, want ErrNotMember", err)
		}

		_, err = h.Chat.HandleReaction(context.Background(), bob.ID, &pb.ReactionUpdate{
			MessageId: message.ID, ConversationId: bobMalloryConversationID, Emoji: "👍", Add: true,
		})
		if !errors.Is(err, chat.ErrMessageConversationMismatch) {
			t.Fatalf("cross-conversation reaction error = %v, want mismatch", err)
		}
	})

	t.Run("roles are server scoped and cannot escalate manager privileges", func(t *testing.T) {
		serverA := mkServer(t, h, alice, "security-role-a")
		serverB := mkServer(t, h, alice, "security-role-b")
		invite := mkInviteCode(t, h, alice, serverA)
		joinViaInvite(t, h, bob, invite)
		joinViaInvite(t, h, mallory, invite)

		status, _, roleBBody := h.Do(alice, http.MethodPost,
			"/v1/servers/"+serverB+"/roles", map[string]any{
				"name": "server-b-role", "permissions": uint64(0),
			})
		if status != http.StatusCreated {
			t.Fatalf("create server B role status=%d body=%v", status, roleBBody)
		}
		roleB := roleBBody["id"].(string)
		for _, request := range []struct {
			method string
			path   string
			body   any
		}{
			{http.MethodPatch, "/v1/servers/" + serverA + "/roles/" + roleB, map[string]string{"name": "cross-server-write"}},
			{http.MethodDelete, "/v1/servers/" + serverA + "/roles/" + roleB, nil},
			{http.MethodPut, "/v1/servers/" + serverA + "/members/" + mallory.ID + "/roles/" + roleB, nil},
		} {
			status, _, body := h.Do(alice, request.method, request.path, request.body)
			if status != http.StatusForbidden {
				t.Fatalf("cross-server role request %s %s status=%d body=%v", request.method, request.path, status, body)
			}
		}
		status, _, rolesB := h.Do(alice, http.MethodGet, "/v1/servers/"+serverB+"/roles", nil)
		if status != http.StatusOK {
			t.Fatalf("list server B roles status=%d body=%v", status, rolesB)
		}
		foundUntouched := false
		for _, raw := range rolesB["roles"].([]any) {
			role := raw.(map[string]any)
			if role["id"] == roleB && role["name"] == "server-b-role" {
				foundUntouched = true
			}
		}
		if !foundUntouched {
			t.Fatalf("cross-server update/delete changed role B: %v", rolesB)
		}

		status, _, managerBody := h.Do(alice, http.MethodPost,
			"/v1/servers/"+serverA+"/roles", map[string]any{
				"name": "role-manager", "permissions": db.PermManageRoles,
			})
		if status != http.StatusCreated {
			t.Fatalf("create manager role status=%d body=%v", status, managerBody)
		}
		managerRole := managerBody["id"].(string)
		status, _, _ = h.Do(alice, http.MethodPut,
			"/v1/servers/"+serverA+"/members/"+bob.ID+"/roles/"+managerRole, nil)
		if status != http.StatusOK {
			t.Fatalf("assign manager role status=%d", status)
		}

		status, _, highBody := h.Do(alice, http.MethodPost,
			"/v1/servers/"+serverA+"/roles", map[string]any{
				"name": "administrator", "permissions": db.PermAdministrator,
			})
		if status != http.StatusCreated {
			t.Fatalf("create administrator role status=%d body=%v", status, highBody)
		}
		highRole := highBody["id"].(string)

		status, _, _ = h.Do(bob, http.MethodPost,
			"/v1/servers/"+serverA+"/roles", map[string]any{
				"name": "self-admin", "permissions": db.PermAdministrator,
			})
		if status != http.StatusForbidden {
			t.Fatalf("manager created permissions it lacks: status=%d", status)
		}
		status, _, _ = h.Do(bob, http.MethodPatch,
			"/v1/servers/"+serverA+"/roles/"+managerRole,
			map[string]any{"permissions": db.PermAdministrator})
		if status != http.StatusForbidden {
			t.Fatalf("manager escalated own role: status=%d", status)
		}
		status, _, _ = h.Do(bob, http.MethodPut,
			"/v1/servers/"+serverA+"/members/"+bob.ID+"/roles/"+highRole, nil)
		if status != http.StatusForbidden {
			t.Fatalf("manager assigned superior role to self: status=%d", status)
		}

		status, _, safeBody := h.Do(bob, http.MethodPost,
			"/v1/servers/"+serverA+"/roles", map[string]any{
				"name": "subordinate", "permissions": uint64(0),
			})
		if status != http.StatusCreated {
			t.Fatalf("manager could not create subordinate role: status=%d body=%v", status, safeBody)
		}
		safeRole := safeBody["id"].(string)
		status, _, _ = h.Do(bob, http.MethodPatch,
			"/v1/servers/"+serverA+"/roles/"+safeRole,
			map[string]any{"permissions": db.PermKickMembers})
		if status != http.StatusForbidden {
			t.Fatalf("manager granted unpossessed permission: status=%d", status)
		}
		status, _, _ = h.Do(bob, http.MethodPut,
			"/v1/servers/"+serverA+"/members/"+mallory.ID+"/roles/"+safeRole, nil)
		if status != http.StatusOK {
			t.Fatalf("manager could not assign subordinate role: status=%d", status)
		}
		status, _, _ = h.Do(bob, http.MethodPut,
			"/v1/servers/"+serverA+"/members/"+bob.ID+"/roles/"+safeRole, nil)
		if status != http.StatusForbidden {
			t.Fatalf("manager changed own role assignments: status=%d", status)
		}
	})

	t.Run("channel permissions gate directory sync send and channel events", func(t *testing.T) {
		ctx := context.Background()
		serverID := mkServer(t, h, alice, "security-channel-acl")
		invite := mkInviteCode(t, h, alice, serverID)
		joinViaInvite(t, h, bob, invite)
		joinViaInvite(t, h, mallory, invite)

		status, _, channelsBody := h.Do(alice, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK {
			t.Fatalf("owner list channels status=%d body=%v", status, channelsBody)
		}
		channels := channelsBody["channels"].([]any)
		general := channels[0].(map[string]any)
		channelID := general["id"].(string)
		conversationID := general["conversation_id"].(string)

		status, _, rolesBody := h.Do(alice, http.MethodGet, "/v1/servers/"+serverID+"/roles", nil)
		if status != http.StatusOK {
			t.Fatalf("list roles status=%d body=%v", status, rolesBody)
		}
		var defaultRole string
		for _, raw := range rolesBody["roles"].([]any) {
			role := raw.(map[string]any)
			if role["is_default"] == true {
				defaultRole = role["id"].(string)
			}
		}
		if defaultRole == "" {
			t.Fatal("default role not found")
		}
		status, _, _ = h.Do(alice, http.MethodPatch,
			"/v1/servers/"+serverID+"/roles/"+defaultRole,
			map[string]any{"permissions": uint64(0)})
		if status != http.StatusOK {
			t.Fatalf("clear default permissions status=%d", status)
		}

		status, _, speakerBody := h.Do(alice, http.MethodPost,
			"/v1/servers/"+serverID+"/roles", map[string]any{
				"name": "speaker", "permissions": db.PermViewChannel | db.PermSendMessages,
			})
		if status != http.StatusCreated {
			t.Fatalf("create speaker role status=%d body=%v", status, speakerBody)
		}
		speakerRole := speakerBody["id"].(string)
		status, _, _ = h.Do(alice, http.MethodPut,
			"/v1/servers/"+serverID+"/members/"+bob.ID+"/roles/"+speakerRole, nil)
		if status != http.StatusOK {
			t.Fatalf("assign speaker role status=%d", status)
		}

		status, _, _ = h.Do(bob, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK {
			t.Fatalf("VIEW_CHANNEL member list status=%d, want 200", status)
		}
		status, _, hiddenChannels := h.Do(mallory, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK || len(hiddenChannels["channels"].([]any)) != 0 {
			t.Fatalf("no-view member channel list leaked metadata: status=%d body=%v", status, hiddenChannels)
		}
		status, _, _ = h.Do(bob, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusForbidden {
			t.Fatalf("no-history directory status=%d, want 403", status)
		}
		status, _, ownerDirectory := h.Do(alice, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusOK {
			t.Fatalf("owner directory status=%d body=%v", status, ownerDirectory)
		}
		ownerMembers := ownerDirectory["members"].([]any)
		if len(ownerMembers) != 1 || ownerMembers[0].(map[string]any)["user_id"] != alice.ID {
			t.Fatalf("unauthorized channel users leaked in directory: %v", ownerMembers)
		}

		_, _, _, err := h.Chat.HandleSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: conversationID, Ciphertext: []byte("speaker ciphertext"), Header: []byte("speaker header"),
		})
		if !errors.Is(err, db.ErrMessageSecurityContext) {
			t.Fatalf("legacy channel send error=%v, want ErrMessageSecurityContext", err)
		}

		capture := &captureBroadcaster{}
		serverSvc := servers.NewService(h.DB, capture)
		updatedName := "general-renamed"
		if err := serverSvc.UpdateChannel(ctx, channelID, alice.ID, &updatedName, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		call := capture.last(t)
		if !containsString(call.userIDs, alice.ID) || !containsString(call.userIDs, bob.ID) || containsString(call.userIDs, mallory.ID) {
			t.Fatalf("channel metadata broadcast recipients = %v", call.userIDs)
		}

		permissions := db.ChannelReadPermissions | db.PermSendMessages
		status, _, _ = h.Do(alice, http.MethodPatch,
			"/v1/servers/"+serverID+"/roles/"+speakerRole,
			map[string]any{"permissions": permissions})
		if status != http.StatusOK {
			t.Fatalf("grant history status=%d", status)
		}
		status, _, directory := h.Do(bob, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusOK {
			t.Fatalf("authorized directory status=%d body=%v", status, directory)
		}
		members := directory["members"].([]any)
		if len(members) != 2 {
			t.Fatalf("authorized directory members=%v", members)
		}
		seen := map[string]bool{}
		for _, raw := range members {
			member := raw.(map[string]any)
			seen[member["user_id"].(string)] = true
			if len(member["identity_key"].(string)) != 64 || len(member["signing_key"].(string)) != 64 || member["joined_at"] == "" {
				t.Fatalf("incomplete authorized directory member: %v", member)
			}
		}
		if !seen[alice.ID] || !seen[bob.ID] || seen[mallory.ID] {
			t.Fatalf("authorized directory binding mismatch: %v", members)
		}
		security := secureMessageContextForDevice(t, h, conversationID, bob.ID, bobDevice)
		_, _, recipients, err := h.Chat.HandleSecureSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: conversationID, Ciphertext: []byte("speaker ciphertext"), Header: []byte("speaker header"),
		}, security)
		if err != nil {
			t.Fatalf("VIEW+READ+SEND member could not send securely: %v", err)
		}
		if len(recipients) != 1 || recipients[0] != alice.ID {
			t.Fatalf("unauthorized member entered secure message fanout: %v", recipients)
		}

		capture.reset()
		if err := serverSvc.UnassignRole(ctx, serverID, alice.ID, bob.ID, speakerRole); err != nil {
			t.Fatal(err)
		}
		roleEvent := capture.last(t).env.GetServerEvent()
		if roleEvent == nil || roleEvent.GetEventType() != pb.ServerEvent_ROLE_UPDATED ||
			roleEvent.GetMemberInfo() == nil || roleEvent.GetRoleInfo().GetId() != speakerRole {
			t.Fatalf("role revocation broadcast missing authoritative member/role: %v", roleEvent)
		}
		allowed, err := h.DB.CanAccessConversation(ctx, conversationID, bob.ID, db.ChannelReadPermissions)
		if err != nil || allowed {
			t.Fatalf("role revoke did not remove channel access: allowed=%v err=%v", allowed, err)
		}
		status, _, directory = h.Do(alice, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusOK || len(directory["members"].([]any)) != 1 {
			t.Fatalf("revoked member remained in directory: status=%d body=%v", status, directory)
		}
	})

	t.Run("channel overwrites gate channel list directory sync send and retained sender keys", func(t *testing.T) {
		ctx := context.Background()
		serverID := mkServer(t, h, alice, "security-channel-overwrites")
		invite := mkInviteCode(t, h, alice, serverID)
		joinViaInvite(t, h, bob, invite)
		joinViaInvite(t, h, mallory, invite)
		outsider := h.CreateUser("security-overwrite-outsider")

		status, _, channelsBody := h.Do(alice, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK {
			t.Fatalf("owner list channels status=%d body=%v", status, channelsBody)
		}
		general := channelsBody["channels"].([]any)[0].(map[string]any)
		channelID := general["id"].(string)
		conversationID := general["conversation_id"].(string)

		status, _, rolesBody := h.Do(alice, http.MethodGet, "/v1/servers/"+serverID+"/roles", nil)
		if status != http.StatusOK {
			t.Fatalf("list roles status=%d body=%v", status, rolesBody)
		}
		var defaultRole string
		for _, raw := range rolesBody["roles"].([]any) {
			role := raw.(map[string]any)
			if role["is_default"] == true {
				defaultRole = role["id"].(string)
			}
		}
		if defaultRole == "" {
			t.Fatal("default role not found")
		}

		status, _, readerBody := h.Do(alice, http.MethodPost,
			"/v1/servers/"+serverID+"/roles", map[string]any{
				"name": "channel-reader", "permissions": uint64(0),
			})
		if status != http.StatusCreated {
			t.Fatalf("create reader role status=%d body=%v", status, readerBody)
		}
		readerRole := readerBody["id"].(string)
		status, _, _ = h.Do(alice, http.MethodPut,
			"/v1/servers/"+serverID+"/members/"+bob.ID+"/roles/"+readerRole, nil)
		if status != http.StatusOK {
			t.Fatalf("assign reader role status=%d", status)
		}

		channelReadSend := db.ChannelReadPermissions | db.PermSendMessages
		status, _, body := h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": defaultRole, "target_type": db.ChannelOverwriteRole,
				"allow": uint64(0), "deny": channelReadSend,
			})
		if status != http.StatusOK {
			t.Fatalf("deny @everyone overwrite status=%d body=%v", status, body)
		}
		status, _, body = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": readerRole, "target_type": db.ChannelOverwriteRole,
				"allow": db.ChannelReadPermissions, "deny": db.PermSendMessages,
			})
		if status != http.StatusOK {
			t.Fatalf("reader role overwrite status=%d body=%v", status, body)
		}

		status, _, bobChannels := h.Do(bob, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK || len(bobChannels["channels"].([]any)) != 1 {
			t.Fatalf("role-authorized channel list status=%d body=%v", status, bobChannels)
		}
		status, _, malloryChannels := h.Do(mallory, http.MethodGet, "/v1/servers/"+serverID+"/channels", nil)
		if status != http.StatusOK || len(malloryChannels["channels"].([]any)) != 0 {
			t.Fatalf("hidden channel leaked in list: status=%d body=%v", status, malloryChannels)
		}
		status, _, directory := h.Do(bob, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusOK || len(directory["members"].([]any)) != 2 {
			t.Fatalf("role-authorized directory status=%d body=%v", status, directory)
		}
		status, _, _ = h.Do(mallory, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusForbidden {
			t.Fatalf("hidden member directory status=%d, want 403", status)
		}
		status, _, _ = h.Do(bob, http.MethodGet, "/v1/messages/"+conversationID, nil)
		if status != http.StatusOK {
			t.Fatalf("role-authorized message sync status=%d", status)
		}
		if _, _, _, err := h.Chat.HandleSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: conversationID, Ciphertext: []byte("blocked by role overwrite"),
		}); !errors.Is(err, chat.ErrNotMember) {
			t.Fatalf("role send deny error=%v, want ErrNotMember", err)
		}
		status, _, _ = h.Do(bob, http.MethodGet, "/v1/channels/"+channelID+"/overwrites", nil)
		if status != http.StatusForbidden {
			t.Fatalf("non-manager overwrite list status=%d, want 403", status)
		}

		status, _, body = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": bob.ID, "target_type": db.ChannelOverwriteUser,
				"allow": db.PermSendMessages, "deny": uint64(0),
			})
		if status != http.StatusOK {
			t.Fatalf("member send allow status=%d body=%v", status, body)
		}
		security := secureMessageContextForDevice(t, h, conversationID, bob.ID, bobDevice)
		_, _, recipients, err := h.Chat.HandleSecureSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: conversationID, Ciphertext: []byte("allowed by member overwrite"),
		}, security)
		if err != nil || len(recipients) != 1 || recipients[0] != alice.ID {
			t.Fatalf("member send allow err=%v recipients=%v", err, recipients)
		}

		roster := requireReadySecurityRoster(t, h, conversationID)
		if err := h.DB.StoreDeviceSenderKey(
			ctx, conversationID, aliceDevice.ID, bobDevice.ID, []byte("sealed-skdm"), 1,
			roster.Version, roster.Commitment[:], 1, 1,
		); err != nil {
			t.Fatal(err)
		}
		pending, err := h.DB.GetPendingSenderKeys(ctx, bobDevice.ID)
		if err != nil || len(pending) != 1 {
			t.Fatalf("authorized retained sender keys=%v err=%v", pending, err)
		}

		// Removing one role must not collect the target's history when another
		// independently applicable role preserves the exact read authorization.
		alternateReader, err := h.DB.CreateRole(
			ctx, serverID, "continuous-reader", 0, nil, nil,
		)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.AssignRole(ctx, serverID, bob.ID, alternateReader.ID); err != nil {
			t.Fatal(err)
		}
		if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
			ChannelID: channelID, TargetID: alternateReader.ID,
			TargetType: db.ChannelOverwriteRole,
			Allow:      db.ChannelReadPermissions,
			Deny:       db.PermSendMessages,
		}); err != nil {
			t.Fatal(err)
		}
		if err := h.DB.UnassignRole(ctx, serverID, bob.ID, readerRole); err != nil {
			t.Fatal(err)
		}
		pending, err = h.DB.GetPendingSenderKeys(ctx, bobDevice.ID)
		if err != nil || len(pending) != 1 {
			t.Fatalf("continuously authorized target lost retained key=%v err=%v", pending, err)
		}

		status, _, body = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": bob.ID, "target_type": db.ChannelOverwriteUser,
				"allow": db.PermSendMessages, "deny": db.PermReadMessageHistory,
			})
		if status != http.StatusOK {
			t.Fatalf("member history deny status=%d body=%v", status, body)
		}
		if _, err := h.DB.Pool.Exec(ctx,
			`UPDATE sender_keys
			 SET created_at = now() - INTERVAL '2 hours',
			     expires_at = now() - INTERVAL '1 hour'
			 WHERE conversation_id = $1::uuid
			   AND owner_device_id = $2::uuid
			   AND target_device_id = $3::uuid`,
			conversationID, aliceDevice.ID, bobDevice.ID,
		); err != nil {
			t.Fatal(err)
		}
		otherConversationID, err := h.DB.CreateGroup(ctx, "overwrite-prune-other", alice.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.AddGroupMember(ctx, otherConversationID, bob.ID, 0); err != nil {
			t.Fatal(err)
		}
		otherRoster := requireReadySecurityRoster(t, h, otherConversationID)
		otherBlob := []byte("other-conversation-skdm")
		if err := h.DB.StoreDeviceSenderKey(
			ctx, otherConversationID, aliceDevice.ID, bobDevice.ID, otherBlob, 1,
			otherRoster.Version, otherRoster.Commitment[:], 1, 1,
		); err != nil {
			t.Fatalf("expired unauthorized row blocked another conversation admission: %v", err)
		}
		otherCommitment := sha256.Sum256(otherBlob)
		if err := h.DB.AcknowledgeSenderKey(
			ctx, otherConversationID, aliceDevice.ID, bobDevice.ID, 1,
			otherRoster.Version, otherCommitment[:],
		); err != nil {
			t.Fatal(err)
		}
		var unauthorizedRows, preservedHeads int
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM sender_keys
			 WHERE conversation_id = $1::uuid AND target_device_id = $2::uuid`,
			conversationID, bobDevice.ID,
		).Scan(&unauthorizedRows); err != nil || unauthorizedRows != 0 {
			t.Fatalf("ACL-removed target rows=%d err=%v, want 0", unauthorizedRows, err)
		}
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM sender_key_heads
			 WHERE conversation_id = $1::uuid AND target_device_id = $2::uuid`,
			conversationID, bobDevice.ID,
		).Scan(&preservedHeads); err != nil || preservedHeads != 1 {
			t.Fatalf("ACL removal sender-key heads=%d err=%v, want preserved head", preservedHeads, err)
		}
		status, _, _ = h.Do(bob, http.MethodGet, "/v1/conversations/"+conversationID+"/members", nil)
		if status != http.StatusForbidden {
			t.Fatalf("history-denied directory status=%d, want 403", status)
		}
		status, _, _ = h.Do(bob, http.MethodGet, "/v1/messages/"+conversationID, nil)
		if status != http.StatusForbidden {
			t.Fatalf("history-denied sync status=%d, want 403", status)
		}
		status, _, discovery := h.Do(bob, http.MethodGet, "/v1/conversations", nil)
		if status != http.StatusOK {
			t.Fatalf("history-denied discovery status=%d body=%v", status, discovery)
		}
		for _, raw := range discovery["conversations"].([]any) {
			if raw.(map[string]any)["id"] == conversationID {
				t.Fatalf("history-denied channel leaked in discovery: %v", discovery)
			}
		}
		pending, err = h.DB.GetPendingSenderKeys(ctx, bobDevice.ID)
		if err != nil || len(pending) != 0 {
			t.Fatalf("history-denied sender keys were not pruned=%v err=%v", pending, err)
		}
		if _, _, _, err := h.Chat.HandleSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: conversationID, Ciphertext: []byte("send without history"),
		}); !errors.Is(err, db.ErrMessageSecurityContext) {
			t.Fatalf("send-only legacy channel write error=%v, want fail-closed Sender-Key context rejection", err)
		}

		status, _, _ = h.Do(alice, http.MethodDelete,
			fmt.Sprintf("/v1/channels/%s/overwrites/%d/%s", channelID, db.ChannelOverwriteUser, bob.ID), nil)
		if status != http.StatusOK {
			t.Fatalf("delete member overwrite status=%d", status)
		}
		pending, err = h.DB.GetPendingSenderKeys(ctx, bobDevice.ID)
		if err != nil || len(pending) != 0 {
			t.Fatalf("future-only re-admission resurrected old sender keys=%v err=%v", pending, err)
		}

		// A committed loss transition must collect the old target row even when
		// access is restored before any roster resolve, login or pending-key
		// query. Otherwise a fast remove->re-add would resurrect old history.
		reAdmittedRoster := requireReadySecurityRoster(t, h, conversationID)
		transientBlob := []byte("must-not-survive-fast-re-admission")
		if err := h.DB.StoreDeviceSenderKey(
			ctx, conversationID, aliceDevice.ID, bobDevice.ID, transientBlob, 2,
			reAdmittedRoster.Version, reAdmittedRoster.Commitment[:], 1, 1,
		); err != nil {
			t.Fatal(err)
		}
		status, _, body = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": bob.ID, "target_type": db.ChannelOverwriteUser,
				"allow": uint64(0), "deny": db.PermReadMessageHistory,
			})
		if status != http.StatusOK {
			t.Fatalf("fast re-admission deny status=%d body=%v", status, body)
		}
		status, _, _ = h.Do(alice, http.MethodDelete,
			fmt.Sprintf("/v1/channels/%s/overwrites/%d/%s", channelID, db.ChannelOverwriteUser, bob.ID), nil)
		if status != http.StatusOK {
			t.Fatalf("fast re-admission restore status=%d", status)
		}
		pending, err = h.DB.GetPendingSenderKeys(ctx, bobDevice.ID)
		if err != nil || len(pending) != 0 {
			t.Fatalf("fast re-admission resurrected old sender keys=%v err=%v", pending, err)
		}
		var transientHead int64
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT max_generation FROM sender_key_heads
			 WHERE conversation_id = $1::uuid
			   AND owner_device_id = $2::uuid
			   AND target_device_id = $3::uuid`,
			conversationID, aliceDevice.ID, bobDevice.ID,
		).Scan(&transientHead); err != nil || transientHead != 2 {
			t.Fatalf("fast re-admission head=%d err=%v, want preserved generation 2", transientHead, err)
		}

		status, _, _ = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": bob.ID, "target_type": db.ChannelOverwriteUser,
				"allow": db.PermViewChannel, "deny": db.PermViewChannel,
			})
		if status != http.StatusBadRequest {
			t.Fatalf("overlapping allow/deny status=%d, want 400", status)
		}
		status, _, _ = h.Do(alice, http.MethodPut,
			"/v1/channels/"+channelID+"/overwrites", map[string]any{
				"target_id": outsider.ID, "target_type": db.ChannelOverwriteUser,
				"allow": db.PermViewChannel, "deny": uint64(0),
			})
		if status != http.StatusBadRequest {
			t.Fatalf("foreign-server overwrite target status=%d, want 400", status)
		}

		// The database is a second authorization boundary: direct writers must
		// not be able to persist masks/targets the REST service rejects.
		if _, err := h.DB.Pool.Exec(ctx,
			`DELETE FROM roles WHERE id = $1::uuid`, defaultRole,
		); err == nil {
			t.Fatal("database allowed deletion of the only default role")
		}
		var defaultCount int
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM roles WHERE server_id = $1::uuid AND is_default = TRUE`, serverID,
		).Scan(&defaultCount); err != nil || defaultCount != 1 {
			t.Fatalf("default role invariant count=%d err=%v", defaultCount, err)
		}

		for _, invalidPermissions := range []int64{-1, int64(uint64(1) << 20)} {
			if _, err := h.DB.Pool.Exec(ctx,
				`INSERT INTO roles (server_id, name, permissions, position, is_default)
				 VALUES ($1::uuid, 'invalid-mask', $2, 1, FALSE)`,
				serverID, invalidPermissions,
			); err == nil {
				t.Fatalf("database accepted invalid role permission mask %d", invalidPermissions)
			}
		}

		var cleanupRole string
		if err := h.DB.Pool.QueryRow(ctx,
			`INSERT INTO roles (server_id, name, permissions, position, is_default)
			 VALUES ($1::uuid, 'overwrite-cleanup', 0, 1, FALSE)
			 RETURNING id::text`, serverID,
		).Scan(&cleanupRole); err != nil {
			t.Fatalf("create cleanup role: %v", err)
		}
		for _, masks := range [][2]int64{
			{int64(uint64(1) << 20), 0},
			{int64(db.PermViewChannel), int64(db.PermViewChannel)},
		} {
			if _, err := h.DB.Pool.Exec(ctx,
				`INSERT INTO channel_overwrites (channel_id, target_id, target_type, allow, deny)
				 VALUES ($1::uuid, $2::uuid, 0, $3, $4)`,
				channelID, cleanupRole, masks[0], masks[1],
			); err == nil {
				t.Fatalf("database accepted invalid overwrite allow=%d deny=%d", masks[0], masks[1])
			}
		}
		if _, err := h.DB.Pool.Exec(ctx,
			`INSERT INTO channel_overwrites (channel_id, target_id, target_type, allow, deny)
			 VALUES ($1::uuid, $2::uuid, 1, $3, 0)`,
			channelID, outsider.ID, int64(db.PermViewChannel),
		); err == nil {
			t.Fatal("database accepted an overwrite for a user outside the server")
		}

		if _, err := h.DB.Pool.Exec(ctx,
			`INSERT INTO channel_overwrites (channel_id, target_id, target_type, allow, deny)
			 VALUES ($1::uuid, $2::uuid, 0, $3, 0)`,
			channelID, cleanupRole, int64(db.PermViewChannel),
		); err != nil {
			t.Fatalf("insert role cleanup overwrite: %v", err)
		}
		if _, err := h.DB.Pool.Exec(ctx, `DELETE FROM roles WHERE id = $1::uuid`, cleanupRole); err != nil {
			t.Fatalf("delete non-default role: %v", err)
		}
		var overwriteCount int
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM channel_overwrites
			 WHERE target_type = 0 AND target_id = $1::uuid`, cleanupRole,
		).Scan(&overwriteCount); err != nil || overwriteCount != 0 {
			t.Fatalf("deleted role retained %d overwrites err=%v", overwriteCount, err)
		}

		if _, err := h.DB.Pool.Exec(ctx,
			`INSERT INTO channel_overwrites (channel_id, target_id, target_type, allow, deny)
			 VALUES ($1::uuid, $2::uuid, 1, $3, 0)`,
			channelID, mallory.ID, int64(db.PermViewChannel),
		); err != nil {
			t.Fatalf("insert member cleanup overwrite: %v", err)
		}
		if _, err := h.DB.Pool.Exec(ctx,
			`DELETE FROM server_members WHERE server_id = $1::uuid AND user_id = $2::uuid`,
			serverID, mallory.ID,
		); err != nil {
			t.Fatalf("delete server member: %v", err)
		}
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM channel_overwrites overwrite
			 JOIN channels channel ON channel.id = overwrite.channel_id
			 WHERE channel.server_id = $1::uuid
			   AND overwrite.target_type = 1
			   AND overwrite.target_id = $2::uuid`,
			serverID, mallory.ID,
		).Scan(&overwriteCount); err != nil || overwriteCount != 0 {
			t.Fatalf("removed member retained %d overwrites err=%v", overwriteCount, err)
		}
	})

	t.Run("encrypted attachments are upload scoped and conversation scoped", func(t *testing.T) {
		ctx := context.Background()
		fileID := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := h.DB.CreateTusUpload(ctx, fileID, alice.ID, 10, "local", time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		if err := h.DB.FinishTusUpload(ctx, fileID, time.Now().Add(time.Hour)); err != nil {
			t.Fatal(err)
		}
		attachment := &pb.EncryptedAttachment{
			MediaId: fileID, EncryptedKey: []byte("wrapped-key"), Nonce: []byte("nonce"),
			Size: 10, ContentType: "application/octet-stream",
		}
		_, _, _, err := h.Chat.HandleSendMessage(ctx, bob.ID, &pb.SendMessage{
			ConversationId: aliceBobConversationID, Ciphertext: []byte("foreign upload"),
			Attachments: []*pb.EncryptedAttachment{attachment},
		})
		if !errors.Is(err, chat.ErrAttachmentAccess) {
			t.Fatalf("foreign upload attachment error=%v, want ErrAttachmentAccess", err)
		}
		messageID, _, _, err := h.Chat.HandleSendMessage(ctx, alice.ID, &pb.SendMessage{
			ConversationId: aliceBobConversationID, Ciphertext: []byte("attachment message"), Header: []byte("header"),
			Attachments: []*pb.EncryptedAttachment{attachment},
		})
		if err != nil {
			t.Fatalf("owner attachment send: %v", err)
		}
		allowed, err := h.DB.CanDownloadTusUpload(ctx, fileID, bob.ID)
		if err != nil || !allowed {
			t.Fatalf("current recipient download allowed=%v err=%v", allowed, err)
		}
		allowed, err = h.DB.CanDownloadTusUpload(ctx, fileID, mallory.ID)
		if err != nil || allowed {
			t.Fatalf("unrelated download allowed=%v err=%v", allowed, err)
		}
		status, _, syncBody := h.Do(bob, http.MethodGet, "/v1/messages/"+aliceBobConversationID, nil)
		if status != http.StatusOK {
			t.Fatalf("attachment sync status=%d body=%v", status, syncBody)
		}
		var synced map[string]any
		for _, raw := range syncBody["messages"].([]any) {
			message := raw.(map[string]any)
			if message["id"] == messageID {
				synced = message
			}
		}
		if synced == nil {
			t.Fatalf("attachment message absent from sync: %v", syncBody)
		}
		attachments := synced["attachments"].([]any)
		if len(attachments) != 1 || attachments[0].(map[string]any)["media_id"] != fileID ||
			attachments[0].(map[string]any)["content_type"] != "application/octet-stream" {
			t.Fatalf("unsafe/incomplete attachment descriptor: %v", attachments)
		}
		if _, _, _, err := h.Chat.HandleSendMessage(ctx, alice.ID, &pb.SendMessage{
			ConversationId: aliceBobConversationID, Ciphertext: []byte("bad size"),
			Attachments: []*pb.EncryptedAttachment{{
				MediaId: fileID, EncryptedKey: []byte("key"), Nonce: []byte("nonce"), Size: 11,
				ContentType: "application/octet-stream",
			}},
		}); !errors.Is(err, chat.ErrAttachmentAccess) {
			t.Fatalf("size mismatch error=%v, want ErrAttachmentAccess", err)
		}
		if _, _, _, err := h.Chat.HandleDeleteMessage(ctx, alice.ID, &pb.DeleteMessage{
			MessageId: messageID, ConversationId: aliceBobConversationID,
		}); err != nil {
			t.Fatal(err)
		}
		allowed, err = h.DB.CanDownloadTusUpload(ctx, fileID, bob.ID)
		if err != nil || allowed {
			t.Fatalf("deleted attachment remained downloadable: allowed=%v err=%v", allowed, err)
		}
		if _, err := h.DB.Pool.Exec(ctx, `UPDATE tus_uploads SET expires_at = now() - interval '1 second' WHERE file_id = $1`, fileID); err != nil {
			t.Fatal(err)
		}
		allowed, err = h.DB.CanDownloadTusUpload(ctx, fileID, alice.ID)
		if err != nil || allowed {
			t.Fatalf("expired uploader download allowed=%v err=%v", allowed, err)
		}
	})

	t.Run("push subscription cap is atomic under concurrency", func(t *testing.T) {
		ctx := context.Background()
		pushUser := h.CreateUser("security-push-cap")
		type result struct {
			id  int64
			err error
		}
		results := make(chan result, db.MaxPushSubscriptionsPerUser*2)
		var wg sync.WaitGroup
		for i := 0; i < db.MaxPushSubscriptionsPerUser*2; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				id, err := h.DB.CreatePushSubscription(ctx, pushUser.ID,
					integrationPushInput(fmt.Sprintf("https://push.example/%d", index), "device"))
				results <- result{id: id, err: err}
			}(i)
		}
		wg.Wait()
		close(results)
		succeeded, limited := 0, 0
		var existingID int64
		for result := range results {
			switch {
			case result.err == nil:
				succeeded++
				if existingID == 0 {
					existingID = result.id
				}
			case errors.Is(result.err, db.ErrPushSubscriptionLimit):
				limited++
			default:
				t.Fatalf("unexpected concurrent create error: %v", result.err)
			}
		}
		if succeeded != db.MaxPushSubscriptionsPerUser || limited != db.MaxPushSubscriptionsPerUser {
			t.Fatalf("push cap results: succeeded=%d limited=%d", succeeded, limited)
		}
		rows, err := h.DB.ListPushSubscriptions(ctx, pushUser.ID)
		if err != nil || len(rows) != db.MaxPushSubscriptionsPerUser {
			t.Fatalf("stored subscriptions=%d err=%v", len(rows), err)
		}
		var existing db.PushSubscription
		for _, row := range rows {
			if row.ID == existingID {
				existing = row
			}
		}
		id, err := h.DB.CreatePushSubscription(ctx, pushUser.ID, integrationPushInput(existing.EndpointURL, "renamed"))
		if err != nil || id != existingID {
			t.Fatalf("idempotent upsert at cap id=%d err=%v, want %d", id, err, existingID)
		}
	})

	t.Run("push delivery policy is owner scoped and enforced before fanout", func(t *testing.T) {
		ctx := context.Background()
		owner := h.CreateUser("security-push-policy-owner")
		other := h.CreateUser("security-push-policy-other")
		input := integrationPushInput("https://push.example/policy", "phone")
		id, err := h.DB.CreatePushSubscription(ctx, owner.ID, input)
		if err != nil {
			t.Fatal(err)
		}
		if ok, err := h.DB.ConfirmPushSubscription(ctx, owner.ID, id, input.ValidationTokenHash); err != nil || !ok {
			t.Fatalf("confirm push subscription ok=%v err=%v", ok, err)
		}
		disabled := false
		if ok, err := h.DB.UpdatePushSubscriptionPolicy(ctx, other.ID, id, &disabled, nil); err != nil || ok {
			t.Fatalf("cross-account policy update ok=%v err=%v", ok, err)
		}
		if ok, err := h.DB.UpdatePushSubscriptionPolicy(ctx, owner.ID, id, &disabled, nil); err != nil || !ok {
			t.Fatalf("owner disable ok=%v err=%v", ok, err)
		}
		active, err := h.DB.ListActivePushSubscriptions(ctx, owner.ID)
		if err != nil || len(active) != 0 {
			t.Fatalf("disabled subscription reached dispatcher projection: rows=%d err=%v", len(active), err)
		}
		enabled := true
		mute := int64(60)
		if ok, err := h.DB.UpdatePushSubscriptionPolicy(ctx, owner.ID, id, &enabled, &mute); err != nil || !ok {
			t.Fatalf("owner mute ok=%v err=%v", ok, err)
		}
		active, err = h.DB.ListActivePushSubscriptions(ctx, owner.ID)
		if err != nil || len(active) != 0 {
			t.Fatalf("muted subscription reached dispatcher projection: rows=%d err=%v", len(active), err)
		}
		clearMute := int64(0)
		if ok, err := h.DB.UpdatePushSubscriptionPolicy(ctx, owner.ID, id, nil, &clearMute); err != nil || !ok {
			t.Fatalf("owner unmute ok=%v err=%v", ok, err)
		}
		active, err = h.DB.ListActivePushSubscriptions(ctx, owner.ID)
		if err != nil || len(active) != 1 || active[0].ID != id {
			t.Fatalf("unmuted subscription missing: rows=%v err=%v", active, err)
		}
	})

	t.Run("upload quota reservation is atomic under concurrency", func(t *testing.T) {
		ctx := context.Background()
		uploadUser := h.CreateUser("security-upload-quota")
		start := make(chan struct{})
		errs := make(chan error, 2)
		var wg sync.WaitGroup
		for _, fileID := range []string{
			"cccccccccccccccccccccccccccccccc",
			"dddddddddddddddddddddddddddddddd",
		} {
			wg.Add(1)
			go func(id string) {
				defer wg.Done()
				<-start
				errs <- h.DB.ReserveTusUpload(
					ctx, id, uploadUser.ID, 600, "local", time.Now().Add(time.Hour),
					time.Now().Add(-time.Hour), 1000,
				)
			}(fileID)
		}
		close(start)
		wg.Wait()
		close(errs)
		accepted, rejected := 0, 0
		for err := range errs {
			switch {
			case err == nil:
				accepted++
			case errors.Is(err, db.ErrTusQuotaExceeded):
				rejected++
			default:
				t.Fatalf("unexpected quota reservation error: %v", err)
			}
		}
		if accepted != 1 || rejected != 1 {
			t.Fatalf("upload quota results accepted=%d rejected=%d", accepted, rejected)
		}
		var rows int
		var bytes int64
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*), COALESCE(SUM(size_bytes), 0)
			 FROM tus_uploads WHERE user_id = $1::uuid`, uploadUser.ID,
		).Scan(&rows, &bytes); err != nil {
			t.Fatal(err)
		}
		if rows != 1 || bytes != 600 {
			t.Fatalf("reserved rows=%d bytes=%d, want 1/600", rows, bytes)
		}
	})

	t.Run("kick member enforces strict role hierarchy", func(t *testing.T) {
		serverID := mkServer(t, h, alice, "security-kick-hierarchy")
		invite := mkInviteCode(t, h, alice, serverID)
		joinViaInvite(t, h, bob, invite)
		joinViaInvite(t, h, mallory, invite)
		status, _, lowBody := h.Do(alice, http.MethodPost, "/v1/servers/"+serverID+"/roles", map[string]any{
			"name": "moderator", "permissions": db.PermKickMembers,
		})
		if status != http.StatusCreated {
			t.Fatalf("create moderator status=%d body=%v", status, lowBody)
		}
		lowRole := lowBody["id"].(string)
		status, _, highBody := h.Do(alice, http.MethodPost, "/v1/servers/"+serverID+"/roles", map[string]any{
			"name": "senior", "permissions": uint64(0),
		})
		if status != http.StatusCreated {
			t.Fatalf("create senior status=%d body=%v", status, highBody)
		}
		highRole := highBody["id"].(string)
		for userID, roleID := range map[string]string{bob.ID: lowRole, mallory.ID: highRole} {
			status, _, _ = h.Do(alice, http.MethodPut,
				"/v1/servers/"+serverID+"/members/"+userID+"/roles/"+roleID, nil)
			if status != http.StatusOK {
				t.Fatalf("assign hierarchy role status=%d", status)
			}
		}
		status, _, _ = h.Do(bob, http.MethodDelete, "/v1/servers/"+serverID+"/members/"+mallory.ID, nil)
		if status != http.StatusForbidden {
			t.Fatalf("subordinate kick superior status=%d, want 403", status)
		}
		member, err := h.DB.IsServerMember(context.Background(), serverID, mallory.ID)
		if err != nil || !member {
			t.Fatalf("failed hierarchy kick removed target: member=%v err=%v", member, err)
		}
		status, _, _ = h.Do(alice, http.MethodDelete, "/v1/servers/"+serverID+"/members/"+mallory.ID, nil)
		if status != http.StatusOK {
			t.Fatalf("owner kick status=%d, want 200", status)
		}
	})
}

func requireReadySecurityRoster(t *testing.T, h *Harness, conversationID string) *db.ConversationDeviceRoster {
	t.Helper()
	roster, err := h.DB.ResolveConversationDeviceRoster(
		context.Background(), conversationID, db.RequiredChannelCapabilities,
	)
	if err != nil {
		t.Fatalf("resolve secure roster: %v", err)
	}
	if roster == nil || !roster.Ready || roster.Version == 0 {
		t.Fatalf("secure roster is not ready: %+v", roster)
	}
	return roster
}

func secureMessageContextForDevice(t *testing.T, h *Harness, conversationID, userID string, device *db.Device) *db.MessageSecurityContext {
	t.Helper()
	if device == nil {
		t.Fatal("secure message device is nil")
	}
	roster := requireReadySecurityRoster(t, h, conversationID)
	binding, err := h.DB.GetLatestDeviceBinding(context.Background(), device.ID)
	if err != nil {
		t.Fatalf("load secure message device binding: %v", err)
	}
	return &db.MessageSecurityContext{
		CryptoProfile:          db.MessageCryptoProfileSenderKeyV5,
		CryptoEra:              db.MessageCryptoEraSenderKeyV5,
		RosterVersion:          roster.Version,
		RosterCommitment:       append([]byte(nil), roster.Commitment[:]...),
		SenderDeviceID:         append([]byte(nil), device.DeviceKey...),
		SenderBindingVersion:   binding.Version,
		SenderDeviceDatabaseID: device.ID,
	}
}

type broadcastCall struct {
	userIDs []string
	env     *pb.Envelope
}

type captureBroadcaster struct {
	mu    sync.Mutex
	calls []broadcastCall
}

func (b *captureBroadcaster) BroadcastToUsers(userIDs []string, env *pb.Envelope) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.calls = append(b.calls, broadcastCall{userIDs: append([]string(nil), userIDs...), env: env})
}

func (b *captureBroadcaster) reset() {
	b.mu.Lock()
	b.calls = nil
	b.mu.Unlock()
}

func (b *captureBroadcaster) last(t *testing.T) broadcastCall {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.calls) == 0 {
		t.Fatal("expected broadcast call")
	}
	return b.calls[len(b.calls)-1]
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func randomX25519KeyPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	private := randomBytes(t, 32)
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}
