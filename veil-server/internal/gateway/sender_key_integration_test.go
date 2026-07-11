//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/config"
	integrationtest "github.com/AegisSec/veil-server/internal/integration"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

func TestSenderKeyDurableOfflineDeliveryAndValidation(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	alice := h.CreateUser("skdm-alice")
	bob := h.CreateUser("skdm-bob")
	mallory := h.CreateUser("skdm-mallory")

	aliceDeviceKey := randomDeviceKey(t)
	bobDeviceKey1 := randomDeviceKey(t)
	bobDeviceKey2 := randomDeviceKey(t)
	malloryDeviceKey := randomDeviceKey(t)
	aliceDevice, err := h.DB.CreateDevice(ctx, alice.ID, aliceDeviceKey, "alice-device")
	if err != nil {
		t.Fatal(err)
	}
	bobDevice1, err := h.DB.CreateDevice(ctx, bob.ID, bobDeviceKey1, "bob-device-1")
	if err != nil {
		t.Fatal(err)
	}
	bobDevice2, err := h.DB.CreateDevice(ctx, bob.ID, bobDeviceKey2, "bob-device-2")
	if err != nil {
		t.Fatal(err)
	}
	malloryDevice, err := h.DB.CreateDevice(ctx, mallory.ID, malloryDeviceKey, "mallory-device")
	if err != nil {
		t.Fatal(err)
	}

	aliceBobConversation, err := h.DB.CreateGroup(ctx, "alice-bob-group", alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, aliceBobConversation, bob.ID, 0); err != nil {
		t.Fatal(err)
	}
	aliceMalloryConversation, err := h.DB.CreateGroup(ctx, "alice-mallory-group", alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, aliceMalloryConversation, mallory.ID, 0); err != nil {
		t.Fatal(err)
	}
	aliceBobDM, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}

	hub := &Hub{
		chatSvc:     h.Chat,
		userClients: make(map[string]map[*Client]bool),
	}
	sender := &Client{
		hub:           hub,
		send:          make(chan []byte, 16),
		authenticated: true,
		userID:        alice.ID,
		deviceID:      aliceDevice.ID,
		identityKey:   alice.IdentityKey,
	}

	// DMs use the Double Ratchet and must never accept or retain group Sender
	// Key distributions, even when both users are valid members.
	dmWire := makeSenderKeyEnvelopeV3(
		aliceBobDM, 1, alice.IdentityKey, alice.SigningKey, bob.IdentityKey,
	)
	sender.handleSenderKeyDist(ctx, 31, &pb.SenderKeyDistribution{
		ConversationId:    aliceBobDM,
		SenderKeyMessage:  dmWire,
		Generation:        1,
		TargetIdentityKey: bob.IdentityKey,
	})
	dmRejected := receiveGatewayEnvelope(t, sender.send)
	if dmRejected.GetError() == nil || dmRejected.GetMessageAck() != nil {
		t.Fatalf("DM sender-key distribution was ACKed: %v", dmRejected)
	}
	for _, device := range []string{bobDevice1.ID, bobDevice2.ID} {
		rows, err := h.DB.GetPendingSenderKeys(ctx, device)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 0 {
			t.Fatalf("DM sender-key distribution was retained for %s: %+v", device, rows)
		}
	}

	validWire := makeSenderKeyEnvelopeV3(
		aliceBobConversation, 7, alice.IdentityKey, alice.SigningKey, bob.IdentityKey,
	)
	sender.handleSenderKeyDist(ctx, 41, &pb.SenderKeyDistribution{
		ConversationId:    aliceBobConversation,
		SenderKeyMessage:  validWire,
		Generation:        7,
		TargetIdentityKey: bob.IdentityKey,
	})
	ack := receiveGatewayEnvelope(t, sender.send)
	if ack.GetMessageAck() == nil || ack.GetMessageAck().GetRefSeq() != 41 {
		t.Fatalf("durably stored distribution was not ACKed: %v", ack)
	}

	for _, device := range []string{bobDevice1.ID, bobDevice2.ID} {
		rows, err := h.DB.GetPendingSenderKeys(ctx, device)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Generation != 7 || !bytes.Equal(rows[0].EncryptedKey, validWire) {
			t.Fatalf("device %s pending rows = %+v, want generation 7", device, rows)
		}
	}

	// A later authentication of one offline device receives retained
	// SenderKeyDist before the AuthResult barrier. The row remains for idempotent
	// replay until a device-level delivery ACK exists.
	authSvc := auth.NewService(h.DB, &config.Config{
		AuthChallengeTTL: 5 * time.Second,
		AuthMaxAttempts:  3,
	})
	hub.authSvc = authSvc
	serverPublic, err := authSvc.CreateChallenge("offline-bob")
	if err != nil {
		t.Fatal(err)
	}
	shared, err := curve25519.X25519(bob.IdentityPrivate, serverPublic[:])
	if err != nil {
		t.Fatal(err)
	}
	proof, err := auth.WSAuthSigningMessage(serverPublic[:], shared)
	if err != nil {
		t.Fatal(err)
	}
	offlineBob := &Client{
		hub: hub,
		// Capacity one forces AuthResult to wait behind retained state and
		// makes the fan-out publication barrier deterministic in this test.
		send:   make(chan []byte, 1),
		connID: "offline-bob",
	}
	authDone := make(chan struct{})
	go func() {
		defer close(authDone)
		offlineBob.handleAuth(ctx, 51, &pb.AuthResponse{
			IdentityKey: bob.IdentityKey,
			SigningKey:  bob.SigningPublic,
			Signature:   ed25519.Sign(bob.SigningKey, proof),
			DeviceId:    bobDeviceKey1,
			DeviceName:  "bob-device-1",
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for len(offlineBob.send) != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(offlineBob.send) != 1 {
		t.Fatal("retained SenderKeyDist was not queued")
	}
	hub.mu.RLock()
	indexedBeforeControlDrain := hub.userClients[bob.ID][offlineBob]
	hub.mu.RUnlock()
	if indexedBeforeControlDrain {
		t.Fatal("client was published to live fan-out before retained control state was queued")
	}
	retained := receiveGatewayEnvelope(t, offlineBob.send).GetSenderKeyDist()
	if retained == nil || retained.GetConversationId() != aliceBobConversation ||
		retained.GetGeneration() != 7 || !bytes.Equal(retained.GetSenderKeyMessage(), validWire) ||
		!bytes.Equal(retained.GetTargetIdentityKey(), bob.IdentityKey) {
		t.Fatalf("unexpected retained sender key event: %v", retained)
	}
	authResult := receiveGatewayEnvelope(t, offlineBob.send)
	if authResult.GetAuthResult() == nil || !authResult.GetAuthResult().GetSuccess() {
		t.Fatalf("offline auth barrier missing after retained state: %v", authResult)
	}
	select {
	case <-authDone:
	case <-time.After(2 * time.Second):
		t.Fatal("authentication did not complete after control queue drained")
	}
	hub.mu.RLock()
	indexedAfterControlQueue := hub.userClients[bob.ID][offlineBob]
	hub.mu.RUnlock()
	if !indexedAfterControlQueue {
		t.Fatal("authenticated client was not published after control state")
	}

	// A malformed/badly bound v3 envelope gets only an error response and is
	// never inserted for the target device.
	invalidWire := makeSenderKeyEnvelopeV3(
		aliceMalloryConversation, 3, alice.IdentityKey, bob.SigningKey, mallory.IdentityKey,
	)
	sender.handleSenderKeyDist(ctx, 61, &pb.SenderKeyDistribution{
		ConversationId:    aliceMalloryConversation,
		SenderKeyMessage:  invalidWire,
		Generation:        3,
		TargetIdentityKey: mallory.IdentityKey,
	})
	rejected := receiveGatewayEnvelope(t, sender.send)
	if rejected.GetError() == nil || rejected.GetMessageAck() != nil {
		t.Fatalf("invalid distribution was ACKed: %v", rejected)
	}
	rows, err := h.DB.GetPendingSenderKeys(ctx, malloryDevice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("invalid distribution was stored: %+v", rows)
	}

	// Durable state cannot be rolled back by a stale but otherwise valid v3
	// envelope, and the stale request receives no ACK.
	staleWire := makeSenderKeyEnvelopeV3(
		aliceBobConversation, 6, alice.IdentityKey, alice.SigningKey, bob.IdentityKey,
	)
	sender.handleSenderKeyDist(ctx, 71, &pb.SenderKeyDistribution{
		ConversationId:    aliceBobConversation,
		SenderKeyMessage:  staleWire,
		Generation:        6,
		TargetIdentityKey: bob.IdentityKey,
	})
	stale := receiveGatewayEnvelope(t, sender.send)
	if stale.GetError() == nil || stale.GetError().GetCode() != 409 || stale.GetMessageAck() != nil {
		t.Fatalf("stale distribution response = %v, want 409 without ACK", stale)
	}
	rows, err = h.DB.GetPendingSenderKeys(ctx, bobDevice1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Generation != 7 {
		t.Fatalf("stale distribution rewound durable state: %+v", rows)
	}
}

func randomDeviceKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return key
}

func receiveGatewayEnvelope(t *testing.T, ch <-chan []byte) *pb.Envelope {
	t.Helper()
	select {
	case data := <-ch:
		var env pb.Envelope
		if err := proto.Unmarshal(data, &env); err != nil {
			t.Fatalf("decode gateway envelope: %v", err)
		}
		return &env
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for gateway envelope")
		return nil
	}
}
