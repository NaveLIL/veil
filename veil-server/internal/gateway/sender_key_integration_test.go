//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	integrationtest "github.com/NaveLIL/veil/veil-server/internal/integration"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/jackc/pgx/v5/pgconn"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/proto"
)

type gatewayBoundDevice struct {
	user           *integrationtest.User
	record         *db.Device
	identityPublic []byte
	signingPrivate ed25519.PrivateKey
	signingPublic  ed25519.PublicKey
	bindingVersion uint64
	bindingStatus  db.DeviceBindingStatus
	bindingCaps    uint64
}

func TestSenderKeyPerDeviceRoutingRestoreAndReceipts(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	alice := h.CreateUser("skdm-device-alice")
	bob := h.CreateUser("skdm-device-bob")
	charlie := h.CreateUser("skdm-device-charlie")

	aliceOne := createGatewayBoundDevice(t, h, alice, "alice-one")
	aliceTwo := createGatewayBoundDevice(t, h, alice, "alice-two")
	bobOne := createGatewayBoundDevice(t, h, bob, "bob-one")
	bobTwo := createGatewayBoundDevice(t, h, bob, "bob-two")
	charlieOne := createGatewayBoundDevice(t, h, charlie, "charlie-one")

	conversationID, err := h.DB.CreateGroup(ctx, "per-device-skdm", alice.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, conversationID, bob.ID, 0); err != nil {
		t.Fatal(err)
	}
	roster := requireReadyGatewayRoster(t, h.DB, conversationID)

	hub := &Hub{
		chatSvc:       h.Chat,
		clients:       make(map[*Client]bool),
		userClients:   make(map[string]map[*Client]bool),
		deviceClients: make(map[string]map[*Client]bool),
	}
	sender := gatewayClientForDevice(hub, aliceOne)
	senderSecond := gatewayClientForDevice(hub, aliceTwo)
	targetOne := gatewayClientForDevice(hub, bobOne)
	targetTwo := gatewayClientForDevice(hub, bobTwo)
	for _, client := range []*Client{sender, senderSecond, targetOne, targetTwo} {
		hub.indexClient(client)
	}

	// DMs remain exclusively Double Ratchet traffic. Fully bound devices and a
	// syntactically valid v3 envelope must not accidentally enable Sender Keys.
	dmID, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	dmDistribution, _ := gatewayDeviceDistribution(
		t, dmID, 1, roster, aliceOne, bobOne, 1,
	)
	sender.handleSenderKeyDist(ctx, 10, dmDistribution)
	requireGatewayError(t, receiveGatewayEnvelope(t, sender.send), 400)

	// Outer device routing and the recipient identity sealed into v3 are one
	// authenticated unit. A blob for Bob's second device cannot be relabelled
	// as a distribution for Bob's first device.
	wrongBlob := makeSenderKeyEnvelopeV3WithMarker(
		conversationID, 1, aliceOne.identityPublic,
		aliceOne.signingPrivate, bobTwo.identityPublic, 9,
	)
	wrongRoute, _ := gatewayDeviceDistribution(
		t, conversationID, 1, roster, aliceOne, bobOne, 9,
	)
	wrongRoute.SenderKeyMessage = wrongBlob
	sender.handleSenderKeyDist(ctx, 11, wrongRoute)
	requireGatewayError(t, receiveGatewayEnvelope(t, sender.send), 403)
	requireNoGatewayEnvelope(t, targetOne.send)
	requireNoGatewayEnvelope(t, targetTwo.send)

	distOne, wireOne := gatewayDeviceDistribution(
		t, conversationID, 1, roster, aliceOne, bobOne, 1,
	)
	// Proof fields and unknown protobuf fields arrive from an untrusted client.
	// The gateway must replace the former from its canonical directory and
	// discard the latter instead of reflecting them to a future client.
	distOne.SenderAccountIdentityKey = bytes.Repeat([]byte{0xe1}, 32)
	distOne.SenderAccountSigningKey = bytes.Repeat([]byte{0xe2}, 32)
	distOne.SenderDeviceIdentityKey = bytes.Repeat([]byte{0xe3}, 32)
	distOne.SenderDeviceSigningKey = bytes.Repeat([]byte{0xe4}, 32)
	distOne.SenderDeviceCapabilities = 0
	distOne.SenderDeviceBindingStatus = uint32(db.DeviceBindingRevoked)
	distOne.SenderAccountSignature = bytes.Repeat([]byte{0xe5}, ed25519.SignatureSize)
	// Valid protobuf unknown field 100 (length-delimited "bad").
	distOne.ProtoReflect().SetUnknown([]byte{0xa2, 0x06, 0x03, 'b', 'a', 'd'})
	sender.handleSenderKeyDist(ctx, 20, distOne)
	ackOne := receiveGatewayEnvelope(t, sender.send).GetMessageAck()
	requireSenderKeyAck(t, ackOne, 20, bobOne.record.DeviceKey, conversationID, 1, roster.Version, wireOne)
	forwardedOne := receiveGatewayEnvelope(t, targetOne.send).GetSenderKeyDist()
	if forwardedOne == nil || !bytes.Equal(forwardedOne.GetTargetDeviceId(), bobOne.record.DeviceKey) ||
		!bytes.Equal(forwardedOne.GetSenderKeyMessage(), wireOne) {
		t.Fatalf("wrong exact-device forward: %v", forwardedOne)
	}
	requireSenderBindingProof(t, forwardedOne, aliceOne)
	if unknown := forwardedOne.ProtoReflect().GetUnknown(); len(unknown) != 0 {
		t.Fatalf("live sender-key forward reflected untrusted unknown fields: %x", unknown)
	}
	requireNoGatewayEnvelope(t, targetTwo.send)

	distTwo, wireTwo := gatewayDeviceDistribution(
		t, conversationID, 1, roster, aliceOne, bobTwo, 2,
	)
	sender.handleSenderKeyDist(ctx, 21, distTwo)
	ackTwo := receiveGatewayEnvelope(t, sender.send).GetMessageAck()
	requireSenderKeyAck(t, ackTwo, 21, bobTwo.record.DeviceKey, conversationID, 1, roster.Version, wireTwo)
	forwardedTwo := receiveGatewayEnvelope(t, targetTwo.send).GetSenderKeyDist()
	if forwardedTwo == nil || !bytes.Equal(forwardedTwo.GetTargetDeviceId(), bobTwo.record.DeviceKey) ||
		!bytes.Equal(forwardedTwo.GetSenderKeyMessage(), wireTwo) || bytes.Equal(wireOne, wireTwo) {
		t.Fatalf("wrong second-device forward: %v", forwardedTwo)
	}
	requireSenderBindingProof(t, forwardedTwo, aliceOne)
	requireNoGatewayEnvelope(t, targetOne.send)

	for _, expectation := range []struct {
		device *gatewayBoundDevice
		wire   []byte
	}{
		{device: bobOne, wire: wireOne},
		{device: bobTwo, wire: wireTwo},
	} {
		rows, err := h.DB.GetPendingSenderKeys(ctx, expectation.device.record.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Generation != 1 ||
			!bytes.Equal(rows[0].EncryptedKey, expectation.wire) {
			t.Fatalf("pending exact-device rows for %s: %+v", expectation.device.record.DeviceName, rows)
		}
	}

	// A different authenticated envelope cannot replace a committed generation.
	conflict, _ := gatewayDeviceDistribution(
		t, conversationID, 1, roster, aliceOne, bobOne, 3,
	)
	sender.handleSenderKeyDist(ctx, 22, conflict)
	requireGatewayError(t, receiveGatewayEnvelope(t, sender.send), 409)

	// Group ciphertext fans out to every eligible device, including the
	// sender's other device, but never echoes to the source device itself.
	sender.handleSendMessage(ctx, 30, &pb.SendMessage{
		ConversationId:   conversationID,
		Ciphertext:       []byte("opaque-sender-key-ciphertext"),
		MsgType:          pb.MessageType_MESSAGE_TYPE_TEXT,
		RosterVersion:    roster.Version,
		RosterCommitment: append([]byte(nil), roster.Commitment[:]...),
	})
	messageAck := receiveGatewayEnvelope(t, sender.send)
	if messageAck.GetMessageAck() == nil || messageAck.GetMessageAck().GetRefSeq() != 30 {
		t.Fatalf("message ACK missing: %v", messageAck)
	}
	messageID := messageAck.GetMessageAck().GetMessageId()
	requireTargetedMessageEvent(t, receiveGatewayEnvelope(t, senderSecond.send), aliceOne, aliceTwo, roster)
	requireTargetedMessageEvent(t, receiveGatewayEnvelope(t, targetOne.send), aliceOne, bobOne, roster)
	requireTargetedMessageEvent(t, receiveGatewayEnvelope(t, targetTwo.send), aliceOne, bobTwo, roster)
	requireNoGatewayEnvelope(t, sender.send)

	storedMessages, err := h.DB.GetPendingMessages(ctx, conversationID, bob.ID, time.Time{}, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(storedMessages) != 1 || storedMessages[0].ID != messageID || storedMessages[0].SecurityContext == nil {
		t.Fatalf("persisted secure message = %+v", storedMessages)
	}
	storedSecurity := storedMessages[0].SecurityContext
	if storedSecurity.CryptoProfile != db.MessageCryptoProfileSenderKeyV5 ||
		storedSecurity.CryptoEra != db.MessageCryptoEraSenderKeyV5 ||
		storedSecurity.RosterVersion != roster.Version ||
		!bytes.Equal(storedSecurity.RosterCommitment, roster.Commitment[:]) ||
		!bytes.Equal(storedSecurity.SenderDeviceID, aliceOne.record.DeviceKey) ||
		storedSecurity.SenderBindingVersion != aliceOne.bindingVersion {
		t.Fatalf("persisted security context = %+v", storedSecurity)
	}
	status, raw, rest := h.Do(
		bob, http.MethodGet, "/v1/messages/"+conversationID+"?limit=10", nil,
	)
	if status != http.StatusOK {
		t.Fatalf("REST secure history status=%d body=%s", status, raw)
	}
	restMessages, ok := rest["messages"].([]any)
	if !ok || len(restMessages) != 1 {
		t.Fatalf("REST secure history = %v", rest)
	}
	restMessage, ok := restMessages[0].(map[string]any)
	if !ok || restMessage["crypto_profile"] != db.MessageCryptoProfileSenderKeyV5 ||
		restMessage["crypto_era"] != "1" ||
		restMessage["roster_version"] != fmt.Sprint(roster.Version) ||
		restMessage["sender_binding_version"] != fmt.Sprint(aliceOne.bindingVersion) ||
		restMessage["sender_device_id"] != fmt.Sprintf("%x", aliceOne.record.DeviceKey) ||
		restMessage["roster_commitment"] != fmt.Sprintf("%x", roster.Commitment[:]) {
		t.Fatalf("REST persisted security context = %v", restMessage)
	}

	// Until an exact device-routed edit contract exists, neither a legacy
	// session nor a session whose binding became revoked may replace Sender-Key
	// ciphertext and trigger account-wide edit fan-out.
	legacyEditor := &Client{
		hub: hub, send: make(chan []byte, 4), authenticated: true,
		userID: alice.ID, deviceID: aliceOne.record.ID,
	}
	revokedEditor := &Client{
		hub: hub, send: make(chan []byte, 4), authenticated: true,
		userID: alice.ID, deviceID: aliceOne.record.ID,
		deviceKey:       append([]byte(nil), aliceOne.record.DeviceKey...),
		perDeviceSecure: true, deviceBindingVersion: aliceOne.bindingVersion,
		deviceBindingStatus: db.DeviceBindingRevoked,
	}
	for index, editor := range []*Client{legacyEditor, revokedEditor} {
		editor.handleEditMessage(ctx, uint64(40+index), &pb.EditMessage{
			MessageId: messageID, ConversationId: conversationID,
			NewCiphertext: []byte("forbidden-replacement"),
		})
		requireGatewayError(t, receiveGatewayEnvelope(t, editor.send), 400)
	}
	afterRejectedEdit, err := h.DB.GetPendingMessages(ctx, conversationID, bob.ID, time.Time{}, "", 10)
	if err != nil || len(afterRejectedEdit) != 1 ||
		!bytes.Equal(afterRejectedEdit[0].Ciphertext, []byte("opaque-sender-key-ciphertext")) ||
		afterRejectedEdit[0].EditedAt != nil {
		t.Fatalf("rejected secure edit changed row: messages=%+v err=%v", afterRejectedEdit, err)
	}
	requireNoGatewayEnvelope(t, senderSecond.send)
	requireNoGatewayEnvelope(t, targetOne.send)
	requireNoGatewayEnvelope(t, targetTwo.send)

	// Keep a second unacknowledged generation. It must remain restorable after
	// both a roster-version change and removal of the original sender account.
	distOneGenTwo, wireOneGenTwo := gatewayDeviceDistribution(
		t, conversationID, 2, roster, aliceOne, bobOne, 4,
	)
	sender.handleSenderKeyDist(ctx, 31, distOneGenTwo)
	requireSenderKeyAck(
		t, receiveGatewayEnvelope(t, sender.send).GetMessageAck(), 31,
		bobOne.record.DeviceKey, conversationID, 2, roster.Version, wireOneGenTwo,
	)
	_ = receiveGatewayEnvelope(t, targetOne.send)

	stale, _ := gatewayDeviceDistribution(
		t, conversationID, 1, roster, aliceOne, bobOne, 1,
	)
	sender.handleSenderKeyDist(ctx, 32, stale)
	requireGatewayError(t, receiveGatewayEnvelope(t, sender.send), 409)

	if err := h.DB.AddGroupMember(ctx, conversationID, charlie.ID, 0); err != nil {
		t.Fatal(err)
	}
	changedRoster := requireReadyGatewayRoster(t, h.DB, conversationID)
	if changedRoster.Version <= roster.Version {
		t.Fatalf("roster did not advance: old=%d new=%d", roster.Version, changedRoster.Version)
	}
	if err := h.DB.RemoveGroupMember(ctx, conversationID, alice.ID); err != nil {
		t.Fatal(err)
	}
	_ = charlieOne // its active binding keeps the changed roster ready.

	restored, err := targetOne.buildPendingDeviceSenderKeyEnvelopes(ctx)
	if err != nil {
		t.Fatalf("restore after roster churn and owner removal: %v", err)
	}
	if len(restored) != 2 {
		t.Fatalf("restored generations = %d, want 2", len(restored))
	}
	for index, want := range []struct {
		generation uint32
		wire       []byte
	}{{1, wireOne}, {2, wireOneGenTwo}} {
		var envelope pb.Envelope
		if err := proto.Unmarshal(restored[index], &envelope); err != nil {
			t.Fatal(err)
		}
		got := envelope.GetSenderKeyDist()
		if got == nil || got.GetGeneration() != want.generation ||
			got.GetRosterVersion() != roster.Version ||
			!bytes.Equal(got.GetRosterCommitment(), roster.Commitment[:]) ||
			!bytes.Equal(got.GetSenderKeyMessage(), want.wire) ||
			!bytes.Equal(got.GetSenderDeviceId(), aliceOne.record.DeviceKey) {
			t.Fatalf("restored historical distribution %d: %v", index, got)
		}
		requireSenderBindingProof(t, got, aliceOne)
	}

	commitmentOne := sha256.Sum256(wireOne)
	wrongReceipt := &pb.SenderKeyReceipt{
		ConversationId:     conversationID,
		OwnerDeviceId:      append([]byte(nil), aliceOne.record.DeviceKey...),
		TargetDeviceId:     append([]byte(nil), bobOne.record.DeviceKey...),
		Generation:         1,
		RosterVersion:      roster.Version,
		EnvelopeCommitment: commitmentOne[:],
	}
	targetTwo.handleSenderKeyReceipt(ctx, 40, wrongReceipt)
	requireGatewayError(t, receiveGatewayEnvelope(t, targetTwo.send), 400)

	targetOne.handleSenderKeyReceipt(ctx, 41, wrongReceipt)
	receiptAck := receiveGatewayEnvelope(t, targetOne.send).GetMessageAck()
	requireSenderKeyAck(t, receiptAck, 41, bobOne.record.DeviceKey, conversationID, 1, roster.Version, wireOne)
	rowsOne, err := h.DB.GetPendingSenderKeys(ctx, bobOne.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	rowsTwo, err := h.DB.GetPendingSenderKeys(ctx, bobTwo.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsOne) != 1 || rowsOne[0].Generation != 2 || len(rowsTwo) != 1 {
		t.Fatalf("exact receipt collected wrong rows: bob1=%+v bob2=%+v", rowsOne, rowsTwo)
	}

	// Revocation before offline delivery prunes only rows addressed to the
	// revoked target. The stream head remains as its rollback barrier.
	storeGatewayBindingVersion(t, h, bobTwo, 2, db.RequiredChannelCapabilities, db.DeviceBindingRevoked)
	rowsTwo, err = h.DB.GetPendingSenderKeys(ctx, bobTwo.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsTwo) != 0 {
		t.Fatalf("revoked target retained distributions: %+v", rowsTwo)
	}
	pendingRevoked, err := targetTwo.buildPendingDeviceSenderKeyEnvelopes(ctx)
	if err != nil || len(pendingRevoked) != 0 {
		t.Fatalf("revoked target restore = %d, err=%v", len(pendingRevoked), err)
	}
	var retainedHead int64
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, aliceOne.record.ID, bobTwo.record.ID,
	).Scan(&retainedHead); err != nil || retainedHead != 1 {
		t.Fatalf("revoked stream head = %d, err=%v", retainedHead, err)
	}

	// A committed target membership loss collects old history immediately.
	// Re-adding the target before any resolve/login must not resurrect it;
	// unlike owner removal above, this is a future-only admission boundary.
	if err := h.DB.RemoveGroupMember(ctx, conversationID, bob.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, conversationID, bob.ID, 0); err != nil {
		t.Fatal(err)
	}
	rowsOne, err = h.DB.GetPendingSenderKeys(ctx, bobOne.record.ID)
	if err != nil || len(rowsOne) != 0 {
		t.Fatalf("target remove/re-add resurrected historical rows=%+v err=%v", rowsOne, err)
	}
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, aliceOne.record.ID, bobOne.record.ID,
	).Scan(&retainedHead); err != nil || retainedHead != 2 {
		t.Fatalf("target membership loss head = %d, err=%v, want 2", retainedHead, err)
	}
}

func TestPendingSenderKeyRestoreIsolatesBadConversations(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("restore-isolation-owner")
	target := h.CreateUser("restore-isolation-target")
	legacy := h.CreateUser("restore-isolation-legacy")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "restore-owner-device")
	targetDevice := createGatewayBoundDevice(t, h, target, "restore-target-device")

	storeDistribution := func(name string, marker byte) (string, *db.ConversationDeviceRoster, []byte) {
		t.Helper()
		conversationID, err := h.DB.CreateGroup(ctx, name, owner.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
			t.Fatal(err)
		}
		roster := requireReadyGatewayRoster(t, h.DB, conversationID)
		distribution, wire := gatewayDeviceDistribution(
			t, conversationID, 1, roster, ownerDevice, targetDevice, marker,
		)
		if err := h.DB.StoreDeviceSenderKey(
			ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
			distribution.SenderKeyMessage, distribution.Generation,
			roster.Version, roster.Commitment[:],
			ownerDevice.bindingVersion, targetDevice.bindingVersion,
		); err != nil {
			t.Fatalf("store %s retained distribution: %v", name, err)
		}
		return conversationID, roster, wire
	}

	healthyID, _, healthyWire := storeDistribution("restore-healthy", 0x31)
	notReadyID, oldNotReadyRoster, _ := storeDistribution("restore-not-ready", 0x32)
	expiredID, expiredRoster, _ := storeDistribution("restore-expired", 0x33)
	oversizedID, _, _ := storeDistribution("restore-oversized", 0x34)

	backlogsBeforeMutation, err := h.DB.ListPendingSenderKeyConversations(ctx, targetDevice.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	listedNotReady := false
	for _, backlog := range backlogsBeforeMutation {
		if backlog.ConversationID == notReadyID && !backlog.Expired && !backlog.LegacyOrPartial {
			listedNotReady = true
		}
	}
	if !listedNotReady {
		t.Fatalf("ready conversation missing from pre-mutation restore metadata: %+v", backlogsBeforeMutation)
	}
	if err := h.DB.AddGroupMember(ctx, notReadyID, legacy.ID, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.CreateDevice(ctx, legacy.ID, randomDeviceKey(t), "legacy-unbound"); err != nil {
		t.Fatal(err)
	}
	if restore, err := h.DB.LoadPendingSenderKeyConversation(
		ctx, targetDevice.record.ID, targetDevice.record.DeviceKey,
		targetDevice.bindingVersion, notReadyID,
		db.MaxPendingSenderKeyRowsPerTarget, db.MaxPendingSenderKeyBytesPerTarget,
	); !errors.Is(err, db.ErrSenderKeyConversationUnavailable) || restore != nil {
		t.Fatalf("mutation between metadata/load restore=%v err=%v, want isolated unavailable", restore, err)
	}
	notReadyRoster, err := h.DB.ResolveConversationDeviceRoster(
		ctx, notReadyID, db.RequiredChannelCapabilities,
	)
	if err != nil || notReadyRoster.Ready || notReadyRoster.Reason != "legacy_unbound_device" {
		t.Fatalf("legacy conversation roster=%+v err=%v, want not-ready legacy", notReadyRoster, err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE sender_keys
		 SET created_at = now() - interval '2 seconds',
		     expires_at = now() - interval '1 second'
		 WHERE conversation_id = $1::uuid
		   AND target_device_id = $2::uuid`, expiredID, targetDevice.record.ID,
	); err != nil {
		t.Fatal(err)
	}
	oversized := bytes.Repeat([]byte{0x7d}, db.MaxPendingSenderKeyBytesPerTarget+1)
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE sender_keys
		 SET encrypted_key = $3::bytea,
		     envelope_commitment = digest($3::bytea, 'sha256')
		 WHERE conversation_id = $1::uuid
		   AND target_device_id = $2::uuid`,
		oversizedID, targetDevice.record.ID, oversized,
	); err != nil {
		t.Fatal(err)
	}

	hub := &Hub{chatSvc: h.Chat}
	targetClient := gatewayClientForDevice(hub, targetDevice)
	restored, err := targetClient.pendingSenderKeyEnvelopes(ctx)
	if err != nil {
		t.Fatalf("pre-auth restore failed globally: %v", err)
	}
	if len(restored) != 1 {
		t.Fatalf("isolated restore envelopes=%d, want only healthy conversation", len(restored))
	}
	var envelope pb.Envelope
	if err := proto.Unmarshal(restored[0], &envelope); err != nil {
		t.Fatal(err)
	}
	got := envelope.GetSenderKeyDist()
	if got == nil || got.GetConversationId() != healthyID ||
		!bytes.Equal(got.GetSenderKeyMessage(), healthyWire) {
		t.Fatalf("healthy restore envelope=%v", got)
	}
	requireSenderBindingProof(t, got, ownerDevice)

	// Isolation is not an implicit receipt or cleanup. Both unavailable
	// conversations retain their exact rows and remain fail-closed for writes.
	for _, conversationID := range []string{notReadyID, expiredID, oversizedID} {
		var pending int
		if err := h.DB.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM sender_keys
			 WHERE conversation_id = $1::uuid
			   AND target_device_id = $2::uuid`,
			conversationID, targetDevice.record.ID,
		).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("isolated conversation %s pending=%d err=%v, want 1", conversationID, pending, err)
		}
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, notReadyID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("must-not-write-not-ready"), 2,
		oldNotReadyRoster.Version, oldNotReadyRoster.Commitment[:],
		ownerDevice.bindingVersion, targetDevice.bindingVersion,
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("not-ready conversation write=%v, want ErrSenderKeyRosterChanged", err)
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, expiredID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("must-not-write-expired"), 2,
		expiredRoster.Version, expiredRoster.Commitment[:],
		ownerDevice.bindingVersion, targetDevice.bindingVersion,
	); !errors.Is(err, db.ErrSenderKeyRetentionExpired) &&
		!errors.Is(err, db.ErrSenderKeyTargetBacklogFull) {
		t.Fatalf("expired conversation write=%v, want fail-closed retention/backlog error", err)
	}

	// Sender-Key isolation must not affect ordinary Double-Ratchet DM sync.
	dmID, _, err := h.DB.FindOrCreateDM(ctx, owner.ID, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO messages (conversation_id, sender_id, ciphertext)
		 VALUES ($1::uuid, $2::uuid, $3)`, dmID, owner.ID, []byte("healthy-dm-ciphertext"),
	); err != nil {
		t.Fatal(err)
	}
	dmMessages, err := h.DB.GetPendingMessages(ctx, dmID, target.ID, time.Time{}, "", 10)
	if err != nil || len(dmMessages) != 1 ||
		!bytes.Equal(dmMessages[0].Ciphertext, []byte("healthy-dm-ciphertext")) {
		t.Fatalf("DM sync after isolated restore messages=%v err=%v", dmMessages, err)
	}
}

func TestSenderKeyRetentionDeadlineAndBound(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("skdm-retention-owner")
	target := h.CreateUser("skdm-retention-target")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "retention-owner")
	targetDevice := createGatewayBoundDevice(t, h, target, "retention-target")
	conversationID, err := h.DB.CreateGroup(ctx, "skdm-retention", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	roster := requireReadyGatewayRoster(t, h.DB, conversationID)

	blobs := make(map[uint32][]byte, db.MaxPendingSenderKeyGenerationsPerStream+2)
	for generation := uint32(1); generation <= db.MaxPendingSenderKeyGenerationsPerStream; generation++ {
		blob := []byte(fmt.Sprintf("retained-skdm-%03d", generation))
		blobs[generation] = blob
		if err := h.DB.StoreDeviceSenderKey(
			ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
			blob, generation, roster.Version, roster.Commitment[:], 1, 1,
		); err != nil {
			t.Fatalf("store generation %d: %v", generation, err)
		}
	}

	next := uint32(db.MaxPendingSenderKeyGenerationsPerStream + 1)
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("over-cap"), next, roster.Version, roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRetentionFull) {
		t.Fatalf("over-cap admission = %v, want ErrSenderKeyRetentionFull", err)
	}

	// Expiry never silently deletes history. It closes admission until the
	// exact target receipt clears the old generation.
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE sender_keys
		 SET created_at = now() - INTERVAL '2 hours',
		     expires_at = now() - INTERVAL '1 hour'
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid
		   AND target_device_id = $3::uuid AND generation = 1`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("expired-gate"), next, roster.Version, roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRetentionExpired) {
		t.Fatalf("expired admission = %v, want ErrSenderKeyRetentionExpired", err)
	}
	expiredRestore, err := h.DB.GetPendingSenderKeys(ctx, targetDevice.record.ID)
	if !errors.Is(err, db.ErrSenderKeyRetentionExpired) || len(expiredRestore) != 0 {
		t.Fatalf("expired restore = %d rows, err=%v; want fail-closed empty restore", len(expiredRestore), err)
	}

	// Equal-generation replay remains idempotent even while an older row is
	// expired; it neither advances the head nor duplicates retained state.
	last := uint32(db.MaxPendingSenderKeyGenerationsPerStream)
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		blobs[last], last, roster.Version, roster.Commitment[:], 1, 1,
	); err != nil {
		t.Fatalf("idempotent head replay: %v", err)
	}

	firstCommitment := sha256.Sum256(blobs[1])
	if err := h.DB.AcknowledgeSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		1, roster.Version, firstCommitment[:],
	); err != nil {
		t.Fatalf("collect expired generation by exact receipt: %v", err)
	}
	blobs[next] = []byte("after-exact-receipt")
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		blobs[next], next, roster.Version, roster.Commitment[:], 1, 1,
	); err != nil {
		t.Fatalf("admission after exact receipt: %v", err)
	}

	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE sender_keys
		 SET created_at = now() - INTERVAL '2 hours',
		     expires_at = now() - INTERVAL '1 hour'
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid
		   AND target_device_id = $3::uuid AND generation = 2`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("still-expired"), next+1, roster.Version, roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRetentionExpired) {
		t.Fatalf("second expired admission = %v", err)
	}
	var head int64
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	).Scan(&head); err != nil || head != int64(next) {
		t.Fatalf("failed admission advanced head to %d, err=%v", head, err)
	}

	secondCommitment := sha256.Sum256(blobs[2])
	if err := h.DB.AcknowledgeSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		2, roster.Version, secondCommitment[:],
	); err != nil {
		t.Fatal(err)
	}
	blobs[next+1] = []byte("after-second-receipt")
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		blobs[next+1], next+1, roster.Version, roster.Commitment[:], 1, 1,
	); err != nil {
		t.Fatalf("admission after expired receipt: %v", err)
	}

	storeGatewayBindingVersion(t, h, targetDevice, 2, db.RequiredChannelCapabilities, db.DeviceBindingExcluded)
	rows, err := h.DB.GetPendingSenderKeys(ctx, targetDevice.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("excluded device retained %d rows", len(rows))
	}
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	).Scan(&head); err != nil || head != int64(next+1) {
		t.Fatalf("pruning removed/changed rollback head %d, err=%v", head, err)
	}
	// Simulate the original TOCTOU ordering: the gateway resolved the old
	// roster, then the target became ineligible, then durable admission ran
	// with that stale proof. The database-level snapshot guard must reject it
	// and must not recreate a row after revocation pruning.
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("stale-after-exclusion"), next+2,
		roster.Version, roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("stale post-exclusion durable admission = %v, want ErrSenderKeyRosterChanged", err)
	}
	rows, err = h.DB.GetPendingSenderKeys(ctx, targetDevice.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Fatalf("stale durable admission recreated pruned rows: %+v", rows)
	}
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	).Scan(&head); err != nil || head != int64(next+1) {
		t.Fatalf("stale durable admission changed rollback head %d, err=%v", head, err)
	}

	// The successful migration cutover is one-way: both the schema and runtime
	// reject any attempt to reintroduce account-routed state. Rollback heads are
	// preserved as the monotonic barrier.
	legacyBlob := []byte("legacy-account-routed-skdm")
	legacyCommitment := sha256.Sum256(legacyBlob)
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO sender_keys (
		   conversation_id, owner_device_id, target_device_id,
		   encrypted_key, generation, envelope_commitment
		 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 777, $5)`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
		legacyBlob, legacyCommitment[:],
	); err == nil {
		t.Fatal("post-cutover database accepted a legacy sender-key row")
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`SELECT veil_assert_sender_key_device_routing_cutover()`); err != nil {
		t.Fatalf("device-routing cutover invariant failed after rejected legacy writes: %v", err)
	}
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT max_generation FROM sender_key_heads
		 WHERE conversation_id = $1::uuid AND owner_device_id = $2::uuid AND target_device_id = $3::uuid`,
		conversationID, ownerDevice.record.ID, targetDevice.record.ID,
	).Scan(&head); err != nil || head != int64(next+1) {
		t.Fatalf("rejected legacy writes removed/changed rollback head %d, err=%v", head, err)
	}
}

func TestSenderKeyTargetWideBacklogBound(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("skdm-global-cap-owner")
	target := h.CreateUser("skdm-global-cap-target")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "global-cap-owner")
	targetDevice := createGatewayBoundDevice(t, h, target, "global-cap-target")

	const streams = 64
	const generationsPerStream = 16
	if streams*generationsPerStream*4096 != db.MaxPendingSenderKeyBytesPerTarget {
		t.Fatal("global backlog fixture no longer matches configured byte cap")
	}
	for stream := 0; stream < streams; stream++ {
		conversationID, err := h.DB.CreateGroup(ctx, fmt.Sprintf("global-cap-%02d", stream), owner.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := h.DB.Pool.Exec(ctx,
			`INSERT INTO sender_keys (
			   conversation_id, owner_device_id, target_device_id,
			   encrypted_key, generation, envelope_commitment,
			   roster_version, roster_commitment,
			   owner_binding_version, target_binding_version
			 )
			 SELECT $1::uuid, $2::uuid, $3::uuid,
			        repeat('x', 4096)::bytea, generation,
			        digest(repeat('x', 4096)::bytea, 'sha256'),
			        1, $4, 1, 1
			 FROM generate_series(1, $5) AS generation`,
			conversationID, ownerDevice.record.ID, targetDevice.record.ID,
			make([]byte, 32), generationsPerStream,
		); err != nil {
			t.Fatalf("seed target backlog stream %d: %v", stream, err)
		}
	}

	admissionConversation, err := h.DB.CreateGroup(ctx, "global-cap-admission", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, admissionConversation, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	roster := requireReadyGatewayRoster(t, h.DB, admissionConversation)
	if err := h.DB.StoreDeviceSenderKey(
		ctx, admissionConversation, ownerDevice.record.ID, targetDevice.record.ID,
		[]byte("one-byte-over-global-cap"), 1,
		roster.Version, roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyTargetBacklogFull) {
		t.Fatalf("target-wide admission = %v, want ErrSenderKeyTargetBacklogFull", err)
	}
	var admitted int
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM sender_keys WHERE conversation_id = $1::uuid`,
		admissionConversation,
	).Scan(&admitted); err != nil || admitted != 0 {
		t.Fatalf("target-wide rejected rows=%d err=%v, want 0", admitted, err)
	}

	rows, err := h.DB.GetPendingSenderKeys(ctx, targetDevice.record.ID)
	if err != nil || len(rows) != streams*generationsPerStream {
		t.Fatalf("bounded restore at exact cap rows=%d err=%v", len(rows), err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO sender_keys (
		   conversation_id, owner_device_id, target_device_id,
		   encrypted_key, generation, envelope_commitment,
		   roster_version, roster_commitment,
		   owner_binding_version, target_binding_version
		 ) VALUES (
		   $1::uuid, $2::uuid, $3::uuid, '\x01', 1, digest('\x01'::bytea, 'sha256'),
		   $4, $5, 1, 1
		 )`,
		admissionConversation, ownerDevice.record.ID, targetDevice.record.ID,
		int64(roster.Version), roster.Commitment[:],
	); err != nil {
		t.Fatal(err)
	}
	rows, err = h.DB.GetPendingSenderKeys(ctx, targetDevice.record.ID)
	if !errors.Is(err, db.ErrSenderKeyRestoreBacklogExceeded) || len(rows) != 0 {
		t.Fatalf("over-bound restore rows=%d err=%v", len(rows), err)
	}
}

func TestSenderKeyTargetWideBacklogConcurrentAdmission(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("skdm-concurrent-cap-owner")
	target := h.CreateUser("skdm-concurrent-cap-target")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "concurrent-cap-owner")
	targetDevice := createGatewayBoundDevice(t, h, target, "concurrent-cap-target")

	seedConversation, err := h.DB.CreateGroup(ctx, "concurrent-cap-seed", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, seedConversation, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	seedRoster := requireReadyGatewayRoster(t, h.DB, seedConversation)
	seed := bytes.Repeat([]byte{0x7c}, db.MaxPendingSenderKeyBytesPerTarget-1)
	seedCommitment := sha256.Sum256(seed)
	if _, err := h.DB.Pool.Exec(ctx,
		`INSERT INTO sender_keys (
		   conversation_id, owner_device_id, target_device_id,
		   encrypted_key, generation, envelope_commitment,
		   roster_version, roster_commitment,
		   owner_binding_version, target_binding_version
		 ) VALUES ($1::uuid, $2::uuid, $3::uuid, $4, 1, $5, $6, $7, 1, 1)`,
		seedConversation, ownerDevice.record.ID, targetDevice.record.ID,
		seed, seedCommitment[:], int64(seedRoster.Version), seedRoster.Commitment[:],
	); err != nil {
		t.Fatal(err)
	}

	type admission struct {
		conversationID string
		roster         *db.ConversationDeviceRoster
	}
	admissions := make([]admission, 0, 2)
	for index := range 2 {
		conversationID, err := h.DB.CreateGroup(ctx, fmt.Sprintf("concurrent-cap-%d", index), owner.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
			t.Fatal(err)
		}
		admissions = append(admissions, admission{
			conversationID: conversationID,
			roster:         requireReadyGatewayRoster(t, h.DB, conversationID),
		})
	}

	start := make(chan struct{})
	results := make(chan error, len(admissions))
	for _, candidate := range admissions {
		candidate := candidate
		go func() {
			<-start
			results <- h.DB.StoreDeviceSenderKey(
				ctx, candidate.conversationID,
				ownerDevice.record.ID, targetDevice.record.ID,
				[]byte{0x01}, 1, candidate.roster.Version,
				candidate.roster.Commitment[:], 1, 1,
			)
		}()
	}
	close(start)
	var admitted, rejected int
	for range admissions {
		err := <-results
		switch {
		case err == nil:
			admitted++
		case errors.Is(err, db.ErrSenderKeyTargetBacklogFull):
			rejected++
		default:
			t.Fatalf("unexpected concurrent target-cap result: %v", err)
		}
	}
	if admitted != 1 || rejected != 1 {
		t.Fatalf("concurrent target-cap admitted=%d rejected=%d, want 1/1", admitted, rejected)
	}
	var totalBytes int64
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT COALESCE(SUM(octet_length(encrypted_key)), 0)
		 FROM sender_keys WHERE target_device_id = $1::uuid`,
		targetDevice.record.ID,
	).Scan(&totalBytes); err != nil {
		t.Fatal(err)
	}
	if totalBytes != db.MaxPendingSenderKeyBytesPerTarget {
		t.Fatalf("concurrent target backlog bytes=%d, want %d", totalBytes, db.MaxPendingSenderKeyBytesPerTarget)
	}
}

func TestSecureChannelBlocksLegacyRoster(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("legacy-roster-owner")
	target := h.CreateUser("legacy-roster-target")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "owner-secure")
	_ = createGatewayBoundDevice(t, h, target, "target-secure")
	conversationID, err := h.DB.CreateGroup(ctx, "legacy-roster", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	ready := requireReadyGatewayRoster(t, h.DB, conversationID)
	if _, err := h.DB.CreateDevice(ctx, target.ID, randomDeviceKey(t), "legacy-unbound"); err != nil {
		t.Fatal(err)
	}

	hub := &Hub{
		chatSvc:       h.Chat,
		userClients:   make(map[string]map[*Client]bool),
		deviceClients: make(map[string]map[*Client]bool),
	}
	sender := gatewayClientForDevice(hub, ownerDevice)
	sender.handleSendMessage(ctx, 70, &pb.SendMessage{
		ConversationId:   conversationID,
		Ciphertext:       []byte("must-not-store"),
		RosterVersion:    ready.Version,
		RosterCommitment: append([]byte(nil), ready.Commitment[:]...),
	})
	requireGatewayError(t, receiveGatewayEnvelope(t, sender.send), 409)
}

func TestConversationRosterRevisionLinearization(t *testing.T) {
	h := integrationtest.New(t)
	ctx := context.Background()
	owner := h.CreateUser("roster-lock-owner")
	target := h.CreateUser("roster-lock-target")
	ownerDevice := createGatewayBoundDevice(t, h, owner, "roster-owner-device")
	targetOne := createGatewayBoundDevice(t, h, target, "roster-target-one")

	conversationID, err := h.DB.CreateGroup(ctx, "roster-linearization", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddGroupMember(ctx, conversationID, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	var heads int
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM conversation_device_rosters WHERE conversation_id = $1::uuid`,
		conversationID,
	).Scan(&heads); err != nil || heads != 0 {
		t.Fatalf("unexpected pre-resolve head count %d, err=%v", heads, err)
	}

	// Two first resolvers race on an absent materialized head. The revision row
	// serializes them, so both observe the same canonical version-1 snapshot.
	type rosterResult struct {
		roster *db.ConversationDeviceRoster
		err    error
	}
	start := make(chan struct{})
	results := make(chan rosterResult, 2)
	for range 2 {
		go func() {
			<-start
			roster, err := h.DB.ResolveConversationDeviceRoster(
				ctx, conversationID, db.RequiredChannelCapabilities,
			)
			results <- rosterResult{roster: roster, err: err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	for index, result := range []rosterResult{first, second} {
		if result.err != nil || result.roster == nil || !result.roster.Ready || result.roster.Version != 1 {
			t.Fatalf("concurrent first resolve %d: roster=%+v err=%v", index, result.roster, result.err)
		}
	}
	if first.roster.Commitment != second.roster.Commitment {
		t.Fatal("concurrent first resolves committed different rosters")
	}
	requireCleanRosterHead(t, h.DB, conversationID, 1)

	// Adding another device dirties the exact roster before its binding is even
	// installed. Installing the binding dirties it again. An old proof cannot be
	// admitted until a resolver publishes the recomputed commitment.
	targetTwo := createGatewayBoundDevice(t, h, target, "roster-target-two")
	requireDirtyRosterHead(t, h.DB, conversationID)
	staleMessage := &db.Message{
		ConversationID: conversationID,
		SenderID:       owner.ID,
		Ciphertext:     []byte("must-not-persist-under-stale-roster"),
		SecurityContext: &db.MessageSecurityContext{
			CryptoProfile:          db.MessageCryptoProfileSenderKeyV5,
			CryptoEra:              db.MessageCryptoEraSenderKeyV5,
			RosterVersion:          first.roster.Version,
			RosterCommitment:       append([]byte(nil), first.roster.Commitment[:]...),
			SenderDeviceID:         append([]byte(nil), ownerDevice.record.DeviceKey...),
			SenderBindingVersion:   ownerDevice.bindingVersion,
			SenderDeviceDatabaseID: ownerDevice.record.ID,
		},
	}
	if err := h.DB.StoreMessage(ctx, staleMessage); !errors.Is(err, db.ErrMessageRosterChanged) {
		t.Fatalf("stale secure message admission = %v, want ErrMessageRosterChanged", err)
	}
	var staleMessages int
	if err := h.DB.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM messages WHERE conversation_id = $1::uuid`, conversationID,
	).Scan(&staleMessages); err != nil || staleMessages != 0 {
		t.Fatalf("stale secure message rows=%d err=%v, want 0", staleMessages, err)
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetOne.record.ID,
		[]byte("old-proof-after-device-add"), 1,
		first.roster.Version, first.roster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("device-add stale proof = %v, want ErrSenderKeyRosterChanged", err)
	}
	withSecondDevice := requireReadyGatewayRoster(t, h.DB, conversationID)
	if withSecondDevice.Version <= first.roster.Version {
		t.Fatalf("device-add resolve did not advance: %d", withSecondDevice.Version)
	}
	requireCleanRosterHead(t, h.DB, conversationID, withSecondDevice.Version)

	preRevokeBlob := []byte("durable-before-revoke-publication")
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetTwo.record.ID,
		preRevokeBlob, 1, withSecondDevice.Version, withSecondDevice.Commitment[:], 1, 1,
	); err != nil {
		t.Fatalf("pre-revoke durable admission: %v", err)
	}
	storeGatewayBindingVersion(t, h, targetTwo, 2, db.RequiredChannelCapabilities, db.DeviceBindingRevoked)
	requireDirtyRosterHead(t, h.DB, conversationID)
	publishedAfterRevoke := false
	if err := h.DB.WithCurrentSenderKeyRoute(
		ctx, conversationID, ownerDevice.record.ID, targetTwo.record.ID,
		withSecondDevice.Version, withSecondDevice.Commitment[:], 1, 1,
		func() error {
			publishedAfterRevoke = true
			return nil
		},
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("post-revoke publication authorization = %v, want ErrSenderKeyRosterChanged", err)
	}
	if publishedAfterRevoke {
		t.Fatal("post-revoke publication callback ran")
	}
	preRevokeCommitment := sha256.Sum256(preRevokeBlob)
	if err := h.DB.DiscardDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetTwo.record.ID,
		1, withSecondDevice.Version, preRevokeCommitment[:],
	); err != nil {
		t.Fatal(err)
	}
	rowsAfterRevoke, err := h.DB.GetPendingSenderKeys(ctx, targetTwo.record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rowsAfterRevoke) != 0 {
		t.Fatalf("revoked-before-publication rows: %+v", rowsAfterRevoke)
	}
	if err := h.DB.StoreDeviceSenderKey(
		ctx, conversationID, ownerDevice.record.ID, targetOne.record.ID,
		[]byte("old-proof-after-revoke"), 1,
		withSecondDevice.Version, withSecondDevice.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("device-revoke stale proof = %v, want ErrSenderKeyRosterChanged", err)
	}
	afterRevoke := requireReadyGatewayRoster(t, h.DB, conversationID)
	if afterRevoke.Version <= withSecondDevice.Version {
		t.Fatalf("device-revoke resolve did not advance: %d", afterRevoke.Version)
	}

	// Direct key-table replacement is not a rotation protocol. Migration 019
	// rejects it even for operators/future maintenance code, preserving both
	// the materialized roster and every retained historical proof.
	replacementIdentity := make([]byte, 32)
	if _, err := rand.Read(replacementIdentity); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE device_crypto_keys SET device_identity_key = $2
		 WHERE device_id = $1::uuid`,
		targetOne.record.ID, replacementIdentity,
	); err == nil {
		t.Fatal("migration 019 accepted direct device identity replacement")
	} else {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "23514" {
			t.Fatalf("direct device identity replacement error=%v, want SQLSTATE 23514", err)
		}
	}
	requireCleanRosterHead(t, h.DB, conversationID, afterRevoke.Version)
	afterKeyChange := requireReadyGatewayRoster(t, h.DB, conversationID)
	if afterKeyChange.Version != afterRevoke.Version || afterKeyChange.Commitment != afterRevoke.Commitment {
		t.Fatalf("rejected key replacement changed roster: before=%+v after=%+v", afterRevoke, afterKeyChange)
	}

	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE conversations SET conv_type = 0 WHERE id = $1::uuid`, conversationID,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Pool.Exec(ctx,
		`UPDATE conversations SET conv_type = 1 WHERE id = $1::uuid`, conversationID,
	); err != nil {
		t.Fatal(err)
	}
	requireDirtyRosterHead(t, h.DB, conversationID)
	afterTypeChange := requireReadyGatewayRoster(t, h.DB, conversationID)
	if afterTypeChange.Version <= afterKeyChange.Version {
		t.Fatalf("conversation-type resolve did not advance: %d", afterTypeChange.Version)
	}

	// Server role and overwrite mutations use the same revision lock as device
	// changes. This prevents a channel SKDM from slipping between an ACL commit
	// and publication of the new directory commitment.
	server, err := h.DB.CreateServer(ctx, "roster-lock-server", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.DB.AddServerMember(ctx, server.ID, target.ID); err != nil {
		t.Fatal(err)
	}
	channels, err := h.DB.GetServerChannels(ctx, server.ID)
	if err != nil || len(channels) == 0 || channels[0].ConversationID == nil {
		t.Fatalf("server channel unavailable: channels=%+v err=%v", channels, err)
	}
	channel := channels[0]
	channelConversationID := *channel.ConversationID
	if err := h.DB.AddGroupMember(ctx, channelConversationID, target.ID, 0); err != nil {
		t.Fatal(err)
	}
	channelRoster := requireReadyGatewayRoster(t, h.DB, channelConversationID)
	role, err := h.DB.CreateRole(
		ctx, server.ID, "reader", db.ChannelReadPermissions|db.PermSendMessages, nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	requireDirtyRosterHead(t, h.DB, channelConversationID)
	channelRoster = requireReadyGatewayRoster(t, h.DB, channelConversationID)
	if err := h.DB.AssignRole(ctx, server.ID, target.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	requireDirtyRosterHead(t, h.DB, channelConversationID)
	channelRoster = requireReadyGatewayRoster(t, h.DB, channelConversationID)
	if err := h.DB.UpsertChannelOverwrite(ctx, db.ChannelOverwrite{
		ChannelID: channel.ID, TargetID: target.ID,
		TargetType: db.ChannelOverwriteUser, Deny: db.PermViewChannel,
	}); err != nil {
		t.Fatal(err)
	}
	requireDirtyRosterHead(t, h.DB, channelConversationID)
	if err := h.DB.StoreDeviceSenderKey(
		ctx, channelConversationID, ownerDevice.record.ID, targetOne.record.ID,
		[]byte("old-proof-after-overwrite"), 1,
		channelRoster.Version, channelRoster.Commitment[:], 1, 1,
	); !errors.Is(err, db.ErrSenderKeyRosterChanged) {
		t.Fatalf("overwrite stale proof = %v, want ErrSenderKeyRosterChanged", err)
	}

	// Parent deletion may cascade through members and roster state in either
	// internal order. Dirty triggers must skip a conversation already being
	// deleted instead of trying to recreate an FK-protected revision row.
	deletedConversation, err := h.DB.CreateGroup(ctx, "roster-delete-cascade", owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	_ = requireReadyGatewayRoster(t, h.DB, deletedConversation)
	if _, err := h.DB.Pool.Exec(ctx,
		`DELETE FROM conversations WHERE id = $1::uuid`, deletedConversation,
	); err != nil {
		t.Fatalf("conversation cascade tripped roster trigger: %v", err)
	}
}

func requireDirtyRosterHead(t *testing.T, database *db.DB, conversationID string) {
	t.Helper()
	var dirty bool
	var mutationRevision, resolvedRevision int64
	if err := database.Pool.QueryRow(context.Background(),
		`SELECT head.dirty, revision.mutation_revision, head.resolved_mutation_revision
		 FROM conversation_device_rosters head
		 JOIN conversation_roster_revisions revision USING (conversation_id)
		 WHERE head.conversation_id = $1::uuid`,
		conversationID,
	).Scan(&dirty, &mutationRevision, &resolvedRevision); err != nil {
		t.Fatal(err)
	}
	if !dirty || mutationRevision <= resolvedRevision {
		t.Fatalf("roster head is not dirty: dirty=%v mutation=%d resolved=%d", dirty, mutationRevision, resolvedRevision)
	}
}

func requireCleanRosterHead(t *testing.T, database *db.DB, conversationID string, version uint64) {
	t.Helper()
	var dirty bool
	var storedVersion, mutationRevision, resolvedRevision int64
	if err := database.Pool.QueryRow(context.Background(),
		`SELECT head.dirty, head.roster_version,
		        revision.mutation_revision, head.resolved_mutation_revision
		 FROM conversation_device_rosters head
		 JOIN conversation_roster_revisions revision USING (conversation_id)
		 WHERE head.conversation_id = $1::uuid`,
		conversationID,
	).Scan(&dirty, &storedVersion, &mutationRevision, &resolvedRevision); err != nil {
		t.Fatal(err)
	}
	if dirty || storedVersion != int64(version) || mutationRevision != resolvedRevision {
		t.Fatalf(
			"roster head is not clean: dirty=%v version=%d/%d mutation=%d resolved=%d",
			dirty, storedVersion, version, mutationRevision, resolvedRevision,
		)
	}
}

func createGatewayBoundDevice(t *testing.T, h *integrationtest.Harness, user *integrationtest.User, name string) *gatewayBoundDevice {
	t.Helper()
	identityPrivate := make([]byte, 32)
	if _, err := rand.Read(identityPrivate); err != nil {
		t.Fatal(err)
	}
	identityPublic, err := curve25519.X25519(identityPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	record, err := h.DB.CreateDevice(context.Background(), user.ID, randomDeviceKey(t), name)
	if err != nil {
		t.Fatal(err)
	}
	device := &gatewayBoundDevice{
		user:           user,
		record:         record,
		identityPublic: identityPublic,
		signingPrivate: signingPrivate,
		signingPublic:  signingPublic,
	}
	storeGatewayBindingVersion(t, h, device, 1, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	return device
}

func storeGatewayBindingVersion(t *testing.T, h *integrationtest.Harness, device *gatewayBoundDevice, version, capabilities uint64, status db.DeviceBindingStatus) {
	t.Helper()
	input := &auth.DeviceBindingInput{
		DeviceKey:         append([]byte(nil), device.record.DeviceKey...),
		DeviceIdentityKey: append([]byte(nil), device.identityPublic...),
		DeviceSigningKey:  append([]byte(nil), device.signingPublic...),
		Version:           version,
		Capabilities:      capabilities,
		Status:            status,
	}
	message, err := auth.DeviceBindingSigningMessage(
		device.user.IdentityKey, device.user.SigningPublic, input,
	)
	if err != nil {
		t.Fatal(err)
	}
	input.AccountSignature = ed25519.Sign(device.user.SigningKey, message)
	commitment := sha256.Sum256(message)
	if _, err := h.DB.StoreDeviceBinding(context.Background(), &db.DeviceBinding{
		DeviceID:          device.record.ID,
		UserID:            device.user.ID,
		DeviceKey:         append([]byte(nil), device.record.DeviceKey...),
		DeviceIdentityKey: append([]byte(nil), device.identityPublic...),
		DeviceSigningKey:  append([]byte(nil), device.signingPublic...),
		Version:           version,
		Capabilities:      capabilities,
		Status:            status,
		AccountSignature:  append([]byte(nil), input.AccountSignature...),
		Commitment:        commitment[:],
	}); err != nil {
		t.Fatal(err)
	}
	device.bindingVersion = version
	device.bindingStatus = status
	device.bindingCaps = capabilities
}

func gatewayClientForDevice(hub *Hub, device *gatewayBoundDevice) *Client {
	return &Client{
		hub:                  hub,
		send:                 make(chan []byte, 32),
		authenticated:        true,
		userID:               device.user.ID,
		deviceID:             device.record.ID,
		deviceKey:            append([]byte(nil), device.record.DeviceKey...),
		identityKey:          append([]byte(nil), device.user.IdentityKey...),
		perDeviceSecure:      device.bindingStatus == db.DeviceBindingActive && device.bindingCaps&db.RequiredChannelCapabilities == db.RequiredChannelCapabilities,
		deviceBindingVersion: device.bindingVersion,
		deviceBindingStatus:  device.bindingStatus,
	}
}

func requireReadyGatewayRoster(t *testing.T, database *db.DB, conversationID string) *db.ConversationDeviceRoster {
	t.Helper()
	roster, err := database.ResolveConversationDeviceRoster(
		context.Background(), conversationID, db.RequiredChannelCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !roster.Ready {
		t.Fatalf("roster is not ready: %s", roster.Reason)
	}
	return roster
}

func gatewayDeviceDistribution(t *testing.T, conversationID string, generation uint32, roster *db.ConversationDeviceRoster, source, target *gatewayBoundDevice, marker byte) (*pb.SenderKeyDistribution, []byte) {
	t.Helper()
	wire := makeSenderKeyEnvelopeV3WithMarker(
		conversationID, generation, source.identityPublic,
		source.signingPrivate, target.identityPublic, marker,
	)
	return &pb.SenderKeyDistribution{
		ConversationId:          conversationID,
		SenderKeyMessage:        wire,
		Generation:              generation,
		TargetIdentityKey:       append([]byte(nil), target.user.IdentityKey...),
		TargetDeviceId:          append([]byte(nil), target.record.DeviceKey...),
		TargetDeviceIdentityKey: append([]byte(nil), target.identityPublic...),
		SenderDeviceId:          append([]byte(nil), source.record.DeviceKey...),
		RosterVersion:           roster.Version,
		RosterCommitment:        append([]byte(nil), roster.Commitment[:]...),
		SenderBindingVersion:    source.bindingVersion,
		TargetBindingVersion:    target.bindingVersion,
	}, wire
}

func requireSenderBindingProof(t *testing.T, distribution *pb.SenderKeyDistribution, source *gatewayBoundDevice) {
	t.Helper()
	if distribution == nil || source == nil ||
		!bytes.Equal(distribution.GetSenderAccountIdentityKey(), source.user.IdentityKey) ||
		!bytes.Equal(distribution.GetSenderAccountSigningKey(), source.user.SigningPublic) ||
		!bytes.Equal(distribution.GetSenderDeviceId(), source.record.DeviceKey) ||
		!bytes.Equal(distribution.GetSenderDeviceIdentityKey(), source.identityPublic) ||
		!bytes.Equal(distribution.GetSenderDeviceSigningKey(), source.signingPublic) ||
		distribution.GetSenderBindingVersion() != source.bindingVersion ||
		distribution.GetSenderDeviceCapabilities() != source.bindingCaps ||
		distribution.GetSenderDeviceBindingStatus() != uint32(db.DeviceBindingActive) ||
		len(distribution.GetSenderAccountSignature()) != ed25519.SignatureSize {
		t.Fatalf("incomplete or mismatched historical sender binding proof: %v", distribution)
	}
	proof := &auth.DeviceBindingInput{
		DeviceKey:         append([]byte(nil), distribution.GetSenderDeviceId()...),
		DeviceIdentityKey: append([]byte(nil), distribution.GetSenderDeviceIdentityKey()...),
		DeviceSigningKey:  append([]byte(nil), distribution.GetSenderDeviceSigningKey()...),
		Version:           distribution.GetSenderBindingVersion(),
		Capabilities:      distribution.GetSenderDeviceCapabilities(),
		Status:            db.DeviceBindingStatus(distribution.GetSenderDeviceBindingStatus()),
	}
	message, err := auth.DeviceBindingSigningMessage(
		distribution.GetSenderAccountIdentityKey(),
		distribution.GetSenderAccountSigningKey(), proof,
	)
	if err != nil || !ed25519.Verify(
		ed25519.PublicKey(distribution.GetSenderAccountSigningKey()),
		message, distribution.GetSenderAccountSignature(),
	) {
		t.Fatalf("invalid historical sender account signature: err=%v", err)
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
		var envelope pb.Envelope
		if err := proto.Unmarshal(data, &envelope); err != nil {
			t.Fatalf("decode gateway envelope: %v", err)
		}
		return &envelope
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for gateway envelope")
		return nil
	}
}

func requireNoGatewayEnvelope(t *testing.T, ch <-chan []byte) {
	t.Helper()
	select {
	case data := <-ch:
		var envelope pb.Envelope
		_ = proto.Unmarshal(data, &envelope)
		t.Fatalf("unexpected gateway envelope: %v", &envelope)
	case <-time.After(25 * time.Millisecond):
	}
}

func requireGatewayError(t *testing.T, envelope *pb.Envelope, code uint32) {
	t.Helper()
	if envelope.GetError() == nil || envelope.GetError().GetCode() != code || envelope.GetMessageAck() != nil {
		t.Fatalf("gateway response = %v, want error %d without ACK", envelope, code)
	}
}

func requireSenderKeyAck(t *testing.T, ack *pb.MessageAck, seq uint64, targetDeviceID []byte, conversationID string, generation uint32, rosterVersion uint64, wire []byte) {
	t.Helper()
	commitment := sha256.Sum256(wire)
	if ack == nil || ack.GetRefSeq() != seq ||
		!bytes.Equal(ack.GetTargetDeviceId(), targetDeviceID) ||
		ack.GetConversationId() != conversationID ||
		ack.GetSenderKeyGeneration() != generation ||
		ack.GetRosterVersion() != rosterVersion ||
		!bytes.Equal(ack.GetEnvelopeCommitment(), commitment[:]) {
		t.Fatalf("sender-key ACK = %v", ack)
	}
}

func requireTargetedMessageEvent(t *testing.T, envelope *pb.Envelope, source, target *gatewayBoundDevice, roster *db.ConversationDeviceRoster) {
	t.Helper()
	event := envelope.GetMessageEvent()
	if event == nil || event.GetEventType() != pb.MessageEvent_NEW ||
		!bytes.Equal(event.GetSenderDeviceId(), source.record.DeviceKey) ||
		!bytes.Equal(event.GetTargetDeviceId(), target.record.DeviceKey) ||
		event.GetRosterVersion() != roster.Version ||
		!bytes.Equal(event.GetRosterCommitment(), roster.Commitment[:]) ||
		event.GetCryptoProfile() != db.MessageCryptoProfileSenderKeyV5 ||
		event.GetCryptoEra() != db.MessageCryptoEraSenderKeyV5 ||
		event.GetSenderBindingVersion() != source.bindingVersion {
		t.Fatalf("targeted message event = %v", event)
	}
}
