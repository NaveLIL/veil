//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"golang.org/x/crypto/curve25519"
)

type integrationDeviceKeys struct {
	identityPrivate []byte
	identityPublic  []byte
	signingPrivate  ed25519.PrivateKey
	signingPublic   ed25519.PublicKey
}

func newIntegrationDeviceKeys(t *testing.T) integrationDeviceKeys {
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
	return integrationDeviceKeys{
		identityPrivate: identityPrivate,
		identityPublic:  identityPublic,
		signingPrivate:  signingPrivate,
		signingPublic:   signingPublic,
	}
}

func signedDeviceBinding(t *testing.T, user *User, deviceKey []byte, keys integrationDeviceKeys, version, capabilities uint64, status db.DeviceBindingStatus) (*auth.DeviceBindingInput, map[string]any) {
	t.Helper()
	binding := &auth.DeviceBindingInput{
		DeviceKey:         append([]byte(nil), deviceKey...),
		DeviceIdentityKey: append([]byte(nil), keys.identityPublic...),
		DeviceSigningKey:  append([]byte(nil), keys.signingPublic...),
		Version:           version,
		Capabilities:      capabilities,
		Status:            status,
	}
	message, err := auth.DeviceBindingSigningMessage(user.IdentityKey, user.SigningPublic, binding)
	if err != nil {
		t.Fatal(err)
	}
	binding.AccountSignature = ed25519.Sign(user.SigningKey, message)
	return binding, map[string]any{
		"device_identity_key": base64.StdEncoding.EncodeToString(binding.DeviceIdentityKey),
		"device_signing_key":  base64.StdEncoding.EncodeToString(binding.DeviceSigningKey),
		"version":             strconv.FormatUint(binding.Version, 10),
		"capabilities":        strconv.FormatUint(binding.Capabilities, 10),
		"status":              binding.Status,
		"account_signature":   base64.StdEncoding.EncodeToString(binding.AccountSignature),
	}
}

func requireDirectory(t *testing.T, h *Harness, user *User, conversationID string, wantVersion uint64, wantReady bool) map[string]any {
	t.Helper()
	status, raw, directory := h.Do(user, http.MethodGet,
		"/v1/conversations/"+conversationID+"/device-directory", nil,
	)
	if status != http.StatusOK {
		t.Fatalf("device directory: status=%d body=%s", status, raw)
	}
	gotVersion, err := strconv.ParseUint(directory["roster_version"].(string), 10, 64)
	if err != nil {
		t.Fatalf("invalid roster version: %v", directory["roster_version"])
	}
	if got := gotVersion; got != wantVersion {
		t.Fatalf("roster version = %d, want %d (%v)", got, wantVersion, directory)
	}
	if got, ok := directory["ready"].(bool); !ok || got != wantReady {
		t.Fatalf("roster ready = %v, want %v (%v)", directory["ready"], wantReady, directory)
	}
	if got, _ := directory["roster_commitment"].(string); len(got) != 64 {
		t.Fatalf("roster commitment must be 32-byte hex, got %q", got)
	}
	gotCapabilities, err := strconv.ParseUint(directory["required_capabilities"].(string), 10, 64)
	if err != nil {
		t.Fatalf("invalid required capabilities: %v", directory["required_capabilities"])
	}
	if got := gotCapabilities; got != db.RequiredChannelCapabilities {
		t.Fatalf("required capabilities = %d, want %d", got, db.RequiredChannelCapabilities)
	}
	return directory
}

func putDeviceBinding(t *testing.T, h *Harness, user *User, deviceKey []byte, payload map[string]any, wantStatus int) map[string]any {
	t.Helper()
	status, raw, body := h.Do(user, http.MethodPut,
		"/v1/device-bindings/"+hex.EncodeToString(deviceKey), payload,
	)
	if status != wantStatus {
		t.Fatalf("put binding: status=%d want=%d body=%s", status, wantStatus, raw)
	}
	return body
}

// TestDeviceDirectoryLifecycle verifies that the signed REST directory is
// rollback resistant, exposes legacy devices as ineligible, changes its
// monotonic version only with its exact commitment, and treats revocation as
// terminal. It intentionally uses one container for the full state machine.
func TestDeviceDirectoryLifecycle(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("directory-alice")
	bob := h.CreateUser("directory-bob")
	mallory := h.CreateUser("directory-mallory")
	aliceDeviceKey := bytes.Repeat([]byte{0xa1}, 16)
	bobDeviceKey := bytes.Repeat([]byte{0xb2}, 16)
	aliceKeys := newIntegrationDeviceKeys(t)
	bobKeys := newIntegrationDeviceKeys(t)
	if _, err := h.DB.CreateDevice(context.Background(), alice.ID, aliceDeviceKey, "alice-bound-device"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.CreateDevice(context.Background(), bob.ID, bobDeviceKey, "bob-bound-device"); err != nil {
		t.Fatal(err)
	}

	status, raw, conversation := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": bob.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("create directory DM: status=%d body=%s", status, raw)
	}
	conversationID := conversation["conversation_id"].(string)
	directoryPath := "/v1/conversations/" + conversationID + "/device-directory"

	if status, _ := h.DoUnsigned(http.MethodGet, directoryPath, nil); status != http.StatusBadRequest {
		t.Fatalf("unsigned directory status = %d, want 400", status)
	}
	if status, _, _ := h.Do(mallory, http.MethodGet, directoryPath, nil); status != http.StatusForbidden {
		t.Fatalf("non-member directory status = %d, want 403", status)
	}

	legacy := requireDirectory(t, h, alice, conversationID, 1, false)
	for _, field := range []string{
		"membership_conversation_kind",
		"membership_bootstrap_owner_id",
		"membership_bootstrap_owner_signing_key",
	} {
		if _, present := legacy[field]; present {
			t.Fatalf("Direct directory unexpectedly exposed %s", field)
		}
	}
	if reason, _ := legacy["reason"].(string); reason != "legacy_unbound_device" {
		t.Fatalf("legacy directory reason = %q", reason)
	}
	legacyDevices := legacy["devices"].([]any)
	if len(legacyDevices) != 2 {
		t.Fatalf("legacy device count = %d, want 2", len(legacyDevices))
	}
	for _, rawDevice := range legacyDevices {
		device := rawDevice.(map[string]any)
		if got := db.DeviceBindingStatus(device["status"].(float64)); got != db.DeviceLegacyUnbound {
			t.Fatalf("legacy status = %d, want %d (%v)", got, db.DeviceLegacyUnbound, device)
		}
		if eligible, _ := device["eligible"].(bool); eligible {
			t.Fatalf("legacy device unexpectedly eligible: %v", device)
		}
		if _, present := device["binding"]; present {
			t.Fatalf("legacy device must not synthesize a signed binding: %v", device)
		}
	}

	_, aliceV1 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 1, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	if status, _, _ := h.Do(mallory, http.MethodPut,
		"/v1/device-bindings/"+hex.EncodeToString(aliceDeviceKey), aliceV1,
	); status != http.StatusForbidden {
		t.Fatalf("foreign binding management status = %d, want 403", status)
	}
	tamperedV1 := make(map[string]any, len(aliceV1))
	for key, value := range aliceV1 {
		tamperedV1[key] = value
	}
	tamperedSignature, err := base64.StdEncoding.DecodeString(tamperedV1["account_signature"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tamperedSignature[0] ^= 0x80
	tamperedV1["account_signature"] = base64.StdEncoding.EncodeToString(tamperedSignature)
	putDeviceBinding(t, h, alice, aliceDeviceKey, tamperedV1, http.StatusBadRequest)
	requireDirectory(t, h, alice, conversationID, 1, false)

	storedAlice := putDeviceBinding(t, h, alice, aliceDeviceKey, aliceV1, http.StatusOK)
	if storedAlice["device_identity_key"] != aliceV1["device_identity_key"] ||
		storedAlice["device_signing_key"] != aliceV1["device_signing_key"] ||
		storedAlice["account_signature"] != aliceV1["account_signature"] {
		t.Fatalf("binding API did not return the exact signed binding: %v", storedAlice)
	}
	requireDirectory(t, h, alice, conversationID, 2, false)

	_, bobV1 := signedDeviceBinding(t, bob, bobDeviceKey, bobKeys, 1, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	putDeviceBinding(t, h, bob, bobDeviceKey, bobV1, http.StatusOK)
	ready := requireDirectory(t, h, alice, conversationID, 3, true)
	readyCommitment := ready["roster_commitment"]
	unchanged := requireDirectory(t, h, alice, conversationID, 3, true)
	if unchanged["roster_commitment"] != readyCommitment {
		t.Fatalf("unchanged directory commitment moved: %v -> %v", readyCommitment, unchanged["roster_commitment"])
	}

	// Same version with different signed fields is a conflict, not an
	// idempotent overwrite.
	_, aliceV1Conflict := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 1, db.DeviceCapabilitySenderKeyV5, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, aliceV1Conflict, http.StatusConflict)
	requireDirectory(t, h, alice, conversationID, 3, true)

	// A capability regression is explicit and creates a new roster version.
	_, aliceV2 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 2, db.DeviceCapabilitySenderKeyV5, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, aliceV2, http.StatusOK)
	capabilityBlocked := requireDirectory(t, h, alice, conversationID, 4, false)
	if reason, _ := capabilityBlocked["reason"].(string); reason != "active_device_missing_required_capabilities" {
		t.Fatalf("capability block reason = %q", reason)
	}

	// Old versions cannot roll the head back, even when the old payload and
	// signature are byte-for-byte valid.
	putDeviceBinding(t, h, alice, aliceDeviceKey, aliceV1, http.StatusConflict)

	// Neither a skipped version nor an account-signed key replacement can
	// mutate the immutable device identity.
	_, gapV4 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 4, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, gapV4, http.StatusConflict)
	replacementKeys := newIntegrationDeviceKeys(t)
	_, replacementV3 := signedDeviceBinding(t, alice, aliceDeviceKey, replacementKeys, 3, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, replacementV3, http.StatusConflict)
	requireDirectory(t, h, alice, conversationID, 4, false)

	// EXCLUDED is reversible only by the next explicit account-signed version.
	_, excludedV3 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 3, db.RequiredChannelCapabilities, db.DeviceBindingExcluded)
	putDeviceBinding(t, h, alice, aliceDeviceKey, excludedV3, http.StatusOK)
	requireDirectory(t, h, alice, conversationID, 5, false)
	_, reactivatedV4 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 4, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, reactivatedV4, http.StatusOK)
	requireDirectory(t, h, alice, conversationID, 6, true)

	// REVOKED is terminal: a later, correctly signed ACTIVE version is still
	// rejected and cannot change the roster head.
	_, revokedV5 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 5, db.RequiredChannelCapabilities, db.DeviceBindingRevoked)
	putDeviceBinding(t, h, alice, aliceDeviceKey, revokedV5, http.StatusOK)
	requireDirectory(t, h, alice, conversationID, 7, false)
	_, forbiddenV6 := signedDeviceBinding(t, alice, aliceDeviceKey, aliceKeys, 6, db.RequiredChannelCapabilities, db.DeviceBindingActive)
	putDeviceBinding(t, h, alice, aliceDeviceKey, forbiddenV6, http.StatusConflict)
	requireDirectory(t, h, alice, conversationID, 7, false)
}
