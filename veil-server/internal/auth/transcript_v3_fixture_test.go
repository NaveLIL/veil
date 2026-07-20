package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const (
	transportAuthFixtureV1ReviewedSHA256 = "c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc"
	transportAuthFixtureV1MaxBytes       = 64 * 1024
)

type transportAuthFixtureV1 struct {
	SchemaVersion uint32                         `json:"schema_version"`
	SyntheticOnly bool                           `json:"synthetic_only"`
	Note          string                         `json:"note"`
	Inputs        transportAuthFixtureV1Inputs   `json:"inputs"`
	Expected      transportAuthFixtureV1Expected `json:"expected"`
}

type transportAuthFixtureV1Inputs struct {
	CanonicalOrigin              string `json:"canonical_origin"`
	OtherCanonicalOrigin         string `json:"other_canonical_origin"`
	ServerEphemeralHex           string `json:"server_ephemeral_hex"`
	AccountIdentityKeyHex        string `json:"account_identity_key_hex"`
	AccountSigningSeedHex        string `json:"account_signing_seed_hex"`
	AccountSigningKeyHex         string `json:"account_signing_key_hex"`
	DeviceSigningSeedHex         string `json:"device_signing_seed_hex"`
	DeviceSigningKeyHex          string `json:"device_signing_key_hex"`
	DeviceIDHex                  string `json:"device_id_hex"`
	VerifiedBindingCommitmentHex string `json:"verified_binding_commitment_hex"`
	NodeAccessPassHex            string `json:"node_access_pass_hex"`
	RegistrationIntent           uint8  `json:"registration_intent"`
	AccountSharedSecretHex       string `json:"account_shared_secret_hex"`
	DeviceSharedSecretHex        string `json:"device_shared_secret_hex"`
	RESTUserID                   string `json:"rest_user_id"`
	RESTMethod                   string `json:"rest_method"`
	RESTRequestTarget            string `json:"rest_request_target"`
	RESTTimestampMS              uint64 `json:"rest_timestamp_ms"`
	RESTNonceHex                 string `json:"rest_nonce_hex"`
	RESTBodyUTF8                 string `json:"rest_body_utf8"`
}

type transportAuthFixtureV1Expected struct {
	NodeAccessPassCommitmentHex string `json:"node_access_pass_commitment_hex"`
	WSContextHex                string `json:"ws_context_hex"`
	WSContextSHA256Hex          string `json:"ws_context_sha256_hex"`
	WSAccountProofMessageHex    string `json:"ws_account_proof_message_hex"`
	WSAccountProofSignatureHex  string `json:"ws_account_proof_signature_hex"`
	WSDeviceProofMessageHex     string `json:"ws_device_proof_message_hex"`
	WSDeviceProofSignatureHex   string `json:"ws_device_proof_signature_hex"`
	RESTBodySHA256Hex           string `json:"rest_body_sha256_hex"`
	RESTSigningMessageHex       string `json:"rest_signing_message_hex"`
	RESTSigningMessageSHA256Hex string `json:"rest_signing_message_sha256_hex"`
	RESTSignatureHex            string `json:"rest_signature_hex"`
}

func TestTransportAuthV1SharedFixtureWSContract(t *testing.T) {
	fixture := loadTransportAuthFixtureV1(t)
	if fixture.SchemaVersion != 1 {
		t.Fatalf("schema_version = %d, want 1", fixture.SchemaVersion)
	}
	if !fixture.SyntheticOnly {
		t.Fatal("shared transport-auth fixture is not marked synthetic_only")
	}

	serverEphemeral := fixtureHex32(t, "inputs.server_ephemeral_hex", fixture.Inputs.ServerEphemeralHex)
	accountIdentityKey := fixtureHex32(t, "inputs.account_identity_key_hex", fixture.Inputs.AccountIdentityKeyHex)
	accountSigningSeed := fixtureHexBytes(t, "inputs.account_signing_seed_hex", fixture.Inputs.AccountSigningSeedHex, ed25519.SeedSize)
	accountSigningKey := fixtureHex32(t, "inputs.account_signing_key_hex", fixture.Inputs.AccountSigningKeyHex)
	deviceSigningSeed := fixtureHexBytes(t, "inputs.device_signing_seed_hex", fixture.Inputs.DeviceSigningSeedHex, ed25519.SeedSize)
	deviceSigningKey := fixtureHex32(t, "inputs.device_signing_key_hex", fixture.Inputs.DeviceSigningKeyHex)
	deviceID := fixtureHex16(t, "inputs.device_id_hex", fixture.Inputs.DeviceIDHex)
	bindingCommitment := fixtureHex32(t, "inputs.verified_binding_commitment_hex", fixture.Inputs.VerifiedBindingCommitmentHex)
	nodeAccessPass := fixtureHexBytes(t, "inputs.node_access_pass_hex", fixture.Inputs.NodeAccessPassHex, NodeAccessPassSizeV1)
	accountShared := fixtureHexBytes(t, "inputs.account_shared_secret_hex", fixture.Inputs.AccountSharedSecretHex, WSAuthV3SharedSecretSize)
	deviceShared := fixtureHexBytes(t, "inputs.device_shared_secret_hex", fixture.Inputs.DeviceSharedSecretHex, WSAuthV3SharedSecretSize)

	// Decode every other fixed-width cryptographic field even though this test
	// exercises only the WS half of the shared WS/REST fixture.
	_ = fixtureHexBytes(t, "inputs.rest_nonce_hex", fixture.Inputs.RESTNonceHex, 32)
	_ = fixtureHexBytes(t, "expected.rest_body_sha256_hex", fixture.Expected.RESTBodySHA256Hex, sha256.Size)
	_ = fixtureHexBytes(t, "expected.rest_signing_message_sha256_hex", fixture.Expected.RESTSigningMessageSHA256Hex, sha256.Size)
	_ = fixtureHexBytes(t, "expected.rest_signature_hex", fixture.Expected.RESTSignatureHex, ed25519.SignatureSize)
	_ = fixtureHexBytes(t, "expected.rest_signing_message_hex", fixture.Expected.RESTSigningMessageHex, -1)

	accountPrivate := ed25519.NewKeyFromSeed(accountSigningSeed)
	derivedAccountPublic := accountPrivate.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedAccountPublic, accountSigningKey[:]) {
		t.Fatalf("derived account signing key = %x, want %x", derivedAccountPublic, accountSigningKey)
	}
	devicePrivate := ed25519.NewKeyFromSeed(deviceSigningSeed)
	derivedDevicePublic := devicePrivate.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedDevicePublic, deviceSigningKey[:]) {
		t.Fatalf("derived device signing key = %x, want %x", derivedDevicePublic, deviceSigningKey)
	}

	passCommitment, err := NodeAccessPassCommitmentV1(fixture.Inputs.CanonicalOrigin, nodeAccessPass)
	if err != nil {
		t.Fatalf("rebuild Node Access Pass commitment: %v", err)
	}
	wantPassCommitment := fixtureHexBytes(
		t, "expected.node_access_pass_commitment_hex",
		fixture.Expected.NodeAccessPassCommitmentHex, sha256.Size,
	)
	requireTransportAuthFixtureBytes(t, "Node Access Pass commitment", passCommitment[:], wantPassCommitment)

	contextInput := WSAuthContextV3Input{
		CanonicalOrigin:           fixture.Inputs.CanonicalOrigin,
		ServerEphemeral:           serverEphemeral,
		AccountIdentityKey:        accountIdentityKey,
		AccountSigningKey:         accountSigningKey,
		DeviceID:                  deviceID,
		VerifiedBindingCommitment: bindingCommitment,
		RegistrationIntent:        WSAuthRegistrationIntentV3(fixture.Inputs.RegistrationIntent),
		PassCommitment:            passCommitment,
	}
	context, err := WSAuthV3Context(contextInput)
	if err != nil {
		t.Fatalf("rebuild WS v3 context: %v", err)
	}
	wantContext := fixtureHexBytes(t, "expected.ws_context_hex", fixture.Expected.WSContextHex, len(context))
	requireTransportAuthFixtureBytes(t, "WS context", context, wantContext)
	contextSHA256 := sha256.Sum256(context)
	wantContextSHA256 := fixtureHexBytes(
		t, "expected.ws_context_sha256_hex", fixture.Expected.WSContextSHA256Hex, sha256.Size,
	)
	requireTransportAuthFixtureBytes(t, "WS context SHA-256", contextSHA256[:], wantContextSHA256)

	accountMessage, err := WSAuthV3AccountProofMessage(contextInput, accountShared)
	if err != nil {
		t.Fatalf("rebuild WS account proof message: %v", err)
	}
	wantAccountMessage := fixtureHexBytes(
		t, "expected.ws_account_proof_message_hex",
		fixture.Expected.WSAccountProofMessageHex, len(accountMessage),
	)
	requireTransportAuthFixtureBytes(t, "WS account proof message", accountMessage, wantAccountMessage)
	accountSignature := ed25519.Sign(accountPrivate, accountMessage)
	wantAccountSignature := fixtureHexBytes(
		t, "expected.ws_account_proof_signature_hex",
		fixture.Expected.WSAccountProofSignatureHex, ed25519.SignatureSize,
	)
	requireTransportAuthFixtureBytes(t, "WS account proof signature", accountSignature, wantAccountSignature)
	if !ed25519.Verify(derivedAccountPublic, accountMessage, accountSignature) {
		t.Fatal("rebuilt WS account proof signature did not verify")
	}

	deviceMessage, err := WSAuthV3DeviceProofMessage(contextInput, deviceShared, accountSignature)
	if err != nil {
		t.Fatalf("rebuild WS device proof message: %v", err)
	}
	wantDeviceMessage := fixtureHexBytes(
		t, "expected.ws_device_proof_message_hex",
		fixture.Expected.WSDeviceProofMessageHex, len(deviceMessage),
	)
	requireTransportAuthFixtureBytes(t, "WS device proof message", deviceMessage, wantDeviceMessage)
	deviceSignature := ed25519.Sign(devicePrivate, deviceMessage)
	wantDeviceSignature := fixtureHexBytes(
		t, "expected.ws_device_proof_signature_hex",
		fixture.Expected.WSDeviceProofSignatureHex, ed25519.SignatureSize,
	)
	requireTransportAuthFixtureBytes(t, "WS device proof signature", deviceSignature, wantDeviceSignature)
	if !ed25519.Verify(derivedDevicePublic, deviceMessage, deviceSignature) {
		t.Fatal("rebuilt WS device proof signature did not verify")
	}

	otherPassCommitment, err := NodeAccessPassCommitmentV1(
		fixture.Inputs.OtherCanonicalOrigin, nodeAccessPass,
	)
	if err != nil {
		t.Fatalf("rebuild other-origin Pass commitment: %v", err)
	}
	otherContextInput := contextInput
	otherContextInput.CanonicalOrigin = fixture.Inputs.OtherCanonicalOrigin
	otherContextInput.PassCommitment = otherPassCommitment
	otherContext, err := WSAuthV3Context(otherContextInput)
	if err != nil {
		t.Fatalf("rebuild other-origin context: %v", err)
	}
	if bytes.Equal(context, otherContext) {
		t.Fatal("changing the canonical origin did not change the WS context")
	}
	otherAccountMessage, err := WSAuthV3AccountProofMessage(otherContextInput, accountShared)
	if err != nil {
		t.Fatalf("rebuild other-origin account message: %v", err)
	}
	if ed25519.Verify(derivedAccountPublic, otherAccountMessage, accountSignature) {
		t.Fatal("original account proof verified for another canonical origin")
	}
	otherDeviceMessage, err := WSAuthV3DeviceProofMessage(otherContextInput, deviceShared, accountSignature)
	if err != nil {
		t.Fatalf("rebuild other-origin device message: %v", err)
	}
	if ed25519.Verify(derivedDevicePublic, otherDeviceMessage, deviceSignature) {
		t.Fatal("original device proof verified for another canonical origin")
	}

	accountWithDeviceDomain := substituteTransportAuthFixtureDomain(
		t, accountMessage, wsAuthAccountProofDomainV3, wsAuthDeviceProofDomainV3,
	)
	if ed25519.Verify(derivedAccountPublic, accountWithDeviceDomain, accountSignature) {
		t.Fatal("account proof verified after account/device domain substitution")
	}
	deviceWithAccountDomain := substituteTransportAuthFixtureDomain(
		t, deviceMessage, wsAuthDeviceProofDomainV3, wsAuthAccountProofDomainV3,
	)
	if ed25519.Verify(derivedDevicePublic, deviceWithAccountDomain, deviceSignature) {
		t.Fatal("device proof verified after device/account domain substitution")
	}
}

func loadTransportAuthFixtureV1(t *testing.T) transportAuthFixtureV1 {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve transport-auth fixture test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	fixtureDirectory := filepath.Join(repositoryRoot, "test-vectors", "transport-auth")
	fixtureBytes := readTransportAuthFixtureFileV1(t, filepath.Join(fixtureDirectory, "v1.json"))
	sumsBytes := readTransportAuthFixtureFileV1(t, filepath.Join(fixtureDirectory, "SHA256SUMS"))

	digest := sha256.Sum256(fixtureBytes)
	if got := hex.EncodeToString(digest[:]); got != transportAuthFixtureV1ReviewedSHA256 {
		t.Fatalf("transport-auth v1 fixture SHA-256 = %s, reviewed %s", got, transportAuthFixtureV1ReviewedSHA256)
	}
	wantSums := []byte(transportAuthFixtureV1ReviewedSHA256 + "  v1.json\n")
	if !bytes.Equal(sumsBytes, wantSums) {
		t.Fatalf("transport-auth SHA256SUMS is not the exact reviewed line: %q", sumsBytes)
	}

	trimmed := bytes.TrimSpace(fixtureBytes)
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		t.Fatal("transport-auth fixture must contain exactly one top-level JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(fixtureBytes))
	decoder.DisallowUnknownFields()
	var fixture transportAuthFixtureV1
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode strict transport-auth fixture: %v", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("transport-auth fixture has a trailing JSON value: %v", err)
	}
	return fixture
}

func readTransportAuthFixtureFileV1(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() > transportAuthFixtureV1MaxBytes {
		t.Fatalf("%s must be a regular file no larger than %d bytes", path, transportAuthFixtureV1MaxBytes)
	}
	contents, err := io.ReadAll(io.LimitReader(file, transportAuthFixtureV1MaxBytes+1))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(contents) == 0 || len(contents) > transportAuthFixtureV1MaxBytes {
		t.Fatalf("%s is empty or larger than %d bytes", path, transportAuthFixtureV1MaxBytes)
	}
	if bytes.ContainsRune(contents, '\r') {
		t.Fatalf("%s is not LF-only", path)
	}
	if contents[len(contents)-1] != '\n' || (len(contents) > 1 && contents[len(contents)-2] == '\n') {
		t.Fatalf("%s must end in exactly one LF", path)
	}
	return contents
}

func fixtureHexBytes(t *testing.T, field, value string, expectedBytes int) []byte {
	t.Helper()
	if value == "" || len(value)%2 != 0 || (expectedBytes >= 0 && len(value) != expectedBytes*2) {
		t.Fatalf("%s has invalid canonical hex width", field)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		t.Fatalf("%s is not canonical lowercase hex", field)
	}
	return decoded
}

func fixtureHex32(t *testing.T, field, value string) (output [32]byte) {
	t.Helper()
	copy(output[:], fixtureHexBytes(t, field, value, len(output)))
	return output
}

func fixtureHex16(t *testing.T, field, value string) (output [16]byte) {
	t.Helper()
	copy(output[:], fixtureHexBytes(t, field, value, len(output)))
	return output
}

func requireTransportAuthFixtureBytes(t *testing.T, field string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch:\n got %x\nwant %x", field, got, want)
	}
}

func substituteTransportAuthFixtureDomain(t *testing.T, message []byte, from, to string) []byte {
	t.Helper()
	if !bytes.HasPrefix(message, []byte(from)) {
		t.Fatalf("message does not begin with expected domain %q", from)
	}
	substituted := make([]byte, 0, len(message)-len(from)+len(to))
	substituted = append(substituted, to...)
	substituted = append(substituted, message[len(from):]...)
	return substituted
}
