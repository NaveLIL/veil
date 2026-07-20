package authmw

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
	transportAuthFixtureMaxBytes = 64 * 1024
	transportAuthFixtureSHA256   = "c90f7aac7619d178e06c0ac0d7aab6084511ceffb505b8fcf7058ba6812ad9bc"
)

type transportAuthFixtureV1 struct {
	SchemaVersion int    `json:"schema_version"`
	SyntheticOnly bool   `json:"synthetic_only"`
	Note          string `json:"note"`
	Inputs        struct {
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
	} `json:"inputs"`
	Expected struct {
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
	} `json:"expected"`
}

func TestRESTAuthV2SharedImmutableFixture(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve REST auth v2 fixture test source path")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", "..", ".."))
	fixtureDirectory := filepath.Join(repositoryRoot, "test-vectors", "transport-auth")
	fixturePath := filepath.Join(fixtureDirectory, "v1.json")
	manifestPath := filepath.Join(fixtureDirectory, "SHA256SUMS")

	fixtureBytes := readBoundedTransportAuthFixtureFile(t, fixturePath)
	requireSingleFinalLFTransportAuthFixture(t, "v1.json", fixtureBytes)
	fixtureDigest := sha256.Sum256(fixtureBytes)
	if got := hex.EncodeToString(fixtureDigest[:]); got != transportAuthFixtureSHA256 {
		t.Fatalf("transport auth fixture SHA-256 = %s, want reviewed %s", got, transportAuthFixtureSHA256)
	}

	manifestBytes := readBoundedTransportAuthFixtureFile(t, manifestPath)
	requireSingleFinalLFTransportAuthFixture(t, "SHA256SUMS", manifestBytes)
	expectedManifest := transportAuthFixtureSHA256 + "  v1.json\n"
	if string(manifestBytes) != expectedManifest {
		t.Fatalf("transport auth SHA256SUMS is not the exact reviewed line: %q", manifestBytes)
	}

	var fixture transportAuthFixtureV1
	decoder := json.NewDecoder(bytes.NewReader(fixtureBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatalf("decode strict transport auth fixture: %v", err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("transport auth fixture contains trailing JSON data: %v", err)
	}
	if fixture.SchemaVersion != 1 {
		t.Fatalf("transport auth fixture schema_version = %d, want 1", fixture.SchemaVersion)
	}
	if !fixture.SyntheticOnly {
		t.Fatal("transport auth fixture is not marked synthetic_only")
	}

	accountSeed := decodeCanonicalLowerHexTransportAuthFixture(
		t, "inputs.account_signing_seed_hex", fixture.Inputs.AccountSigningSeedHex, ed25519.SeedSize,
	)
	accountPublicKey := decodeCanonicalLowerHexTransportAuthFixture(
		t, "inputs.account_signing_key_hex", fixture.Inputs.AccountSigningKeyHex, ed25519.PublicKeySize,
	)
	nonceBytes := decodeCanonicalLowerHexTransportAuthFixture(
		t, "inputs.rest_nonce_hex", fixture.Inputs.RESTNonceHex, RESTAuthV2NonceSize,
	)
	expectedBodyDigest := decodeCanonicalLowerHexTransportAuthFixture(
		t, "expected.rest_body_sha256_hex", fixture.Expected.RESTBodySHA256Hex, sha256.Size,
	)
	expectedMessage := decodeCanonicalLowerHexTransportAuthFixture(
		t, "expected.rest_signing_message_hex", fixture.Expected.RESTSigningMessageHex, 0,
	)
	expectedMessageDigest := decodeCanonicalLowerHexTransportAuthFixture(
		t, "expected.rest_signing_message_sha256_hex", fixture.Expected.RESTSigningMessageSHA256Hex, sha256.Size,
	)
	expectedSignature := decodeCanonicalLowerHexTransportAuthFixture(
		t, "expected.rest_signature_hex", fixture.Expected.RESTSignatureHex, ed25519.SignatureSize,
	)

	bodyDigest := RESTAuthV2BodyDigest([]byte(fixture.Inputs.RESTBodyUTF8))
	if !bytes.Equal(bodyDigest[:], expectedBodyDigest) {
		t.Fatalf("REST fixture body digest = %x, want %x", bodyDigest, expectedBodyDigest)
	}
	var nonce [RESTAuthV2NonceSize]byte
	copy(nonce[:], nonceBytes)
	input := RESTAuthV2Input{
		CanonicalOrigin: fixture.Inputs.CanonicalOrigin,
		UserID:          fixture.Inputs.RESTUserID,
		Method:          fixture.Inputs.RESTMethod,
		RequestTarget:   fixture.Inputs.RESTRequestTarget,
		TimestampMS:     fixture.Inputs.RESTTimestampMS,
		Nonce:           nonce,
		BodySHA256:      bodyDigest,
	}
	message, err := RESTAuthV2SigningMessage(input)
	if err != nil {
		t.Fatalf("build REST auth v2 fixture message: %v", err)
	}
	if !bytes.Equal(message, expectedMessage) {
		t.Fatalf("REST auth v2 fixture message = %x, want %x", message, expectedMessage)
	}
	messageDigest := sha256.Sum256(message)
	if !bytes.Equal(messageDigest[:], expectedMessageDigest) {
		t.Fatalf("REST auth v2 fixture message SHA-256 = %x, want %x", messageDigest, expectedMessageDigest)
	}

	privateKey := ed25519.NewKeyFromSeed(accountSeed)
	derivedPublicKey := privateKey.Public().(ed25519.PublicKey)
	if !bytes.Equal(derivedPublicKey, accountPublicKey) {
		t.Fatalf("derived REST fixture public key = %x, want %x", derivedPublicKey, accountPublicKey)
	}
	signature := ed25519.Sign(privateKey, message)
	if !bytes.Equal(signature, expectedSignature) {
		t.Fatalf("REST auth v2 fixture signature = %x, want %x", signature, expectedSignature)
	}
	if !ed25519.Verify(accountPublicKey, message, expectedSignature) {
		t.Fatal("reviewed REST auth v2 fixture signature did not verify")
	}

	otherOriginInput := input
	otherOriginInput.CanonicalOrigin = fixture.Inputs.OtherCanonicalOrigin
	otherOriginMessage, err := RESTAuthV2SigningMessage(otherOriginInput)
	if err != nil {
		t.Fatalf("build other-origin REST auth v2 fixture message: %v", err)
	}
	if bytes.Equal(otherOriginMessage, message) {
		t.Fatal("other canonical origin did not change the REST auth v2 message")
	}
	if ed25519.Verify(accountPublicKey, otherOriginMessage, expectedSignature) {
		t.Fatal("Node A REST signature verified for the fixture's Node B origin")
	}
}

func readBoundedTransportAuthFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()
	info, err := file.Stat()
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > transportAuthFixtureMaxBytes {
		t.Fatalf("fixture file %s is not a bounded regular file: mode=%v size=%d", path, info.Mode(), info.Size())
	}
	contents, err := io.ReadAll(io.LimitReader(file, transportAuthFixtureMaxBytes+1))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if len(contents) == 0 || len(contents) > transportAuthFixtureMaxBytes || int64(len(contents)) != info.Size() {
		t.Fatalf("fixture file %s changed size while reading: stat=%d read=%d", path, info.Size(), len(contents))
	}
	return contents
}

func requireSingleFinalLFTransportAuthFixture(t *testing.T, name string, contents []byte) {
	t.Helper()
	if bytes.ContainsRune(contents, '\r') || contents[len(contents)-1] != '\n' ||
		(len(contents) > 1 && contents[len(contents)-2] == '\n') {
		t.Fatalf("%s must be LF-only with exactly one final LF", name)
	}
}

func decodeCanonicalLowerHexTransportAuthFixture(t *testing.T, field, value string, exactBytes int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		t.Fatalf("%s is not canonical lowercase hex", field)
	}
	if exactBytes > 0 && len(decoded) != exactBytes {
		t.Fatalf("%s decoded length = %d, want %d", field, len(decoded), exactBytes)
	}
	if exactBytes == 0 && len(decoded) == 0 {
		t.Fatalf("%s must not be empty", field)
	}
	return decoded
}
