package transparency

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

const reviewedTransparencyFixtureSHA256 = "d450d353f4472d630e37c74e6ea692461c001a31a1ad31b612856ad3efebb3a1"

type transparencyFixture struct {
	SchemaVersion uint32 `json:"schema_version"`
	SyntheticOnly bool   `json:"synthetic_only"`
	Note          string `json:"note"`
	Inputs        struct {
		CanonicalOrigin         string   `json:"canonical_origin"`
		AccountIDHex            string   `json:"account_id_hex"`
		AccountIdentityKeyHex   string   `json:"account_identity_key_hex"`
		AccountSigningSeedHex   string   `json:"account_signing_seed_hex"`
		DeviceKeyHex            string   `json:"device_key_hex"`
		DeviceIdentityKeyHex    string   `json:"device_identity_key_hex"`
		DeviceSigningSeedHex    string   `json:"device_signing_seed_hex"`
		DeviceBindingVersion    uint64   `json:"device_binding_version"`
		DeviceCapabilities      uint64   `json:"device_capabilities"`
		DeviceBindingStatus     uint8    `json:"device_binding_status"`
		DeviceAccountSignature  string   `json:"device_account_signature_hex"`
		DeviceBindingCommitment string   `json:"device_binding_commitment_hex"`
		AdditionalEventHex      []string `json:"additional_event_hex"`
		InclusionLeafIndex      uint64   `json:"inclusion_leaf_index"`
		ConsistencyOldSize      uint64   `json:"consistency_old_size"`
		IssuedAtMS              uint64   `json:"issued_at_ms"`
		WitnessSigningSeedHex   []string `json:"witness_signing_seed_hex"`
		WitnessThreshold        uint16   `json:"witness_threshold"`
	} `json:"inputs"`
	Expected struct {
		AccountSigningKeyHex        string   `json:"account_signing_key_hex"`
		AccountRegistrationEventHex string   `json:"account_registration_event_hex"`
		DeviceSigningKeyHex         string   `json:"device_signing_key_hex"`
		DeviceBindingEventHex       string   `json:"device_binding_event_hex"`
		LeafHashHex                 []string `json:"leaf_hash_hex"`
		TreeRootHex                 []string `json:"tree_root_hex"`
		InclusionProofHex           []string `json:"inclusion_proof_hex"`
		ConsistencyProofHex         []string `json:"consistency_proof_hex"`
		LogIDHex                    string   `json:"log_id_hex"`
		TreeHeadSigningMessageHex   string   `json:"tree_head_signing_message_hex"`
		TreeHeadSignatureHex        string   `json:"tree_head_signature_hex"`
		WitnessCheckpointMessageHex string   `json:"witness_checkpoint_message_hex"`
		WitnessSigningKeyHex        []string `json:"witness_signing_key_hex"`
		WitnessSignatureHex         []string `json:"witness_signature_hex"`
		WitnessPolicyHashHex        string   `json:"witness_policy_hash_hex"`
	} `json:"expected"`
}

func fixtureHex(t *testing.T, label, encoded string, exactLength int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || (exactLength >= 0 && len(decoded) != exactLength) {
		t.Fatalf("invalid %s fixture field", label)
	}
	return decoded
}

func fixtureHash(t *testing.T, label, encoded string) Hash {
	t.Helper()
	decoded := fixtureHex(t, label, encoded, sha256.Size)
	var result Hash
	copy(result[:], decoded)
	return result
}

func loadTransparencyFixture(t *testing.T) transparencyFixture {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve fixture test path")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "test-vectors", "transparency", "v1.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) > 64*1024 || fmt.Sprintf("%x", sha256.Sum256(contents)) != reviewedTransparencyFixtureSHA256 {
		t.Fatal("transparency fixture size or reviewed digest changed")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var fixture transparencyFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("transparency fixture contains trailing JSON")
	}
	if fixture.SchemaVersion != 1 || !fixture.SyntheticOnly || fixture.Note == "" {
		t.Fatal("transparency fixture metadata is invalid")
	}
	return fixture
}

func TestCrossLanguageTransparencyV1Vector(t *testing.T) {
	fixture := loadTransparencyFixture(t)
	seed := fixtureHex(t, "account signing seed", fixture.Inputs.AccountSigningSeedHex, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	if !bytes.Equal(public, fixtureHex(t, "account signing key", fixture.Expected.AccountSigningKeyHex, ed25519.PublicKeySize)) {
		t.Fatal("derived fixture signing key changed")
	}
	accountID := fixtureHex(t, "account id", fixture.Inputs.AccountIDHex, 16)
	identityKey := fixtureHex(t, "account identity key", fixture.Inputs.AccountIdentityKeyHex, 32)
	event, err := AccountRegistrationEvent(fixture.Inputs.CanonicalOrigin, accountID, identityKey, public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(event, fixtureHex(t, "account event", fixture.Expected.AccountRegistrationEventHex, -1)) {
		t.Fatal("canonical account registration event changed")
	}
	devicePrivate := ed25519.NewKeyFromSeed(fixtureHex(
		t, "device signing seed", fixture.Inputs.DeviceSigningSeedHex, ed25519.SeedSize,
	))
	devicePublic := devicePrivate.Public().(ed25519.PublicKey)
	if !bytes.Equal(devicePublic, fixtureHex(t, "device signing key", fixture.Expected.DeviceSigningKeyHex, ed25519.PublicKeySize)) {
		t.Fatal("derived fixture device signing key changed")
	}
	deviceEvent, err := DeviceBindingEvent(
		fixture.Inputs.CanonicalOrigin,
		accountID,
		fixtureHex(t, "device key", fixture.Inputs.DeviceKeyHex, 16),
		fixtureHex(t, "device identity key", fixture.Inputs.DeviceIdentityKeyHex, 32),
		devicePublic,
		fixture.Inputs.DeviceBindingVersion,
		fixture.Inputs.DeviceCapabilities,
		fixture.Inputs.DeviceBindingStatus,
		fixtureHex(t, "device account signature", fixture.Inputs.DeviceAccountSignature, ed25519.SignatureSize),
		fixtureHex(t, "device binding commitment", fixture.Inputs.DeviceBindingCommitment, sha256.Size),
	)
	if err != nil || !bytes.Equal(deviceEvent, fixtureHex(t, "device binding event", fixture.Expected.DeviceBindingEventHex, -1)) {
		t.Fatalf("canonical device binding event changed: %v", err)
	}
	events := make([][]byte, 1, 1+len(fixture.Inputs.AdditionalEventHex))
	events[0] = event
	for index, encoded := range fixture.Inputs.AdditionalEventHex {
		events = append(events, fixtureHex(t, fmt.Sprintf("additional event %d", index), encoded, -1))
	}
	if len(fixture.Expected.LeafHashHex) != len(events) || len(fixture.Expected.TreeRootHex) != len(events)+1 {
		t.Fatal("transparency fixture vector dimensions are invalid")
	}
	for index, item := range events {
		hash, err := LeafHash(item)
		if err != nil || hash != fixtureHash(t, fmt.Sprintf("leaf hash %d", index), fixture.Expected.LeafHashHex[index]) {
			t.Fatalf("leaf hash %d changed: %v", index, err)
		}
	}
	for size := 0; size <= len(events); size++ {
		root, err := TreeRoot(events[:size])
		if err != nil || root != fixtureHash(t, fmt.Sprintf("tree root %d", size), fixture.Expected.TreeRootHex[size]) {
			t.Fatalf("tree root %d changed: %v", size, err)
		}
	}
	inclusion, err := InclusionProof(events, int(fixture.Inputs.InclusionLeafIndex))
	if err != nil || len(inclusion) != len(fixture.Expected.InclusionProofHex) {
		t.Fatalf("inclusion vector invalid: %v", err)
	}
	for index, item := range inclusion {
		if item != fixtureHash(t, fmt.Sprintf("inclusion proof %d", index), fixture.Expected.InclusionProofHex[index]) {
			t.Fatalf("inclusion proof %d changed", index)
		}
	}
	consistency, err := ConsistencyProof(events, int(fixture.Inputs.ConsistencyOldSize))
	if err != nil || len(consistency) != len(fixture.Expected.ConsistencyProofHex) {
		t.Fatalf("consistency vector invalid: %v", err)
	}
	for index, item := range consistency {
		if item != fixtureHash(t, fmt.Sprintf("consistency proof %d", index), fixture.Expected.ConsistencyProofHex[index]) {
			t.Fatalf("consistency proof %d changed", index)
		}
	}
	root := fixtureHash(t, "latest tree root", fixture.Expected.TreeRootHex[len(events)])
	computedLogID, err := LogID(fixture.Inputs.CanonicalOrigin, public)
	if err != nil {
		t.Fatal(err)
	}
	if computedLogID != fixtureHash(t, "log id", fixture.Expected.LogIDHex) {
		t.Fatal("log id vector changed")
	}
	head := TreeHead{
		LogID:      computedLogID,
		TreeSize:   uint64(len(events)),
		RootHash:   root,
		IssuedAtMs: fixture.Inputs.IssuedAtMS,
	}
	message, err := head.SigningMessage(fixture.Inputs.CanonicalOrigin)
	if err != nil || !bytes.Equal(message, fixtureHex(t, "tree-head message", fixture.Expected.TreeHeadSigningMessageHex, -1)) {
		t.Fatalf("tree-head signing message changed: %v", err)
	}
	signature := ed25519.Sign(private, message)
	if !bytes.Equal(signature, fixtureHex(t, "tree-head signature", fixture.Expected.TreeHeadSignatureHex, ed25519.SignatureSize)) ||
		!head.VerifyNodeSignature(fixture.Inputs.CanonicalOrigin, public, signature) {
		t.Fatal("tree-head signature vector changed")
	}
	checkpoint, err := WitnessCheckpointMessage(
		fixture.Inputs.CanonicalOrigin, public, head, signature,
	)
	if err != nil || !bytes.Equal(
		checkpoint,
		fixtureHex(t, "witness checkpoint", fixture.Expected.WitnessCheckpointMessageHex, -1),
	) {
		t.Fatalf("witness checkpoint vector changed: %v", err)
	}
	type witnessFixtureKey struct {
		public  ed25519.PublicKey
		private ed25519.PrivateKey
	}
	witnesses := make([]witnessFixtureKey, len(fixture.Inputs.WitnessSigningSeedHex))
	for index, encoded := range fixture.Inputs.WitnessSigningSeedHex {
		privateKey := ed25519.NewKeyFromSeed(fixtureHex(t, "witness seed", encoded, ed25519.SeedSize))
		witnesses[index] = witnessFixtureKey{
			public: privateKey.Public().(ed25519.PublicKey), private: privateKey,
		}
	}
	sort.Slice(witnesses, func(i, j int) bool {
		return bytes.Compare(witnesses[i].public, witnesses[j].public) < 0
	})
	if len(witnesses) != len(fixture.Expected.WitnessSigningKeyHex) ||
		len(witnesses) != len(fixture.Expected.WitnessSignatureHex) {
		t.Fatal("witness fixture dimensions are invalid")
	}
	policyKeys := make([][]byte, len(witnesses))
	for index := range witnesses {
		policyKeys[index] = witnesses[index].public
		if !bytes.Equal(
			witnesses[index].public,
			fixtureHex(t, "witness public key", fixture.Expected.WitnessSigningKeyHex[index], ed25519.PublicKeySize),
		) || !bytes.Equal(
			ed25519.Sign(witnesses[index].private, checkpoint),
			fixtureHex(t, "witness signature", fixture.Expected.WitnessSignatureHex[index], ed25519.SignatureSize),
		) {
			t.Fatalf("witness vector %d changed", index)
		}
	}
	policyHash, err := WitnessPolicyHash(fixture.Inputs.WitnessThreshold, policyKeys)
	if err != nil || policyHash != fixtureHash(t, "witness policy hash", fixture.Expected.WitnessPolicyHashHex) {
		t.Fatalf("witness policy vector changed: %v", err)
	}
}

func testEvents(count int) [][]byte {
	events := make([][]byte, count)
	for index := range events {
		events[index] = []byte(fmt.Sprintf("canonical-event-%04d", index))
	}
	return events
}

func TestInclusionAndConsistencyExhaustiveForUnbalancedTrees(t *testing.T) {
	all := testEvents(80)
	for size := 1; size <= len(all); size++ {
		current := all[:size]
		root, err := TreeRoot(current)
		if err != nil {
			t.Fatalf("root size %d: %v", size, err)
		}
		for index := range current {
			proof, err := InclusionProof(current, index)
			if err != nil {
				t.Fatalf("inclusion index %d size %d: %v", index, size, err)
			}
			if !VerifyInclusion(current[index], uint64(index), uint64(size), proof, root) {
				t.Fatalf("inclusion failed for index %d size %d", index, size)
			}
			if len(proof) != 0 {
				forged := append([]Hash(nil), proof...)
				forged[0][0] ^= 1
				if VerifyInclusion(current[index], uint64(index), uint64(size), forged, root) {
					t.Fatalf("forged inclusion accepted for index %d size %d", index, size)
				}
			}
		}

		for oldSize := 1; oldSize <= size; oldSize++ {
			oldRoot, err := TreeRoot(current[:oldSize])
			if err != nil {
				t.Fatal(err)
			}
			proof, err := ConsistencyProof(current, oldSize)
			if err != nil {
				t.Fatalf("consistency %d -> %d: %v", oldSize, size, err)
			}
			if !VerifyConsistency(uint64(oldSize), uint64(size), oldRoot, root, proof) {
				t.Fatalf("consistency failed for %d -> %d", oldSize, size)
			}
			if oldSize != size {
				wrong := oldRoot
				wrong[0] ^= 1
				if VerifyConsistency(uint64(oldSize), uint64(size), wrong, root, proof) {
					t.Fatalf("wrong old root accepted for %d -> %d", oldSize, size)
				}
			}
		}
	}
}

func TestTreeHeadAndAccountEventAreStrictlyBound(t *testing.T) {
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	public := private.Public().(ed25519.PublicKey)
	event, err := AccountRegistrationEvent(
		"https://node.example:443",
		append([]byte{1}, make([]byte, 15)...),
		bytes.Repeat([]byte{2}, 32),
		public,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := TreeRoot([][]byte{event})
	if err != nil {
		t.Fatal(err)
	}
	head := TreeHead{LogID: hashParts([]byte("test-log")), TreeSize: 1, RootHash: root, IssuedAtMs: 1712345678901}
	message, err := head.SigningMessage("https://node.example:443")
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(private, message)
	if !head.VerifyNodeSignature("https://node.example:443", public, signature) {
		t.Fatal("valid tree-head signature rejected")
	}
	if head.VerifyNodeSignature("https://other.example:443", public, signature) {
		t.Fatal("cross-origin tree-head signature accepted")
	}
	head.TreeSize++
	if head.VerifyNodeSignature("https://node.example:443", public, signature) {
		t.Fatal("mutated tree-head signature accepted")
	}
	if _, err := AccountRegistrationEvent("https://node.example:443", make([]byte, 16), bytes.Repeat([]byte{2}, 32), public); err == nil {
		t.Fatal("nil account id accepted")
	}
}

func TestProofCoordinatesAndBoundsFailClosed(t *testing.T) {
	events := testEvents(3)
	root, err := TreeRoot(events)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InclusionProof(events, 3); err == nil {
		t.Fatal("out-of-range inclusion coordinate accepted")
	}
	if _, err := ConsistencyProof(events, 0); err == nil {
		t.Fatal("zero old tree accepted")
	}
	if VerifyInclusion(events[0], 3, 3, nil, root) {
		t.Fatal("out-of-range inclusion verified")
	}
	if VerifyConsistency(4, 3, root, root, nil) {
		t.Fatal("reverse consistency verified")
	}
	if _, err := LeafHash(nil); err == nil {
		t.Fatal("empty transparency event accepted")
	}
}
