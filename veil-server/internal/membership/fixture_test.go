package membership

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

const reviewedMembershipFixtureSHA256 = "3f51612291ab9ddfe353292b04fe8088087312dd495eec67e68909bfcf551ece"

type membershipFixtureSigner struct {
	AccountID         string `json:"account_id"`
	AccountSigningKey string `json:"account_signing_key"`
}

type membershipFixtureSignature struct {
	SignerAccountID string `json:"signer_account_id"`
	Signature       string `json:"signature"`
}

type membershipFixtureEpoch struct {
	Number           string                       `json:"number"`
	PredecessorHash  string                       `json:"predecessor_hash"`
	RosterVersion    string                       `json:"roster_version"`
	RosterCommitment string                       `json:"roster_commitment"`
	PolicyThreshold  uint16                       `json:"policy_threshold"`
	PolicySigners    []membershipFixtureSigner    `json:"policy_signers"`
	CryptoProfile    byte                         `json:"crypto_profile"`
	CryptoEra        string                       `json:"crypto_era"`
	MutationNonce    string                       `json:"mutation_nonce"`
	EpochHash        string                       `json:"epoch_hash"`
	Signatures       []membershipFixtureSignature `json:"signatures"`
}

type membershipFixture struct {
	Version          uint32                   `json:"version"`
	CanonicalOrigin  string                   `json:"canonical_origin"`
	ConversationID   string                   `json:"conversation_id"`
	ConversationKind byte                     `json:"conversation_kind"`
	Owner            membershipFixtureSigner  `json:"owner"`
	Epochs           []membershipFixtureEpoch `json:"epochs"`
}

func loadMembershipFixture(t *testing.T) membershipFixture {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve membership fixture path")
	}
	path := filepath.Join(filepath.Dir(source), "..", "..", "..", "test-vectors", "membership", "v1.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(contents) > 64*1024 || fmt.Sprintf("%x", sha256.Sum256(contents)) != reviewedMembershipFixtureSHA256 {
		t.Fatal("membership fixture size or reviewed digest changed")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var fixture membershipFixture
	if err := decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		t.Fatal("membership fixture contains trailing JSON")
	}
	if fixture.Version != 1 || len(fixture.Epochs) != 2 {
		t.Fatal("membership fixture metadata is invalid")
	}
	return fixture
}

func membershipFixtureBytes(t *testing.T, label, encoded string, size int) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != size || hex.EncodeToString(decoded) != encoded {
		t.Fatalf("invalid %s fixture field", label)
	}
	return decoded
}

func membershipFixtureU64(t *testing.T, label, encoded string) uint64 {
	t.Helper()
	value, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || strconv.FormatUint(value, 10) != encoded {
		t.Fatalf("invalid %s fixture integer", label)
	}
	return value
}

func membershipFixtureSignerValue(t *testing.T, encoded membershipFixtureSigner) PolicySigner {
	t.Helper()
	var signer PolicySigner
	copy(signer.AccountID[:], membershipFixtureBytes(t, "policy account id", encoded.AccountID, 16))
	copy(signer.AccountSigningKey[:], membershipFixtureBytes(t, "policy account signing key", encoded.AccountSigningKey, 32))
	return signer
}

func membershipFixtureEpochValue(
	t *testing.T,
	fixture membershipFixture,
	encoded membershipFixtureEpoch,
) (Epoch, []Signature) {
	t.Helper()
	var epoch Epoch
	epoch.CanonicalOrigin = fixture.CanonicalOrigin
	copy(epoch.ConversationID[:], membershipFixtureBytes(t, "conversation id", fixture.ConversationID, 16))
	epoch.ConversationKind = fixture.ConversationKind
	epoch.Number = membershipFixtureU64(t, "epoch number", encoded.Number)
	copy(epoch.PredecessorHash[:], membershipFixtureBytes(t, "predecessor hash", encoded.PredecessorHash, 32))
	epoch.RosterVersion = membershipFixtureU64(t, "roster version", encoded.RosterVersion)
	copy(epoch.RosterCommitment[:], membershipFixtureBytes(t, "roster commitment", encoded.RosterCommitment, 32))
	epoch.SuccessorPolicy.Threshold = encoded.PolicyThreshold
	for _, signer := range encoded.PolicySigners {
		epoch.SuccessorPolicy.Signers = append(epoch.SuccessorPolicy.Signers, membershipFixtureSignerValue(t, signer))
	}
	epoch.CryptoProfile = encoded.CryptoProfile
	era := membershipFixtureU64(t, "crypto era", encoded.CryptoEra)
	if era > uint64(^uint16(0)) {
		t.Fatal("membership fixture crypto era overflows")
	}
	epoch.CryptoEra = uint16(era)
	copy(epoch.MutationNonce[:], membershipFixtureBytes(t, "mutation nonce", encoded.MutationNonce, 32))
	signatures := make([]Signature, len(encoded.Signatures))
	for index, value := range encoded.Signatures {
		copy(signatures[index].SignerAccountID[:], membershipFixtureBytes(t, "signature account id", value.SignerAccountID, 16))
		copy(signatures[index].Signature[:], membershipFixtureBytes(t, "membership signature", value.Signature, 64))
	}
	return epoch, signatures
}

func TestCrossLanguageMembershipEpochV1Vector(t *testing.T) {
	fixture := loadMembershipFixture(t)
	first, firstSignatures := membershipFixtureEpochValue(t, fixture, fixture.Epochs[0])
	second, secondSignatures := membershipFixtureEpochValue(t, fixture, fixture.Epochs[1])
	firstHash, err := first.Hash()
	if err != nil || hex.EncodeToString(firstHash[:]) != fixture.Epochs[0].EpochHash {
		t.Fatalf("first membership epoch hash changed: %v", err)
	}
	secondHash, err := second.Hash()
	if err != nil || hex.EncodeToString(secondHash[:]) != fixture.Epochs[1].EpochHash {
		t.Fatalf("second membership epoch hash changed: %v", err)
	}
	owner := membershipFixtureSignerValue(t, fixture.Owner)
	if err := VerifyBootstrap(first, owner, firstSignatures); err != nil {
		t.Fatalf("fixture bootstrap rejected: %v", err)
	}
	if err := VerifyTransition(first, second, secondSignatures); err != nil {
		t.Fatalf("fixture transition rejected: %v", err)
	}
}
