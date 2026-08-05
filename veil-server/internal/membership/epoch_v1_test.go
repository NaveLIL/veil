package membership

import (
	"crypto/ed25519"
	"testing"
)

func testAccount(id, seed byte) (PolicySigner, ed25519.PrivateKey) {
	privateKey := ed25519.NewKeyFromSeed(bytesOf(seed, ed25519.SeedSize))
	var accountID [16]byte
	accountID[15] = id
	var publicKey [ed25519.PublicKeySize]byte
	copy(publicKey[:], privateKey.Public().(ed25519.PublicKey))
	return PolicySigner{AccountID: accountID, AccountSigningKey: publicKey}, privateKey
}

func bytesOf(value byte, count int) []byte {
	result := make([]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func signEpoch(t *testing.T, epoch Epoch, signer PolicySigner, privateKey ed25519.PrivateKey) Signature {
	t.Helper()
	message, err := epoch.SignatureMessage()
	if err != nil {
		t.Fatal(err)
	}
	signatureBytes := ed25519.Sign(privateKey, message)
	var signature [ed25519.SignatureSize]byte
	copy(signature[:], signatureBytes)
	return Signature{SignerAccountID: signer.AccountID, Signature: signature}
}

func testEpochOne() (Epoch, PolicySigner, ed25519.PrivateKey, PolicySigner, ed25519.PrivateKey) {
	owner, ownerKey := testAccount(1, 7)
	admin, adminKey := testAccount(2, 9)
	var conversationID [16]byte
	conversationID[0], conversationID[15] = 0x44, 0x55
	return Epoch{
		CanonicalOrigin:  "https://node.example:443",
		ConversationID:   conversationID,
		ConversationKind: ConversationKindGroup,
		Number:           1,
		RosterVersion:    7,
		RosterCommitment: [32]byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33},
		SuccessorPolicy:  Policy{Threshold: 2, Signers: []PolicySigner{owner, admin}},
		CryptoProfile:    CryptoProfileSenderKeyV6,
		CryptoEra:        CryptoEraV1,
		MutationNonce:    [32]byte{0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77},
	}, owner, ownerKey, admin, adminKey
}

func TestBootstrapAndThresholdTransitionArePredecessorAuthorized(t *testing.T) {
	first, owner, ownerKey, admin, adminKey := testEpochOne()
	if err := VerifyBootstrap(first, owner, []Signature{signEpoch(t, first, owner, ownerKey)}); err != nil {
		t.Fatal(err)
	}
	second := first
	second.Number = 2
	firstHash, err := first.Hash()
	if err != nil {
		t.Fatal(err)
	}
	second.PredecessorHash = firstHash
	second.RosterVersion = 8
	second.RosterCommitment = [32]byte{0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45, 0x45}
	second.MutationNonce = [32]byte{0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88}
	second.SuccessorPolicy = Policy{Threshold: 1, Signers: []PolicySigner{owner}}
	signatures := []Signature{signEpoch(t, second, owner, ownerKey), signEpoch(t, second, admin, adminKey)}
	if err := VerifyTransition(first, second, signatures); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTransition(first, second, signatures[:1]); err == nil {
		t.Fatal("accepted transition below predecessor threshold")
	}
	second.PredecessorHash[0] ^= 1
	if err := VerifyTransition(first, second, signatures); err == nil {
		t.Fatal("accepted transition with a substituted predecessor")
	}
}

func TestPolicyAndSignatureCanonicalizationFailClosed(t *testing.T) {
	first, owner, ownerKey, admin, adminKey := testEpochOne()
	first.SuccessorPolicy.Signers[0], first.SuccessorPolicy.Signers[1] =
		first.SuccessorPolicy.Signers[1], first.SuccessorPolicy.Signers[0]
	if err := first.Validate(); err == nil {
		t.Fatal("accepted a reordered policy")
	}
	first, owner, ownerKey, admin, adminKey = testEpochOne()
	second := first
	second.Number = 2
	second.PredecessorHash, _ = first.Hash()
	second.MutationNonce[0] = 0x88
	reversed := []Signature{signEpoch(t, second, admin, adminKey), signEpoch(t, second, owner, ownerKey)}
	if err := VerifyTransition(first, second, reversed); err == nil {
		t.Fatal("accepted reordered signatures")
	}
	second.CanonicalOrigin = "https://other.example:443"
	crossOrigin := []Signature{signEpoch(t, second, owner, ownerKey), signEpoch(t, second, admin, adminKey)}
	if err := VerifyTransition(first, second, crossOrigin); err == nil {
		t.Fatal("accepted a cross-origin transition")
	}
}
