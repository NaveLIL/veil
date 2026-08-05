package membership

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func FuzzMembershipEpochCanonicalization(f *testing.F) {
	f.Add(
		"https://veil.example:443",
		bytes.Repeat([]byte{0x11}, 16),
		uint64(1),
		uint64(1),
		uint8(ConversationKindGroup),
		bytes.Repeat([]byte{0x22}, 32),
	)
	f.Add("", []byte{}, uint64(0), uint64(0), uint8(0), []byte{})
	f.Fuzz(func(
		t *testing.T,
		origin string,
		conversationBytes []byte,
		number uint64,
		rosterVersion uint64,
		conversationKind uint8,
		material []byte,
	) {
		seed := sha256.Sum256(material)
		signing := ed25519.NewKeyFromSeed(seed[:])
		var conversationID [16]byte
		copy(conversationID[:], conversationBytes)
		var predecessor Hash
		if number != 1 {
			predecessor = sha256.Sum256(append([]byte("predecessor"), material...))
		}
		rosterCommitment := sha256.Sum256(append([]byte("roster"), material...))
		mutationNonce := sha256.Sum256(append([]byte("mutation"), material...))
		accountID := sha256.Sum256(append([]byte("account"), material...))
		epoch := Epoch{
			CanonicalOrigin:  origin,
			ConversationID:   conversationID,
			ConversationKind: conversationKind,
			Number:           number,
			PredecessorHash:  predecessor,
			RosterVersion:    rosterVersion,
			RosterCommitment: rosterCommitment,
			SuccessorPolicy: Policy{
				Threshold: 1,
				Signers: []PolicySigner{{
					AccountID:         [16]byte(accountID[:16]),
					AccountSigningKey: [32]byte(signing.Public().(ed25519.PublicKey)),
				}},
			},
			CryptoProfile: CryptoProfileSenderKeyV6,
			CryptoEra:     CryptoEraV1,
			MutationNonce: mutationNonce,
		}
		first, err := epoch.CanonicalUnsignedBytes()
		second, secondErr := epoch.CanonicalUnsignedBytes()
		if (err == nil) != (secondErr == nil) || !bytes.Equal(first, second) {
			t.Fatal("membership epoch canonicalization is non-deterministic")
		}
		if err != nil {
			return
		}
		if validateErr := epoch.Validate(); validateErr != nil {
			t.Fatalf("canonicalization accepted an invalid epoch: %v", validateErr)
		}
		hash, hashErr := epoch.Hash()
		if hashErr != nil || hash != sha256.Sum256(first) {
			t.Fatal("membership epoch hash differs from its canonical bytes")
		}
		mutated := epoch
		mutated.MutationNonce[0] ^= 1
		mutatedHash, mutatedErr := mutated.Hash()
		if mutatedErr != nil || mutatedHash == hash {
			t.Fatal("membership mutation nonce was not committed by the epoch hash")
		}
	})
}
