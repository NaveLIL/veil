package transparency

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type witnessProofSourceFixture struct {
	fromRoot Hash
	toRoot   Hash
	proof    []Hash
	calls    int
}

func (s *witnessProofSourceFixture) IdentityTransparencyWitnessConsistencyProof(
	_ context.Context,
	fromSize uint64,
	toSize uint64,
	expectedFromRoot Hash,
	expectedToRoot Hash,
) ([]Hash, error) {
	s.calls++
	if fromSize != 1 || toSize != 2 || expectedFromRoot != s.fromRoot || expectedToRoot != s.toRoot {
		return nil, context.Canceled
	}
	return append([]Hash(nil), s.proof...), nil
}

func TestHTTPWitnessQuorumVerifiesAndSortsIndependentSignatures(t *testing.T) {
	origin := "https://node.example:443"
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	var nodePublic [ed25519.PublicKeySize]byte
	copy(nodePublic[:], nodePrivate.Public().(ed25519.PublicKey))
	logID, err := LogID(origin, nodePublic[:])
	if err != nil {
		t.Fatal(err)
	}
	head := TreeHead{
		LogID: logID, TreeSize: 7, RootHash: hashParts([]byte("witness-root")), IssuedAtMs: 1_718_888_888_123,
	}
	nodeMessage, err := head.SigningMessage(origin)
	if err != nil {
		t.Fatal(err)
	}
	var nodeSignature [ed25519.SignatureSize]byte
	copy(nodeSignature[:], ed25519.Sign(nodePrivate, nodeMessage))
	checkpoint, err := WitnessCheckpointMessage(origin, nodePublic[:], head, nodeSignature[:])
	if err != nil {
		t.Fatal(err)
	}

	endpoints := make([]WitnessEndpoint, 0, 3)
	servers := make([]*httptest.Server, 0, 3)
	for index, seedByte := range []byte{0x43, 0x41, 0x42} {
		privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
		var publicKey [ed25519.PublicKeySize]byte
		copy(publicKey[:], privateKey.Public().(ed25519.PublicKey))
		valid := index != 2
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer r.Body.Close()
			var request witnessCheckpointRequestV1
			decoder := json.NewDecoder(r.Body)
			decoder.DisallowUnknownFields()
			if r.Method != http.MethodPost || decoder.Decode(&request) != nil || request.Version != 1 ||
				request.CanonicalOrigin != origin || request.NodeSigningKey != hex.EncodeToString(nodePublic[:]) ||
				request.LogID != hex.EncodeToString(head.LogID[:]) {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			signature := ed25519.Sign(privateKey, checkpoint)
			if !valid {
				signature[0] ^= 1
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(witnessCheckpointResponseV1{
				Version: 1, SigningKey: hex.EncodeToString(publicKey[:]), Signature: hex.EncodeToString(signature),
			})
		}))
		servers = append(servers, server)
		endpoints = append(endpoints, WitnessEndpoint{URL: server.URL, SigningKey: publicKey})
	}
	defer func() {
		for _, server := range servers {
			server.Close()
		}
	}()

	quorum, err := NewHTTPWitnessQuorum(endpoints, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	signatures, err := quorum.Cosign(context.Background(), origin, nodePublic, head, nodeSignature)
	if err != nil || len(signatures) != 2 {
		t.Fatalf("signatures=%d err=%v", len(signatures), err)
	}
	if bytes.Compare(signatures[0].SigningKey[:], signatures[1].SigningKey[:]) >= 0 {
		t.Fatal("accepted witness signatures are not canonically ordered")
	}
	for _, signature := range signatures {
		if !ed25519.Verify(signature.SigningKey[:], checkpoint, signature.Signature[:]) {
			t.Fatal("returned an unverified witness signature")
		}
	}

	strictQuorum, err := NewHTTPWitnessQuorum(endpoints, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := strictQuorum.Cosign(context.Background(), origin, nodePublic, head, nodeSignature); err == nil {
		t.Fatal("accepted a checkpoint below the configured witness quorum")
	}
}

func TestHTTPWitnessQuorumRetriesWithDurableConsistencyProof(t *testing.T) {
	origin := "https://node.example:443"
	events := [][]byte{[]byte("first"), []byte("second")}
	fromRoot, err := TreeRoot(events[:1])
	if err != nil {
		t.Fatal(err)
	}
	toRoot, err := TreeRoot(events)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := ConsistencyProof(events, 1)
	if err != nil {
		t.Fatal(err)
	}
	source := &witnessProofSourceFixture{fromRoot: fromRoot, toRoot: toRoot, proof: proof}
	nodePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	var nodePublic [ed25519.PublicKeySize]byte
	copy(nodePublic[:], nodePrivate.Public().(ed25519.PublicKey))
	logID, err := LogID(origin, nodePublic[:])
	if err != nil {
		t.Fatal(err)
	}
	head := TreeHead{LogID: logID, TreeSize: 2, RootHash: toRoot, IssuedAtMs: 1_718_888_888_123}
	message, err := head.SigningMessage(origin)
	if err != nil {
		t.Fatal(err)
	}
	var nodeSignature [ed25519.SignatureSize]byte
	copy(nodeSignature[:], ed25519.Sign(nodePrivate, message))
	checkpoint, err := WitnessCheckpointMessage(origin, nodePublic[:], head, nodeSignature[:])
	if err != nil {
		t.Fatal(err)
	}
	witnessPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	var witnessPublic [ed25519.PublicKeySize]byte
	copy(witnessPublic[:], witnessPrivate.Public().(ed25519.PublicKey))
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		defer r.Body.Close()
		var request witnessCheckpointRequestV1
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if request.ConsistencyFrom == "0" {
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(witnessStateResponseV1{
				Version: 1, TreeSize: "1", RootHash: hex.EncodeToString(fromRoot[:]),
			})
			return
		}
		if request.ConsistencyFrom != "1" || request.ConsistencyRoot != hex.EncodeToString(fromRoot[:]) ||
			len(request.ConsistencyProof) != len(proof) {
			http.Error(w, "missing consistency proof", http.StatusBadRequest)
			return
		}
		decodedProof := make([]Hash, len(request.ConsistencyProof))
		for index, encoded := range request.ConsistencyProof {
			value, decodeErr := hex.DecodeString(encoded)
			if decodeErr != nil || len(value) != len(Hash{}) {
				http.Error(w, "invalid consistency proof", http.StatusBadRequest)
				return
			}
			copy(decodedProof[index][:], value)
		}
		if !VerifyConsistency(1, 2, fromRoot, toRoot, decodedProof) {
			http.Error(w, "invalid consistency proof", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(witnessCheckpointResponseV1{
			Version:    1,
			SigningKey: hex.EncodeToString(witnessPublic[:]),
			Signature:  hex.EncodeToString(ed25519.Sign(witnessPrivate, checkpoint)),
		})
	}))
	defer server.Close()

	quorum, err := NewHTTPWitnessQuorum(
		[]WitnessEndpoint{{URL: server.URL, SigningKey: witnessPublic}}, 1, source,
	)
	if err != nil {
		t.Fatal(err)
	}
	if signatures, err := quorum.Cosign(context.Background(), origin, nodePublic, head, nodeSignature); err != nil || len(signatures) != 1 || requests != 2 || source.calls != 1 {
		t.Fatalf("signatures=%d requests=%d source_calls=%d err=%v", len(signatures), requests, source.calls, err)
	}
}
