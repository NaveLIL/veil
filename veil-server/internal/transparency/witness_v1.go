package transparency

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const maxWitnessResponseBytes = 4 * 1024

// WitnessEndpoint identifies one independently operated checkpoint signer.
// Configuration is immutable after the HTTP quorum has been constructed.
type WitnessEndpoint struct {
	URL        string
	SigningKey [ed25519.PublicKeySize]byte
}

type WitnessSignature struct {
	SigningKey [ed25519.PublicKeySize]byte
	Signature  [ed25519.SignatureSize]byte
}

type witnessCheckpointRequestV1 struct {
	Version          int      `json:"version"`
	CanonicalOrigin  string   `json:"canonical_origin"`
	NodeSigningKey   string   `json:"node_signing_key"`
	LogID            string   `json:"log_id"`
	TreeSize         string   `json:"tree_size"`
	RootHash         string   `json:"root_hash"`
	IssuedAtMS       string   `json:"issued_at_ms"`
	NodeSignature    string   `json:"node_signature"`
	ConsistencyFrom  string   `json:"consistency_from"`
	ConsistencyRoot  string   `json:"consistency_root"`
	ConsistencyProof []string `json:"consistency_proof"`
}

type witnessCheckpointResponseV1 struct {
	Version    int    `json:"version"`
	SigningKey string `json:"witness_signing_key"`
	Signature  string `json:"signature"`
}

// HTTPWitnessQuorum obtains and locally verifies external witness signatures.
// A configured quorum fails closed, while an unconfigured Node never creates
// this object and retains the ordinary single-Node compatibility path.
type HTTPWitnessQuorum struct {
	endpoints   []WitnessEndpoint
	threshold   uint16
	client      *http.Client
	proofSource WitnessConsistencyProofSource
}

type WitnessConsistencyProofSource interface {
	IdentityTransparencyWitnessConsistencyProof(
		context.Context,
		uint64,
		uint64,
		Hash,
		Hash,
	) ([]Hash, error)
}

func NewHTTPWitnessQuorum(
	endpoints []WitnessEndpoint,
	threshold uint16,
	proofSource WitnessConsistencyProofSource,
) (*HTTPWitnessQuorum, error) {
	if threshold == 0 || int(threshold) > len(endpoints) || len(endpoints) > MaxWitnesses {
		return nil, errors.New("transparency witness quorum is invalid")
	}
	checked := append([]WitnessEndpoint(nil), endpoints...)
	sort.Slice(checked, func(i, j int) bool {
		return bytes.Compare(checked[i].SigningKey[:], checked[j].SigningKey[:]) < 0
	})
	keys := make([][]byte, len(checked))
	for index := range checked {
		if checked[index].URL == "" || !validEd25519PublicKey(checked[index].SigningKey[:]) ||
			(index > 0 && checked[index-1].SigningKey == checked[index].SigningKey) {
			return nil, errors.New("transparency witness endpoint is invalid")
		}
		keys[index] = checked[index].SigningKey[:]
	}
	if _, err := WitnessPolicyHash(threshold, keys); err != nil {
		return nil, err
	}
	return &HTTPWitnessQuorum{
		endpoints:   checked,
		threshold:   threshold,
		proofSource: proofSource,
		client: &http.Client{
			Timeout: 4 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("transparency witness redirects are disabled")
			},
		},
	}, nil
}

func validEd25519PublicKey(key []byte) bool {
	if len(key) != ed25519.PublicKeySize {
		return false
	}
	var combined byte
	for _, value := range key {
		combined |= value
	}
	return combined != 0
}

func (q *HTTPWitnessQuorum) Cosign(
	ctx context.Context,
	canonicalOrigin string,
	nodeSigningKey [ed25519.PublicKeySize]byte,
	head TreeHead,
	nodeSignature [ed25519.SignatureSize]byte,
) ([]WitnessSignature, error) {
	if q == nil || q.client == nil || q.threshold == 0 {
		return nil, errors.New("transparency witness quorum is unavailable")
	}
	checkpoint, err := WitnessCheckpointMessage(
		canonicalOrigin, nodeSigningKey[:], head, nodeSignature[:],
	)
	if err != nil {
		return nil, err
	}
	wire := witnessCheckpointRequestV1{
		Version: 1, CanonicalOrigin: canonicalOrigin,
		NodeSigningKey:   hex.EncodeToString(nodeSigningKey[:]),
		LogID:            hex.EncodeToString(head.LogID[:]),
		TreeSize:         fmt.Sprintf("%d", head.TreeSize),
		RootHash:         hex.EncodeToString(head.RootHash[:]),
		IssuedAtMS:       fmt.Sprintf("%d", head.IssuedAtMs),
		NodeSignature:    hex.EncodeToString(nodeSignature[:]),
		ConsistencyFrom:  "0",
		ConsistencyRoot:  hex.EncodeToString(make([]byte, len(Hash{}))),
		ConsistencyProof: []string{},
	}

	type result struct {
		signature WitnessSignature
		err       error
	}
	results := make(chan result, len(q.endpoints))
	for _, endpoint := range q.endpoints {
		endpoint := endpoint
		go func() {
			signature, state, requestErr := q.requestOne(ctx, endpoint, wire, checkpoint)
			if state != nil && q.proofSource != nil &&
				state.TreeSize > 0 && state.TreeSize <= head.TreeSize {
				proof, proofErr := q.proofSource.IdentityTransparencyWitnessConsistencyProof(
					ctx, state.TreeSize, head.TreeSize, state.RootHash, head.RootHash,
				)
				if proofErr == nil {
					retry := wire
					retry.ConsistencyFrom = strconv.FormatUint(state.TreeSize, 10)
					retry.ConsistencyRoot = hex.EncodeToString(state.RootHash[:])
					retry.ConsistencyProof = make([]string, len(proof))
					for index := range proof {
						retry.ConsistencyProof[index] = hex.EncodeToString(proof[index][:])
					}
					signature, state, requestErr = q.requestOne(ctx, endpoint, retry, checkpoint)
					if state != nil && requestErr == nil {
						requestErr = errors.New("transparency witness returned ambiguous retry state")
					}
				} else {
					requestErr = proofErr
				}
			}
			results <- result{signature: signature, err: requestErr}
		}()
	}

	accepted := make([]WitnessSignature, 0, len(q.endpoints))
	for range q.endpoints {
		result := <-results
		if result.err == nil {
			accepted = append(accepted, result.signature)
		}
	}
	if len(accepted) < int(q.threshold) {
		return nil, errors.New("transparency witness quorum was not reached")
	}
	sort.Slice(accepted, func(i, j int) bool {
		return bytes.Compare(accepted[i].SigningKey[:], accepted[j].SigningKey[:]) < 0
	})
	return accepted, nil
}

func (q *HTTPWitnessQuorum) requestOne(
	ctx context.Context,
	endpoint WitnessEndpoint,
	wire witnessCheckpointRequestV1,
	checkpoint []byte,
) (WitnessSignature, *witnessStateV1, error) {
	body, err := json.Marshal(wire)
	if err != nil {
		return WitnessSignature{}, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL, bytes.NewReader(body))
	if err != nil {
		return WitnessSignature{}, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := q.client.Do(request)
	if err != nil {
		return WitnessSignature{}, nil, err
	}
	defer response.Body.Close()
	if response.Header.Get("Content-Type") != "application/json" {
		return WitnessSignature{}, nil, errors.New("transparency witness returned an invalid response")
	}
	if response.StatusCode == http.StatusConflict {
		state, stateErr := decodeWitnessStateResponse(response.Body)
		if stateErr != nil {
			return WitnessSignature{}, nil, stateErr
		}
		return WitnessSignature{}, state, errors.New("transparency witness requires a consistency proof")
	}
	if response.StatusCode != http.StatusOK {
		return WitnessSignature{}, nil, errors.New("transparency witness returned an invalid response")
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxWitnessResponseBytes+1))
	decoder.DisallowUnknownFields()
	var responseWire witnessCheckpointResponseV1
	if err := decoder.Decode(&responseWire); err != nil {
		return WitnessSignature{}, nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return WitnessSignature{}, nil, errors.New("transparency witness response has trailing data")
	}
	key, err := hex.DecodeString(responseWire.SigningKey)
	if err != nil || len(key) != ed25519.PublicKeySize || hex.EncodeToString(key) != responseWire.SigningKey ||
		!bytes.Equal(key, endpoint.SigningKey[:]) || responseWire.Version != 1 {
		return WitnessSignature{}, nil, errors.New("transparency witness identity mismatch")
	}
	signature, err := hex.DecodeString(responseWire.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || hex.EncodeToString(signature) != responseWire.Signature ||
		!ed25519.Verify(endpoint.SigningKey[:], checkpoint, signature) {
		return WitnessSignature{}, nil, errors.New("transparency witness signature is invalid")
	}
	var result WitnessSignature
	result.SigningKey = endpoint.SigningKey
	copy(result.Signature[:], signature)
	return result, nil, nil
}

type witnessStateResponseV1 struct {
	Version  int    `json:"version"`
	TreeSize string `json:"tree_size"`
	RootHash string `json:"root_hash"`
}

type witnessStateV1 struct {
	TreeSize uint64
	RootHash Hash
}

func decodeWitnessStateResponse(body io.Reader) (*witnessStateV1, error) {
	decoder := json.NewDecoder(io.LimitReader(body, maxWitnessResponseBytes+1))
	decoder.DisallowUnknownFields()
	var wire witnessStateResponseV1
	if err := decoder.Decode(&wire); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("transparency witness state has trailing data")
	}
	treeSize, sizeErr := parseCanonicalWitnessUint(wire.TreeSize)
	root, rootErr := hex.DecodeString(wire.RootHash)
	if sizeErr != nil || treeSize == 0 || rootErr != nil || len(root) != len(Hash{}) ||
		hex.EncodeToString(root) != wire.RootHash || wire.Version != 1 {
		return nil, errors.New("transparency witness state is invalid")
	}
	state := &witnessStateV1{TreeSize: treeSize}
	copy(state.RootHash[:], root)
	return state, nil
}

func parseCanonicalWitnessUint(value string) (uint64, error) {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || strconv.FormatUint(parsed, 10) != value {
		return 0, errors.New("transparency witness integer is invalid")
	}
	return parsed, nil
}
