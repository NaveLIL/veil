package authmw

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

const (
	restV2VerifierUserA = "00112233-4455-4677-8899-aabbccddeeff"
	restV2VerifierUserB = "10112233-4455-4677-8899-aabbccddeeff"
	restV2VerifierNodeA = "https://node-a.example.test:443"
	restV2VerifierNodeB = "https://node-b.example.test:443"
)

type restV2VerifierLookup struct {
	mu    sync.Mutex
	keys  map[string]ed25519.PublicKey
	err   error
	calls int
}

func (lookup *restV2VerifierLookup) GetSigningKey(_ context.Context, userID string) (ed25519.PublicKey, error) {
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	lookup.calls++
	if lookup.err != nil {
		return nil, lookup.err
	}
	key, ok := lookup.keys[userID]
	if !ok {
		return nil, errors.New("unknown synthetic account")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}

func (lookup *restV2VerifierLookup) callCount() int {
	lookup.mu.Lock()
	defer lookup.mu.Unlock()
	return lookup.calls
}

type restV2VerifierReplayStore struct {
	mu      sync.Mutex
	claimed map[string]struct{}
	err     error
	calls   int
}

func newRESTV2VerifierReplayStore() *restV2VerifierReplayStore {
	return &restV2VerifierReplayStore{claimed: make(map[string]struct{})}
}

func (store *restV2VerifierReplayStore) ClaimRESTAuthV2Nonce(
	_ context.Context,
	userID string,
	nonce [RESTAuthV2NonceSize]byte,
) (bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.calls++
	if store.err != nil {
		return false, store.err
	}
	key := userID + "|" + hex.EncodeToString(nonce[:])
	if _, exists := store.claimed[key]; exists {
		return false, nil
	}
	store.claimed[key] = struct{}{}
	return true, nil
}

func (store *restV2VerifierReplayStore) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.calls
}

type restV2VerifierFixture struct {
	now        time.Time
	origin     nodeorigin.Canonical
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	nonce      [RESTAuthV2NonceSize]byte
}

func newRESTV2VerifierFixture(t *testing.T) restV2VerifierFixture {
	t.Helper()
	origin, err := nodeorigin.ParseCanonical(restV2VerifierNodeA)
	if err != nil {
		t.Fatal(err)
	}
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(0x81 + index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	var nonce [RESTAuthV2NonceSize]byte
	for index := range nonce {
		nonce[index] = byte(index + 1)
	}
	return restV2VerifierFixture{
		now:        time.UnixMilli(1_700_000_000_123),
		origin:     origin,
		privateKey: privateKey,
		publicKey:  publicKey,
		nonce:      nonce,
	}
}

func (fixture restV2VerifierFixture) request(
	t *testing.T,
	userID string,
	privateKey ed25519.PrivateKey,
	timestamp time.Time,
	nonce [RESTAuthV2NonceSize]byte,
	method, target string,
	body []byte,
) RESTAuthV2Request {
	t.Helper()
	message, err := RESTAuthV2SigningMessage(RESTAuthV2Input{
		CanonicalOrigin: fixture.origin.String(),
		UserID:          userID,
		Method:          method,
		RequestTarget:   target,
		TimestampMS:     uint64(timestamp.UnixMilli()),
		Nonce:           nonce,
		BodySHA256:      RESTAuthV2BodyDigest(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(privateKey, message)
	return RESTAuthV2Request{
		Headers: RESTAuthV2HeaderValues{
			Versions:   []string{RESTAuthV2ProtocolVersion},
			Users:      []string{userID},
			Timestamps: []string{strconv.FormatInt(timestamp.UnixMilli(), 10)},
			Nonces:     []string{base64.RawURLEncoding.EncodeToString(nonce[:])},
			Signatures: []string{base64.RawURLEncoding.EncodeToString(signature)},
		},
		Method:        method,
		RequestTarget: target,
		Body:          append([]byte(nil), body...),
	}
}

func (fixture restV2VerifierFixture) verifier(
	t *testing.T,
	lookup UserKeyLookup,
	store RESTAuthV2ReplayStore,
) *RESTAuthV2Verifier {
	t.Helper()
	verifier, err := newRESTAuthV2VerifierWithClock(fixture.origin, lookup, store, func() time.Time {
		return fixture.now
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func cloneRESTAuthV2Request(request RESTAuthV2Request) RESTAuthV2Request {
	request.Headers.Versions = append([]string(nil), request.Headers.Versions...)
	request.Headers.Users = append([]string(nil), request.Headers.Users...)
	request.Headers.Timestamps = append([]string(nil), request.Headers.Timestamps...)
	request.Headers.Nonces = append([]string(nil), request.Headers.Nonces...)
	request.Headers.Signatures = append([]string(nil), request.Headers.Signatures...)
	request.Body = append([]byte(nil), request.Body...)
	return request
}

func requireRESTAuthV2Failure(t *testing.T, err error, want RESTAuthV2Failure) *RESTAuthV2VerifyError {
	t.Helper()
	var typed *RESTAuthV2VerifyError
	if !errors.As(err, &typed) || typed.Failure != want {
		t.Fatalf("failure=%T %v, want %s", err, err, want)
	}
	return typed
}

func TestRESTAuthV2VerifierAcceptsExactProofAndClaimsNonce(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)
	request := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"POST", "/v1/prekeys", []byte(`{"device_id":"0011"}`),
	)

	principal, err := verifier.Verify(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if principal.UserID() != restV2VerifierUserA || lookup.callCount() != 1 || store.callCount() != 1 {
		t.Fatalf("principal=%q lookup_calls=%d replay_calls=%d", principal.UserID(), lookup.callCount(), store.callCount())
	}
	if request.Headers.Versions[0] != "2" || len(request.Headers.Nonces[0]) != 43 || len(request.Headers.Signatures[0]) != 86 {
		t.Fatal("fixture did not use the frozen canonical REST v2 header encodings")
	}
}

func TestRESTAuthV2VerifierRejectsHeaderCardinalityAndAliasesBeforeLookup(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	baseline := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"GET", "/v1/prekeys/0011/count", nil,
	)
	zeroNonce := make([]byte, RESTAuthV2NonceSize)
	mutations := map[string]func(*RESTAuthV2Request){
		"missing version":   func(request *RESTAuthV2Request) { request.Headers.Versions = nil },
		"empty version":     func(request *RESTAuthV2Request) { request.Headers.Versions = []string{""} },
		"combined version":  func(request *RESTAuthV2Request) { request.Headers.Versions = []string{"2, 2"} },
		"duplicate version": func(request *RESTAuthV2Request) { request.Headers.Versions = []string{"2", "2"} },
		"version alias":     func(request *RESTAuthV2Request) { request.Headers.Versions = []string{"02"} },
		"unknown version":   func(request *RESTAuthV2Request) { request.Headers.Versions = []string{"3"} },
		"missing user":      func(request *RESTAuthV2Request) { request.Headers.Users = nil },
		"empty user":        func(request *RESTAuthV2Request) { request.Headers.Users = []string{""} },
		"combined user": func(request *RESTAuthV2Request) {
			request.Headers.Users = []string{restV2VerifierUserA + ", " + restV2VerifierUserA}
		},
		"duplicate user": func(request *RESTAuthV2Request) {
			request.Headers.Users = append(request.Headers.Users, restV2VerifierUserA)
		},
		"uppercase user": func(request *RESTAuthV2Request) {
			request.Headers.Users[0] = "00112233-4455-4677-8899-AABBCCDDEEFF"
		},
		"missing timestamp": func(request *RESTAuthV2Request) { request.Headers.Timestamps = nil },
		"empty timestamp":   func(request *RESTAuthV2Request) { request.Headers.Timestamps = []string{""} },
		"combined timestamp": func(request *RESTAuthV2Request) {
			request.Headers.Timestamps = []string{request.Headers.Timestamps[0] + ", " + request.Headers.Timestamps[0]}
		},
		"timestamp alias": func(request *RESTAuthV2Request) { request.Headers.Timestamps[0] = "01700000000123" },
		"duplicate timestamp": func(request *RESTAuthV2Request) {
			request.Headers.Timestamps = append(request.Headers.Timestamps, request.Headers.Timestamps[0])
		},
		"missing nonce": func(request *RESTAuthV2Request) { request.Headers.Nonces = nil },
		"empty nonce":   func(request *RESTAuthV2Request) { request.Headers.Nonces = []string{""} },
		"short nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces[0] = request.Headers.Nonces[0][:42]
		},
		"non-url nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces[0] = strings.Repeat("+", 43)
		},
		"combined nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces[0] += ", " + request.Headers.Nonces[0]
		},
		"zero nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces[0] = base64.RawURLEncoding.EncodeToString(zeroNonce)
		},
		"padded nonce": func(request *RESTAuthV2Request) { request.Headers.Nonces[0] += "=" },
		"duplicate nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces = append(request.Headers.Nonces, request.Headers.Nonces[0])
		},
		"missing signature": func(request *RESTAuthV2Request) { request.Headers.Signatures = nil },
		"empty signature":   func(request *RESTAuthV2Request) { request.Headers.Signatures = []string{""} },
		"short signature": func(request *RESTAuthV2Request) {
			request.Headers.Signatures[0] = request.Headers.Signatures[0][:85]
		},
		"non-url signature": func(request *RESTAuthV2Request) {
			request.Headers.Signatures[0] = strings.Repeat("+", 86)
		},
		"combined signature": func(request *RESTAuthV2Request) {
			request.Headers.Signatures[0] += ", " + request.Headers.Signatures[0]
		},
		"padded signature": func(request *RESTAuthV2Request) { request.Headers.Signatures[0] += "==" },
		"duplicate signature": func(request *RESTAuthV2Request) {
			request.Headers.Signatures = append(request.Headers.Signatures, request.Headers.Signatures[0])
		},
		"lowercase method": func(request *RESTAuthV2Request) { request.Method = "get" },
		"target alias":     func(request *RESTAuthV2Request) { request.RequestTarget = "/v1//prekeys" },
		"oversized body":   func(request *RESTAuthV2Request) { request.Body = make([]byte, maxSignedBodyBytes+1) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			request := cloneRESTAuthV2Request(baseline)
			mutate(&request)
			lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
				restV2VerifierUserA: fixture.publicKey,
			}}
			store := newRESTV2VerifierReplayStore()
			_, err := fixture.verifier(t, lookup, store).Verify(context.Background(), request)
			requireRESTAuthV2Failure(t, err, RESTAuthV2InvalidRequest)
			if lookup.callCount() != 0 || store.callCount() != 0 {
				t.Fatalf("invalid metadata reached lookup/store: %d/%d", lookup.callCount(), store.callCount())
			}
		})
	}
}

func TestRESTAuthV2VerifierSignatureBindsEveryRequestFieldBeforeReplayClaim(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	baseline := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"POST", "/v1/prekeys?device=7", []byte(`{"x":1}`),
	)
	otherNonce := fixture.nonce
	otherNonce[0] ^= 0x80
	mutations := map[string]func(*RESTAuthV2Request){
		"user": func(request *RESTAuthV2Request) {
			request.Headers.Users[0] = restV2VerifierUserB
		},
		"method": func(request *RESTAuthV2Request) { request.Method = "PUT" },
		"target": func(request *RESTAuthV2Request) { request.RequestTarget = "/v1/prekeys?device=8" },
		"timestamp": func(request *RESTAuthV2Request) {
			request.Headers.Timestamps[0] = strconv.FormatInt(fixture.now.Add(time.Millisecond).UnixMilli(), 10)
		},
		"nonce": func(request *RESTAuthV2Request) {
			request.Headers.Nonces[0] = base64.RawURLEncoding.EncodeToString(otherNonce[:])
		},
		"body": func(request *RESTAuthV2Request) { request.Body = []byte(`{"x":2}`) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			request := cloneRESTAuthV2Request(baseline)
			mutate(&request)
			lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
				restV2VerifierUserA: fixture.publicKey,
				restV2VerifierUserB: fixture.publicKey,
			}}
			store := newRESTV2VerifierReplayStore()
			_, err := fixture.verifier(t, lookup, store).Verify(context.Background(), request)
			requireRESTAuthV2Failure(t, err, RESTAuthV2AuthenticationFailed)
			if store.callCount() != 0 {
				t.Fatal("invalid proof reached replay store")
			}
		})
	}
}

func TestRESTAuthV2VerifierRejectsOtherOriginAndLegacyDomainBeforeClaim(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	request := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"POST", "/v1/prekeys", []byte(`{}`),
	)
	originB, err := nodeorigin.ParseCanonical(restV2VerifierNodeB)
	if err != nil {
		t.Fatal(err)
	}
	verifierB, err := newRESTAuthV2VerifierWithClock(originB, lookup, store, func() time.Time { return fixture.now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifierB.Verify(context.Background(), request)
	requireRESTAuthV2Failure(t, err, RESTAuthV2AuthenticationFailed)
	if store.callCount() != 0 {
		t.Fatal("other-origin proof reached replay store")
	}

	legacyMessage, err := CanonicalRequest(
		request.Method, "node-a.example.test:443", request.RequestTarget,
		request.Headers.Timestamps[0], request.Body,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Headers.Signatures[0] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(fixture.privateKey, legacyMessage))
	_, err = fixture.verifier(t, lookup, store).Verify(context.Background(), request)
	requireRESTAuthV2Failure(t, err, RESTAuthV2AuthenticationFailed)
	if store.callCount() != 0 {
		t.Fatal("REST v1 proof reached REST v2 replay store")
	}
}

func TestRESTAuthV2VerifierTimestampWindowIsInclusive(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)
	for index, testCase := range []struct {
		name   string
		offset time.Duration
		want   RESTAuthV2Failure
	}{
		{name: "old edge", offset: -SignatureMaxSkew},
		{name: "future edge", offset: SignatureMaxSkew},
		{name: "too old", offset: -SignatureMaxSkew - time.Millisecond, want: RESTAuthV2TimestampRejected},
		{name: "too future", offset: SignatureMaxSkew + time.Millisecond, want: RESTAuthV2TimestampRejected},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			nonce := fixture.nonce
			nonce[0] = byte(index + 11)
			request := fixture.request(
				t, restV2VerifierUserA, fixture.privateKey, fixture.now.Add(testCase.offset), nonce,
				"GET", "/v1/users/search?username=alice", nil,
			)
			_, err := verifier.Verify(context.Background(), request)
			if testCase.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			requireRESTAuthV2Failure(t, err, testCase.want)
		})
	}
	if store.callCount() != 2 {
		t.Fatalf("replay calls=%d, want only the two in-window proofs", store.callCount())
	}
}

func TestRESTAuthV2VerifierFreshnessUsesCanonicalMilliseconds(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	now := fixture.now.Add(999 * time.Microsecond)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier, err := newRESTAuthV2VerifierWithClock(fixture.origin, lookup, store, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	canonicalNow := time.UnixMilli(now.UnixMilli())
	for index, testCase := range []struct {
		name   string
		offset time.Duration
		want   RESTAuthV2Failure
	}{
		{name: "old exact millisecond edge", offset: -SignatureMaxSkew},
		{name: "future exact millisecond edge", offset: SignatureMaxSkew},
		{name: "one millisecond too old", offset: -SignatureMaxSkew - time.Millisecond, want: RESTAuthV2TimestampRejected},
		{name: "one millisecond too future", offset: SignatureMaxSkew + time.Millisecond, want: RESTAuthV2TimestampRejected},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			nonce := fixture.nonce
			nonce[0] = byte(index + 31)
			request := fixture.request(
				t, restV2VerifierUserA, fixture.privateKey, canonicalNow.Add(testCase.offset), nonce,
				"GET", "/v1/users/search?username=alice", nil,
			)
			_, verifyErr := verifier.Verify(context.Background(), request)
			if testCase.want == "" {
				if verifyErr != nil {
					t.Fatal(verifyErr)
				}
				return
			}
			requireRESTAuthV2Failure(t, verifyErr, testCase.want)
		})
	}
	if store.callCount() != 2 {
		t.Fatalf("replay calls=%d, want only the two millisecond-edge proofs", store.callCount())
	}
}

func TestRESTAuthV2VerifierReplayScopeAndStoreFailure(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	seedB := make([]byte, ed25519.SeedSize)
	for index := range seedB {
		seedB[index] = byte(0x41 + index)
	}
	privateB := ed25519.NewKeyFromSeed(seedB)
	publicB := privateB.Public().(ed25519.PublicKey)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
		restV2VerifierUserB: publicB,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)

	first := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"POST", "/v1/prekeys", []byte(`{"x":1}`),
	)
	if _, err := verifier.Verify(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	changed := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now.Add(time.Millisecond), fixture.nonce,
		"POST", "/v1/prekeys", []byte(`{"x":2}`),
	)
	_, err := verifier.Verify(context.Background(), changed)
	requireRESTAuthV2Failure(t, err, RESTAuthV2Replay)

	otherAccount := fixture.request(
		t, restV2VerifierUserB, privateB, fixture.now, fixture.nonce,
		"POST", "/v1/prekeys", []byte(`{"x":1}`),
	)
	if _, err := verifier.Verify(context.Background(), otherAccount); err != nil {
		t.Fatalf("same nonce in another account scope: %v", err)
	}

	failingStore := newRESTV2VerifierReplayStore()
	failingStore.err = errors.New("synthetic database outage with private details")
	request := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, [32]byte{99},
		"GET", "/v1/devices/00112233-4455-4677-8899-aabbccddeeff", nil,
	)
	_, err = fixture.verifier(t, lookup, failingStore).Verify(context.Background(), request)
	typed := requireRESTAuthV2Failure(t, err, RESTAuthV2ReplayStoreFailed)
	if typed.Error() != "REST authentication replay protection is unavailable" {
		t.Fatalf("unstable/public store error: %q", typed.Error())
	}
}

func TestRESTAuthV2VerifierRejectsUnknownOrInvalidAccountKeyBeforeClaim(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	wrongSeed := make([]byte, ed25519.SeedSize)
	for index := range wrongSeed {
		wrongSeed[index] = byte(index + 17)
	}
	wrongPublic := ed25519.NewKeyFromSeed(wrongSeed).Public().(ed25519.PublicKey)
	request := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"GET", "/v1/users/search?username=alice", nil,
	)
	for name, lookup := range map[string]*restV2VerifierLookup{
		"unknown": {keys: map[string]ed25519.PublicKey{}},
		"wrong": {keys: map[string]ed25519.PublicKey{
			restV2VerifierUserA: wrongPublic,
		}},
		"low order": {keys: map[string]ed25519.PublicKey{
			restV2VerifierUserA: make(ed25519.PublicKey, ed25519.PublicKeySize),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			store := newRESTV2VerifierReplayStore()
			_, err := fixture.verifier(t, lookup, store).Verify(context.Background(), request)
			requireRESTAuthV2Failure(t, err, RESTAuthV2AuthenticationFailed)
			if store.callCount() != 0 {
				t.Fatal("invalid account key reached replay store")
			}
		})
	}
}

func TestRESTAuthV2VerifierFailuresExposeOnlyStableMessages(t *testing.T) {
	privateCause := errors.New("synthetic private database and account detail")
	for failure, want := range map[RESTAuthV2Failure]string{
		RESTAuthV2InvalidRequest:       "REST authentication request is invalid",
		RESTAuthV2TimestampRejected:    "REST authentication timestamp was rejected",
		RESTAuthV2AuthenticationFailed: "REST authentication failed",
		RESTAuthV2Replay:               "REST authentication nonce was already used",
		RESTAuthV2ReplayStoreFailed:    "REST authentication replay protection is unavailable",
	} {
		t.Run(string(failure), func(t *testing.T) {
			err := restAuthV2Failure(failure, privateCause)
			if err.Error() != want || strings.Contains(err.Error(), privateCause.Error()) {
				t.Fatalf("public error=%q, want exact stable message %q", err.Error(), want)
			}
			if !errors.Is(err, privateCause) {
				t.Fatal("internal cause was not retained for private classification")
			}
		})
	}
}

func TestRESTAuthV2VerifierConcurrentConsumersHaveOneWinner(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)
	request := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		"GET", "/v1/users/search?username=alice", nil,
	)

	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			_, err := verifier.Verify(context.Background(), request)
			results <- err
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	var accepted, replayed int
	for err := range results {
		if err == nil {
			accepted++
			continue
		}
		requireRESTAuthV2Failure(t, err, RESTAuthV2Replay)
		replayed++
	}
	if accepted != 1 || replayed != 1 || store.callCount() != 2 {
		t.Fatalf("accepted=%d replayed=%d claims=%d", accepted, replayed, store.callCount())
	}
}

func TestNewRESTAuthV2VerifierRequiresTrustedDependencies(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{}}
	store := newRESTV2VerifierReplayStore()
	var typedNilLookup *restV2VerifierLookup
	var typedNilLookupFunc LookupFunc
	var typedNilStore *restV2VerifierReplayStore
	for name, build := range map[string]func() (*RESTAuthV2Verifier, error){
		"zero origin": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(nodeorigin.Canonical{}, lookup, store)
		},
		"nil lookup": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(fixture.origin, nil, store)
		},
		"nil store": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(fixture.origin, lookup, nil)
		},
		"typed nil lookup": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(fixture.origin, typedNilLookup, store)
		},
		"typed nil lookup func": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(fixture.origin, typedNilLookupFunc, store)
		},
		"typed nil store": func() (*RESTAuthV2Verifier, error) {
			return NewRESTAuthV2Verifier(fixture.origin, lookup, typedNilStore)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := build(); !errors.Is(err, ErrRESTAuthV2VerifierConfiguration) {
				t.Fatalf("constructor error=%v", err)
			}
		})
	}
	verifier, err := newRESTAuthV2VerifierWithClock(fixture.origin, lookup, store, nil)
	if err != nil || verifier.now == nil {
		t.Fatalf("nil optional clock did not select default: verifier=%v err=%v", verifier, err)
	}
}

func TestRESTAuthV2HeaderNamesAreFrozen(t *testing.T) {
	want := []string{
		"X-Veil-REST-Auth-Version",
		"X-Veil-User",
		"X-Veil-Timestamp",
		"X-Veil-Nonce",
		"X-Veil-Signature",
	}
	got := []string{
		RESTAuthV2VersionHeader,
		RESTAuthV2UserHeader,
		RESTAuthV2TimestampHeader,
		RESTAuthV2NonceHeader,
		RESTAuthV2SignatureHeader,
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("header names=%v, want %v", got, want)
	}
}
