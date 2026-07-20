package authmw

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

func assertRESTAuthV2PreflightCleared(t *testing.T, preflight *restAuthV2Preflight) {
	t.Helper()
	if preflight == nil {
		t.Fatal("nil preflight")
	}
	if preflight.verifier != nil || preflight.userID != "" || preflight.method != "" ||
		preflight.requestTarget != "" || preflight.timestampMS != 0 || !preflight.startedAt.IsZero() || preflight.publicKey != nil {
		t.Fatalf("preflight retained references or metadata: %+v", preflight)
	}
	for index, value := range preflight.nonce {
		if value != 0 {
			t.Fatalf("preflight nonce byte %d was not cleared", index)
		}
	}
	for index, value := range preflight.signature {
		if value != 0 {
			t.Fatalf("preflight signature byte %d was not cleared", index)
		}
	}
	if !preflight.consumed.Load() {
		t.Fatal("cleared preflight was not marked consumed")
	}
}

func TestRESTAuthV2PreflightIsSingleUseAndScrubbed(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)
	body := []byte(`{"durable":true}`)
	proof := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		http.MethodPost, "/v1/prekeys", body,
	)
	preflight, err := verifier.preflight(context.Background(), proof.Headers, proof.Method, proof.RequestTarget)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := preflight.finish(context.Background(), body)
	if err != nil || principal.UserID() != restV2VerifierUserA {
		t.Fatalf("principal=%q err=%v", principal.UserID(), err)
	}
	assertRESTAuthV2PreflightCleared(t, preflight)
	if _, err = preflight.finish(context.Background(), body); err == nil {
		t.Fatal("consumed preflight was accepted twice")
	} else {
		requireRESTAuthV2Failure(t, err, RESTAuthV2InvalidRequest)
	}
	if store.callCount() != 1 {
		t.Fatalf("replay calls=%d, want 1", store.callCount())
	}
	if !bytes.Equal(body, []byte(`{"durable":true}`)) {
		t.Fatal("finish modified caller-owned body bytes")
	}
}

func TestRESTAuthV2PreflightScrubsEveryConsumedFailure(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		finishCtx  context.Context
		finishBody []byte
		want       RESTAuthV2Failure
	}{
		{name: "signature mismatch", finishCtx: context.Background(), finishBody: []byte(`{"changed":true}`), want: RESTAuthV2AuthenticationFailed},
		{name: "nil finish context", finishCtx: nil, finishBody: []byte(`{"signed":true}`), want: RESTAuthV2InvalidRequest},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newRESTV2VerifierFixture(t)
			lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
				restV2VerifierUserA: fixture.publicKey,
			}}
			store := newRESTV2VerifierReplayStore()
			verifier := fixture.verifier(t, lookup, store)
			signedBody := []byte(`{"signed":true}`)
			proof := fixture.request(
				t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
				http.MethodPost, "/v1/prekeys", signedBody,
			)
			preflight, err := verifier.preflight(context.Background(), proof.Headers, proof.Method, proof.RequestTarget)
			if err != nil {
				t.Fatal(err)
			}
			_, err = preflight.finish(testCase.finishCtx, testCase.finishBody)
			requireRESTAuthV2Failure(t, err, testCase.want)
			assertRESTAuthV2PreflightCleared(t, preflight)
			if store.callCount() != 0 {
				t.Fatalf("failed finish reached replay store %d times", store.callCount())
			}
		})
	}
}

func TestRESTAuthV2PreflightConcurrentFinishHasOneWinner(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	verifier := fixture.verifier(t, lookup, store)
	proof := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		http.MethodGet, "/v1/prekeys/identity", nil,
	)
	preflight, err := verifier.preflight(context.Background(), proof.Headers, proof.Method, proof.RequestTarget)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	workers.Add(2)
	for range 2 {
		go func() {
			defer workers.Done()
			<-start
			_, finishErr := preflight.finish(context.Background(), nil)
			results <- finishErr
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	winners, rejected := 0, 0
	for finishErr := range results {
		if finishErr == nil {
			winners++
			continue
		}
		requireRESTAuthV2Failure(t, finishErr, RESTAuthV2InvalidRequest)
		rejected++
	}
	if winners != 1 || rejected != 1 || store.callCount() != 1 {
		t.Fatalf("winners=%d rejected=%d replay=%d", winners, rejected, store.callCount())
	}
	assertRESTAuthV2PreflightCleared(t, preflight)
}

func TestRESTAuthV2FinishRechecksFreshnessBeforeReplayClaim(t *testing.T) {
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	store := newRESTV2VerifierReplayStore()
	current := fixture.now
	verifier, err := newRESTAuthV2VerifierWithClock(fixture.origin, lookup, store, func() time.Time { return current })
	if err != nil {
		t.Fatal(err)
	}
	proof := fixture.request(
		t, restV2VerifierUserA, fixture.privateKey, fixture.now, fixture.nonce,
		http.MethodGet, "/v1/prekeys/identity", nil,
	)
	preflight, err := verifier.preflight(context.Background(), proof.Headers, proof.Method, proof.RequestTarget)
	if err != nil {
		t.Fatal(err)
	}
	current = fixture.now.Add(SignatureMaxSkew + time.Millisecond)
	principal, err := preflight.finish(context.Background(), nil)
	requireRESTAuthV2Failure(t, err, RESTAuthV2TimestampRejected)
	if principal.UserID() != "" || store.callCount() != 0 {
		t.Fatalf("stale staged proof principal=%q replay=%d", principal.UserID(), store.callCount())
	}
	assertRESTAuthV2PreflightCleared(t, preflight)
}

func TestRESTAuthV2FinishBoundsStagedPreflightAgeAcrossClockChanges(t *testing.T) {
	if restAuthV2PreflightMaxAge != SignatureMaxSkew || restAuthV2PreflightMaxAge >= 5*time.Minute {
		t.Fatalf("preflight max age=%s is not aligned with freshness and replay retention", restAuthV2PreflightMaxAge)
	}
	for _, testCase := range []struct {
		name            string
		signedOffset    time.Duration
		finishOffset    time.Duration
		wantFailure     bool
		wantReplayCalls int
	}{
		{
			name:         "held past monotonic max while wall timestamp remains fresh",
			signedOffset: SignatureMaxSkew, finishOffset: restAuthV2PreflightMaxAge + time.Millisecond,
			wantFailure: true,
		},
		{
			name:         "wall clock rollback is fail closed",
			finishOffset: -time.Second,
			wantFailure:  true,
		},
		{
			name:         "exact monotonic max remains inclusive",
			signedOffset: SignatureMaxSkew, finishOffset: restAuthV2PreflightMaxAge,
			wantReplayCalls: 1,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newRESTV2VerifierFixture(t)
			lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
				restV2VerifierUserA: fixture.publicKey,
			}}
			store := newRESTV2VerifierReplayStore()
			current := fixture.now
			verifier, err := newRESTAuthV2VerifierWithClock(fixture.origin, lookup, store, func() time.Time { return current })
			if err != nil {
				t.Fatal(err)
			}
			proof := fixture.request(
				t, restV2VerifierUserA, fixture.privateKey, fixture.now.Add(testCase.signedOffset), fixture.nonce,
				http.MethodGet, "/v1/prekeys/identity", nil,
			)
			preflight, err := verifier.preflight(context.Background(), proof.Headers, proof.Method, proof.RequestTarget)
			if err != nil {
				t.Fatal(err)
			}
			current = fixture.now.Add(testCase.finishOffset)
			principal, err := preflight.finish(context.Background(), nil)
			if testCase.wantFailure {
				requireRESTAuthV2Failure(t, err, RESTAuthV2TimestampRejected)
				if principal.UserID() != "" {
					t.Fatalf("expired staged proof published principal %q", principal.UserID())
				}
			} else if err != nil || principal.UserID() != restV2VerifierUserA {
				t.Fatalf("inclusive staged proof principal=%q err=%v", principal.UserID(), err)
			}
			if store.callCount() != testCase.wantReplayCalls {
				t.Fatalf("replay calls=%d, want %d", store.callCount(), testCase.wantReplayCalls)
			}
			assertRESTAuthV2PreflightCleared(t, preflight)
		})
	}
}

type restV2DeadlineReplayStore struct {
	calls              atomic.Int32
	observed           chan time.Time
	succeedAfterExpiry bool
}

func (store *restV2DeadlineReplayStore) ClaimRESTAuthV2Nonce(
	ctx context.Context,
	_ string,
	_ [RESTAuthV2NonceSize]byte,
) (bool, error) {
	store.calls.Add(1)
	deadline, ok := ctx.Deadline()
	if !ok {
		return false, errors.New("private missing deadline detail")
	}
	store.observed <- deadline
	<-ctx.Done()
	if store.succeedAfterExpiry {
		return true, nil
	}
	return false, errors.New("private replay backend timeout detail")
}

func TestRESTAuthV2HTTPBoundaryRejectsReplaySuccessReturnedAfterDeadline(t *testing.T) {
	store := &restV2DeadlineReplayStore{observed: make(chan time.Time, 1), succeedAfterExpiry: true}
	harness := newRESTV2HTTPHarness(t, store)
	harness.verifier.replayTimeout = 25 * time.Millisecond
	request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) {
		called = true
	})(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if store.calls.Load() != 1 || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("replay calls=%d retry=%q", store.calls.Load(), recorder.Header().Get("Retry-After"))
	}
	select {
	case <-store.observed:
	default:
		t.Fatal("late-success replay store did not observe deadline")
	}
}

func TestRESTAuthV2HTTPBoundaryBoundsReplayClaimAndPublishesNoPrincipal(t *testing.T) {
	store := &restV2DeadlineReplayStore{observed: make(chan time.Time, 1)}
	harness := newRESTV2HTTPHarness(t, store)
	harness.verifier.replayTimeout = 25 * time.Millisecond
	request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	started := time.Now()
	harness.boundary.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) {
		called = true
	})(recorder, request)
	elapsed := time.Since(started)
	payload := requireRESTV2HTTPError(t, recorder, http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if recorder.Header().Get("Retry-After") != "1" || store.calls.Load() != 1 {
		t.Fatalf("retry=%q replay calls=%d", recorder.Header().Get("Retry-After"), store.calls.Load())
	}
	if elapsed < 10*time.Millisecond || elapsed > time.Second {
		t.Fatalf("bounded replay elapsed=%s", elapsed)
	}
	deadline := <-store.observed
	if deadline.Before(started.Add(10*time.Millisecond)) || deadline.After(started.Add(250*time.Millisecond)) {
		t.Fatalf("unexpected replay deadline %s relative to %s", deadline, started)
	}
	if strings.Contains(payload.Error, "backend") || strings.Contains(recorder.Body.String(), "private") {
		t.Fatalf("private replay error leaked: %q", recorder.Body.String())
	}
}

func TestRESTAuthV2HTTPBoundaryMapsVerifierFailuresWithoutPrincipal(t *testing.T) {
	t.Run("stale timestamp", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		proof := harness.fixture.request(
			t, restV2VerifierUserA, harness.fixture.privateKey,
			harness.fixture.now.Add(-SignatureMaxSkew-time.Millisecond), harness.fixture.nonce,
			http.MethodGet, "/v1/prekeys/identity", nil,
		)
		request := harness.request(t, http.MethodGet, proof.RequestTarget, nil, "")
		request.Header[RESTAuthV2TimestampHeader] = proof.Headers.Timestamps
		request.Header[RESTAuthV2SignatureHeader] = proof.Headers.Signatures
		request.Header["X-USER-ID"] = []string{"forged"}
		called := false
		recorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		requireRESTV2HTTPError(t, recorder, http.StatusUnauthorized, publicerr.CodeUnauthenticated)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if harness.lookup.callCount() != 0 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
			t.Fatal("stale proof reached lookup or replay")
		}
	})

	t.Run("signature mismatch", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
		request.Method = http.MethodDelete
		request.Header["x-user-id"] = []string{"forged"}
		called := false
		recorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		requireRESTV2HTTPError(t, recorder, http.StatusUnauthorized, publicerr.CodeUnauthenticated)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if harness.lookup.callCount() != 1 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
			t.Fatal("invalid signature reached replay or skipped lookup")
		}
	})

	t.Run("durable replay", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		policy := RESTAuthV2BodylessHTTPPolicy()
		first := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
		firstRecorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(policy, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })(firstRecorder, first)
		if firstRecorder.Code != http.StatusNoContent {
			t.Fatalf("first request status=%d body=%q", firstRecorder.Code, firstRecorder.Body.String())
		}
		second := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
		second.Header["x-user-id"] = []string{"forged"}
		called := false
		secondRecorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(secondRecorder, second)
		requireRESTV2HTTPError(t, secondRecorder, http.StatusUnauthorized, publicerr.CodeUnauthenticated)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, second, called)
		if harness.replay.(*restV2VerifierReplayStore).callCount() != 2 {
			t.Fatalf("replay calls=%d", harness.replay.(*restV2VerifierReplayStore).callCount())
		}
	})

	t.Run("replay store failure", func(t *testing.T) {
		store := newRESTV2VerifierReplayStore()
		store.err = errors.New("private SQL host and query detail")
		harness := newRESTV2HTTPHarness(t, store)
		request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
		request.Header["x-user-id"] = []string{"forged"}
		called := false
		recorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		payload := requireRESTV2HTTPError(t, recorder, http.StatusServiceUnavailable, publicerr.CodeUnavailable)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if recorder.Header().Get("Retry-After") != "1" || strings.Contains(payload.Error, "SQL") || strings.Contains(recorder.Body.String(), "query") {
			t.Fatalf("unsafe store failure response headers=%v body=%q", recorder.Header(), recorder.Body.String())
		}
	})
}

func TestRESTAuthV2HTTPBoundaryClassifiesKeyLookupBeforeBodyAdmission(t *testing.T) {
	run := func(
		t *testing.T,
		harness *restV2HTTPHarness,
		request *http.Request,
		stream *observedReadCloser,
		wantStatus int,
		wantCode string,
	) {
		t.Helper()
		policy, err := NewRESTAuthV2JSONHTTPPolicy(64)
		if err != nil {
			t.Fatal(err)
		}
		request.Body = stream
		request.Header["x-user-id"] = []string{"forged"}
		called := false
		recorder := httptest.NewRecorder()
		harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		payload := requireRESTV2HTTPError(t, recorder, wantStatus, wantCode)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if stream.reads != 0 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
			t.Fatalf("body reads=%d replay=%d", stream.reads, harness.replay.(*restV2VerifierReplayStore).callCount())
		}
		if strings.Contains(payload.Error, "private") || strings.Contains(recorder.Body.String(), "database") {
			t.Fatalf("private lookup cause leaked: %q", recorder.Body.String())
		}
		wantRetry := ""
		if wantStatus == http.StatusServiceUnavailable {
			wantRetry = "1"
		}
		if recorder.Header().Get("Retry-After") != wantRetry {
			t.Fatalf("Retry-After=%q, want %q", recorder.Header().Get("Retry-After"), wantRetry)
		}
	}

	body := []byte(`{"x":1}`)
	t.Run("explicit unknown account", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		delete(harness.lookup.keys, restV2VerifierUserA)
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		run(t, harness, request, newObservedReadCloser(body), http.StatusUnauthorized, publicerr.CodeUnauthenticated)
	})

	t.Run("database outage", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		harness.lookup.err = errors.New("private database host outage")
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		run(t, harness, request, newObservedReadCloser(body), http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	})

	t.Run("mixed absence and database outage", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		harness.lookup.err = errors.Join(ErrSigningKeyNotFound, errors.New("private database host outage"))
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		run(t, harness, request, newObservedReadCloser(body), http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	})

	t.Run("invalid stored key", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		harness.lookup.keys[restV2VerifierUserA] = make(ed25519.PublicKey, ed25519.PublicKeySize)
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		run(t, harness, request, newObservedReadCloser(body), http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	})

	t.Run("canceled request", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		ctx, cancel := context.WithCancel(request.Context())
		cancel()
		request = request.WithContext(ctx)
		run(t, harness, request, newObservedReadCloser(body), http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	})

	t.Run("lookup deadline", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		blocking := &restV2VerifierBlockingLookup{deadline: make(chan time.Time, 1)}
		harness.verifier.lookup = blocking
		request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
		ctx, cancel := context.WithTimeout(request.Context(), 25*time.Millisecond)
		defer cancel()
		request = request.WithContext(ctx)
		run(t, harness, request, newObservedReadCloser(body), http.StatusServiceUnavailable, publicerr.CodeUnavailable)
		select {
		case <-blocking.deadline:
		default:
			t.Fatal("blocking lookup did not observe a deadline")
		}
	})
}

type trailerInjectingBody struct {
	reader  *bytes.Reader
	request *http.Request
}

func (body *trailerInjectingBody) Read(output []byte) (int, error) {
	count, err := body.reader.Read(output)
	if err == io.EOF {
		body.request.Trailer = http.Header{"X-Late-Trailer": []string{"value"}}
	}
	return count, err
}

func (*trailerInjectingBody) Close() error { return nil }

func TestRESTAuthV2HTTPBoundaryRejectsTrailerMaterializedDuringRead(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy, err := NewRESTAuthV2JSONHTTPPolicy(32)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{}`)
	request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
	request.Body = &trailerInjectingBody{reader: bytes.NewReader(body), request: request}
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusUnsupportedMediaType, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if harness.lookup.callCount() != 1 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
		t.Fatal("late trailer bypassed staged ordering")
	}
}

func TestRESTAuthV2HTTPPolicyAndBoundaryConfigurationFailClosed(t *testing.T) {
	for _, testCase := range []struct {
		media string
		max   int64
	}{
		{media: "", max: 1},
		{media: "Application/JSON", max: 1},
		{media: "application/json; charset=utf-8", max: 1},
		{media: "application/json,application/cbor", max: 1},
		{media: " application/json", max: 1},
		{media: "application", max: 1},
		{media: "application/json", max: 0},
		{media: "application/json", max: RESTAuthV2MaxBodyBytes + 1},
	} {
		if policy, err := NewRESTAuthV2FixedBodyHTTPPolicy(testCase.media, testCase.max); !errors.Is(err, ErrRESTAuthV2HTTPConfiguration) || policy.valid() {
			t.Fatalf("media=%q max=%d policy=%+v err=%v", testCase.media, testCase.max, policy, err)
		}
	}
	if policy, err := NewRESTAuthV2FixedBodyHTTPPolicy("application/octet-stream", 1); err != nil || !policy.valid() {
		t.Fatalf("valid fixed policy=%+v err=%v", policy, err)
	}

	harness := newRESTV2HTTPHarness(t, nil)
	if _, err := NewRESTAuthV2HTTPBoundary(nil, harness.shared); !errors.Is(err, ErrRESTAuthV2HTTPConfiguration) {
		t.Fatalf("nil verifier boundary error=%v", err)
	}
	if _, err := NewRESTAuthV2HTTPBoundary(harness.verifier, nil); !errors.Is(err, ErrRESTAuthV2HTTPConfiguration) {
		t.Fatalf("nil admission boundary error=%v", err)
	}

	request := harness.request(t, http.MethodGet, "/v1/test", nil, "")
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(RESTAuthV2HTTPPolicy{}, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("configuration failure Cache-Control=%q", recorder.Header().Get("Cache-Control"))
	}
}

func TestRESTAuthV2HTTPBoundaryConcurrentReplayHasExactlyOneHandler(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy := RESTAuthV2BodylessHTTPPolicy()
	requests := []*http.Request{
		harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, ""),
		harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, ""),
	}
	recorders := []*httptest.ResponseRecorder{httptest.NewRecorder(), httptest.NewRecorder()}
	start := make(chan struct{})
	var workers sync.WaitGroup
	var downstream atomic.Int32
	handler := harness.boundary.RequireSigned(policy, func(w http.ResponseWriter, request *http.Request) {
		if principal, ok := VerifiedUserID(request.Context()); !ok || principal != restV2VerifierUserA {
			t.Errorf("missing concurrent principal: %q %v", principal, ok)
		}
		downstream.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	workers.Add(len(requests))
	for index := range requests {
		go func(index int) {
			defer workers.Done()
			<-start
			handler(recorders[index], requests[index])
		}(index)
	}
	close(start)
	workers.Wait()
	statuses := map[int]int{}
	for _, recorder := range recorders {
		statuses[recorder.Code]++
	}
	if downstream.Load() != 1 || statuses[http.StatusNoContent] != 1 || statuses[http.StatusUnauthorized] != 1 {
		t.Fatalf("downstream=%d statuses=%v", downstream.Load(), statuses)
	}
	if harness.replay.(*restV2VerifierReplayStore).callCount() != 2 {
		t.Fatalf("replay calls=%d", harness.replay.(*restV2VerifierReplayStore).callCount())
	}
}

func TestRESTAuthV2HTTPBoundaryConsumesNonceBeforeDownstreamFailure(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy := RESTAuthV2BodylessHTTPPolicy()
	first := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	firstCalled := false
	firstRecorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(w http.ResponseWriter, request *http.Request) {
		firstCalled = true
		if principal, ok := VerifiedUserID(request.Context()); !ok || principal != restV2VerifierUserA {
			t.Fatalf("downstream principal=%q ok=%v", principal, ok)
		}
		assertRESTAuthV2ProofHeadersScrubbed(t, request)
		w.WriteHeader(http.StatusInternalServerError)
	})(firstRecorder, first)
	if !firstCalled || firstRecorder.Code != http.StatusInternalServerError {
		t.Fatalf("first called=%v status=%d", firstCalled, firstRecorder.Code)
	}

	second := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	secondCalled := false
	secondRecorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { secondCalled = true })(secondRecorder, second)
	requireRESTV2HTTPError(t, secondRecorder, http.StatusUnauthorized, publicerr.CodeUnauthenticated)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, second, secondCalled)
	if harness.replay.(*restV2VerifierReplayStore).callCount() != 2 {
		t.Fatalf("replay calls=%d, want initial claim plus rejected reuse", harness.replay.(*restV2VerifierReplayStore).callCount())
	}
}
