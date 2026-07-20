package authmw

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

func newRESTAuthV2OnlyDispatcher(t *testing.T, harness *restV2HTTPHarness) *RESTAuthVersionDispatcher {
	t.Helper()
	dispatcher, err := newRESTAuthVersionDispatcherWithClock(
		RESTAuthDispatchV2Only,
		nil,
		harness.boundary,
		RESTAuthPreviewCompatibility{},
		func() time.Time { return harness.fixture.now },
	)
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func newRESTAuthPreviewDispatcher(
	t *testing.T,
	harness *restV2HTTPHarness,
	now func() time.Time,
	expiresAt time.Time,
) *RESTAuthVersionDispatcher {
	t.Helper()
	dispatcher, err := newRESTAuthVersionDispatcherWithClock(
		RESTAuthDispatchPreviewDual,
		harness.shared,
		harness.boundary,
		RESTAuthPreviewCompatibility{Owner: "android-preview", ExpiresAt: expiresAt},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	return dispatcher
}

func legacyRESTAuthRequest(
	t *testing.T,
	fixture restV2VerifierFixture,
	method, target string,
) *http.Request {
	t.Helper()
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)
	authority := strings.TrimPrefix(restV2VerifierNodeA, "https://")
	message, err := CanonicalRequest(method, authority, target, timestamp, nil)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(fixture.privateKey, message)
	request := httptest.NewRequest(method, restV2VerifierNodeA+target, nil)
	request.Header.Set(RESTAuthV2UserHeader, restV2VerifierUserA)
	request.Header.Set(RESTAuthV2TimestampHeader, timestamp)
	request.Header.Set(RESTAuthV2SignatureHeader, base64.StdEncoding.EncodeToString(signature))
	return request
}

func TestRESTAuthVersionDispatcherV2OnlySelectsOnlyExactV2(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	dispatcher := newRESTAuthV2OnlyDispatcher(t, harness)
	request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	called := false
	recorder := httptest.NewRecorder()
	dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(w http.ResponseWriter, authenticated *http.Request) {
		called = true
		principal, ok := VerifiedUserID(authenticated.Context())
		if !ok || principal != restV2VerifierUserA {
			t.Fatalf("principal=%q ok=%v", principal, ok)
		}
		w.WriteHeader(http.StatusNoContent)
	})(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("called=%v status=%d body=%q", called, recorder.Code, recorder.Body.String())
	}
}

func TestRESTAuthVersionDispatcherRejectsAmbiguousSelectorsBeforeEitherVerifier(t *testing.T) {
	mutations := map[string]func(*http.Request){
		"missing version": func(request *http.Request) {
			deleteRESTAuthV2HTTPHeader(request.Header, RESTAuthV2VersionHeader)
			deleteRESTAuthV2HTTPHeader(request.Header, RESTAuthV2NonceHeader)
		},
		"nonce without version": func(request *http.Request) {
			deleteRESTAuthV2HTTPHeader(request.Header, RESTAuthV2VersionHeader)
		},
		"unknown version": func(request *http.Request) {
			request.Header[RESTAuthV2VersionHeader] = []string{"3"}
		},
		"comma version": func(request *http.Request) {
			request.Header[RESTAuthV2VersionHeader] = []string{"2, 2"}
		},
		"duplicate version": func(request *http.Request) {
			request.Header["x-veil-rest-auth-version"] = []string{"2"}
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			harness := newRESTV2HTTPHarness(t, nil)
			dispatcher := newRESTAuthV2OnlyDispatcher(t, harness)
			request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
			request.Header["x-user-id"] = []string{"forged-a"}
			request.Header["X-USER-ID"] = []string{"forged-b"}
			mutate(request)
			called := false
			recorder := httptest.NewRecorder()
			dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
			requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
			assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
			if harness.lookup.callCount() != 0 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
				t.Fatalf("selector reached lookup/replay: %d/%d", harness.lookup.callCount(), harness.replay.(*restV2VerifierReplayStore).callCount())
			}
		})
	}
}

func TestRESTAuthVersionDispatcherFinitePreviewSelectsV1OrV2Once(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	dispatcher := newRESTAuthPreviewDispatcher(
		t, harness, func() time.Time { return harness.fixture.now }, harness.fixture.now.Add(time.Hour),
	)
	handlerCalls := 0
	handler := dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(w http.ResponseWriter, request *http.Request) {
		handlerCalls++
		principal, ok := VerifiedUserID(request.Context())
		if !ok || principal != restV2VerifierUserA || request.Header.Get("X-User-ID") != restV2VerifierUserA {
			t.Fatalf("principal=%q ok=%v header=%q", principal, ok, request.Header.Get("X-User-ID"))
		}
		w.WriteHeader(http.StatusNoContent)
	})

	legacyRequest := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	legacyRecorder := httptest.NewRecorder()
	handler(legacyRecorder, legacyRequest)
	if legacyRecorder.Code != http.StatusNoContent {
		t.Fatalf("legacy status=%d body=%q", legacyRecorder.Code, legacyRecorder.Body.String())
	}

	v2Request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
	v2Recorder := httptest.NewRecorder()
	handler(v2Recorder, v2Request)
	if v2Recorder.Code != http.StatusNoContent {
		t.Fatalf("v2 status=%d body=%q", v2Recorder.Code, v2Recorder.Body.String())
	}
	if handlerCalls != 2 || harness.lookup.callCount() != 2 || harness.replay.(*restV2VerifierReplayStore).callCount() != 1 {
		t.Fatalf("handlers=%d lookup=%d replay=%d", handlerCalls, harness.lookup.callCount(), harness.replay.(*restV2VerifierReplayStore).callCount())
	}
}

func TestRESTAuthVersionDispatcherLegacyCompatibilityPreservesV1RepresentationSemantics(t *testing.T) {
	// This deliberately demonstrates the activation gate documented on the
	// dispatcher: a v2 bodyless policy would reject Content-Type, while the
	// absent-version compatibility branch preserves today's v1 behavior. Do
	// not claim route-policy parity or activate PreviewDual without resolving
	// each legacy route's body/media semantics.
	harness := newRESTV2HTTPHarness(t, nil)
	dispatcher := newRESTAuthPreviewDispatcher(
		t, harness, func() time.Time { return harness.fixture.now }, harness.fixture.now.Add(time.Hour),
	)
	request := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	request.Header.Set("Content-Type", "application/json")
	called := false
	recorder := httptest.NewRecorder()
	dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(w http.ResponseWriter, authenticated *http.Request) {
		called = true
		if authenticated.Header.Get(RESTAuthV2UserHeader) != restV2VerifierUserA ||
			authenticated.Header.Get(RESTAuthV2SignatureHeader) == "" {
			t.Fatal("legacy proof headers were removed before the v1 handler returned")
		}
		w.WriteHeader(http.StatusNoContent)
	})(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("legacy compatibility semantics changed: called=%v status=%d body=%q", called, recorder.Code, recorder.Body.String())
	}
	assertRESTAuthV2ProofHeadersScrubbed(t, request)
}

func TestRESTAuthVersionDispatcherNeverFallsBackFromSelectedV2(t *testing.T) {
	t.Run("legacy proof labeled v2", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		dispatcher := newRESTAuthPreviewDispatcher(
			t, harness, func() time.Time { return harness.fixture.now }, harness.fixture.now.Add(time.Hour),
		)
		request := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
		request.Header.Set(RESTAuthV2VersionHeader, RESTAuthV2ProtocolVersion)
		request.Header["x-user-id"] = []string{"forged"}
		called := false
		recorder := httptest.NewRecorder()
		dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if harness.lookup.callCount() != 0 {
			t.Fatalf("legacy verifier was attempted: lookup=%d", harness.lookup.callCount())
		}
	})

	t.Run("invalid v2 proof", func(t *testing.T) {
		harness := newRESTV2HTTPHarness(t, nil)
		dispatcher := newRESTAuthPreviewDispatcher(
			t, harness, func() time.Time { return harness.fixture.now }, harness.fixture.now.Add(time.Hour),
		)
		request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
		request.Method = http.MethodDelete
		called := false
		recorder := httptest.NewRecorder()
		dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
		requireRESTV2HTTPError(t, recorder, http.StatusUnauthorized, publicerr.CodeUnauthenticated)
		assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
		if harness.lookup.callCount() != 1 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
			t.Fatalf("selected v2 retried another verifier: lookup=%d replay=%d", harness.lookup.callCount(), harness.replay.(*restV2VerifierReplayStore).callCount())
		}
	})
}

func TestRESTAuthVersionDispatcherRejectsLegacyHeaderAliasesBeforeV1(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	dispatcher := newRESTAuthPreviewDispatcher(
		t, harness, func() time.Time { return harness.fixture.now }, harness.fixture.now.Add(time.Hour),
	)
	request := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	request.Header["x-veil-user"] = []string{restV2VerifierUserA}
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if harness.lookup.callCount() != 0 {
		t.Fatalf("ambiguous legacy headers reached lookup %d times", harness.lookup.callCount())
	}
}

func TestRESTAuthVersionDispatcherRuntimeExpiryAndZeroClockFailClosed(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	current := harness.fixture.now
	expiresAt := current.Add(time.Hour)
	dispatcher := newRESTAuthPreviewDispatcher(t, harness, func() time.Time { return current }, expiresAt)
	handlerCalls := 0
	handler := dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(w http.ResponseWriter, _ *http.Request) {
		handlerCalls++
		w.WriteHeader(http.StatusNoContent)
	})

	first := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	firstRecorder := httptest.NewRecorder()
	handler(firstRecorder, first)
	if firstRecorder.Code != http.StatusNoContent || handlerCalls != 1 {
		t.Fatalf("active preview status=%d calls=%d", firstRecorder.Code, handlerCalls)
	}

	current = expiresAt
	expiredRequest := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	expiredRequest.Header["x-user-id"] = []string{"forged"}
	expiredRecorder := httptest.NewRecorder()
	handler(expiredRecorder, expiredRequest)
	requireRESTV2HTTPError(t, expiredRecorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, expiredRequest, handlerCalls != 1)
	if !dispatcher.legacyClosed.Load() {
		t.Fatal("observed expiry did not latch the legacy branch closed")
	}

	// Simulate a wall-clock rollback after expiry was already observed. The
	// process must never revive its v1 compatibility branch.
	current = harness.fixture.now.Add(time.Minute)
	rollbackRequest := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	rollbackRecorder := httptest.NewRecorder()
	handler(rollbackRecorder, rollbackRequest)
	requireRESTV2HTTPError(t, rollbackRecorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, rollbackRequest, handlerCalls != 1)
	if handlerCalls != 1 {
		t.Fatalf("expired preview invoked handler %d times", handlerCalls)
	}
}

func TestRESTAuthVersionDispatcherRuntimeZeroClockLatchesClosed(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	current := harness.fixture.now
	dispatcher := newRESTAuthPreviewDispatcher(
		t, harness, func() time.Time { return current }, current.Add(time.Hour),
	)
	called := false
	handler := dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })
	current = time.Time{}
	request := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if !dispatcher.legacyClosed.Load() {
		t.Fatal("zero runtime clock did not latch legacy closed")
	}
	current = harness.fixture.now.Add(time.Minute)
	retry := legacyRESTAuthRequest(t, harness.fixture, http.MethodGet, "/v1/prekeys/identity")
	retryRecorder := httptest.NewRecorder()
	handler(retryRecorder, retry)
	requireRESTV2HTTPError(t, retryRecorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, retry, called)
}

func TestRESTAuthVersionDispatcherConfigurationIsExplicit(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	otherAdmission := New(harness.lookup)
	t.Cleanup(otherAdmission.Close)
	now := harness.fixture.now
	validCompatibility := RESTAuthPreviewCompatibility{Owner: "android-preview", ExpiresAt: now.Add(time.Hour)}
	tests := []struct {
		name          string
		mode          RESTAuthDispatchMode
		legacy        *Middleware
		boundary      *RESTAuthV2HTTPBoundary
		compatibility RESTAuthPreviewCompatibility
		clock         func() time.Time
	}{
		{name: "zero mode", boundary: harness.boundary, clock: func() time.Time { return now }},
		{name: "v2 only with legacy", mode: RESTAuthDispatchV2Only, legacy: harness.shared, boundary: harness.boundary, clock: func() time.Time { return now }},
		{name: "v2 only with compatibility", mode: RESTAuthDispatchV2Only, boundary: harness.boundary, compatibility: validCompatibility, clock: func() time.Time { return now }},
		{name: "dual missing legacy", mode: RESTAuthDispatchPreviewDual, boundary: harness.boundary, compatibility: validCompatibility, clock: func() time.Time { return now }},
		{name: "dual mismatched admission", mode: RESTAuthDispatchPreviewDual, legacy: otherAdmission, boundary: harness.boundary, compatibility: validCompatibility, clock: func() time.Time { return now }},
		{name: "dual empty owner", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: RESTAuthPreviewCompatibility{ExpiresAt: now.Add(time.Hour)}, clock: func() time.Time { return now }},
		{name: "dual unsafe owner", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: RESTAuthPreviewCompatibility{Owner: "preview owner", ExpiresAt: now.Add(time.Hour)}, clock: func() time.Time { return now }},
		{name: "dual zero expiry", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: RESTAuthPreviewCompatibility{Owner: "preview"}, clock: func() time.Time { return now }},
		{name: "dual expired", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: RESTAuthPreviewCompatibility{Owner: "preview", ExpiresAt: now}, clock: func() time.Time { return now }},
		{name: "dual lifetime over hard max", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: RESTAuthPreviewCompatibility{Owner: "preview", ExpiresAt: now.Add(restAuthPreviewMaxCompatibilityLifetime + time.Nanosecond)}, clock: func() time.Time { return now }},
		{name: "dual zero clock", mode: RESTAuthDispatchPreviewDual, legacy: harness.shared, boundary: harness.boundary, compatibility: validCompatibility, clock: func() time.Time { return time.Time{} }},
		{name: "nil boundary", mode: RESTAuthDispatchV2Only, clock: func() time.Time { return now }},
		{name: "nil clock", mode: RESTAuthDispatchV2Only, boundary: harness.boundary},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			dispatcher, err := newRESTAuthVersionDispatcherWithClock(
				testCase.mode, testCase.legacy, testCase.boundary, testCase.compatibility, testCase.clock,
			)
			if dispatcher != nil || !errors.Is(err, ErrRESTAuthDispatcherConfiguration) {
				t.Fatalf("dispatcher=%v err=%v", dispatcher, err)
			}
		})
	}
	if dispatcher, err := newRESTAuthVersionDispatcherWithClock(
		RESTAuthDispatchPreviewDual,
		harness.shared,
		harness.boundary,
		RESTAuthPreviewCompatibility{Owner: "preview", ExpiresAt: now.Add(restAuthPreviewMaxCompatibilityLifetime)},
		func() time.Time { return now },
	); err != nil || dispatcher == nil {
		t.Fatalf("exact maximum compatibility lifetime rejected: dispatcher=%v err=%v", dispatcher, err)
	}

	var nilDispatcher *RESTAuthVersionDispatcher
	request := harness.request(t, http.MethodGet, "/v1/test", nil, "")
	request.Header["x-user-id"] = []string{"forged"}
	called := false
	recorder := httptest.NewRecorder()
	nilDispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusServiceUnavailable, publicerr.CodeUnavailable)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
}

func completeLegacyMiddlewareForDispatcherTest(lookup UserKeyLookup) *Middleware {
	return &Middleware{
		lookup: lookup,
		keys:   newSigningKeyCache(),
		nonces: newNonceCache(),
		bodyIngress: &RateLimit{
			buckets: make(map[string]*tokenBucket), capacity: 1,
			refill: time.Second, idleTTL: time.Minute, stop: make(chan struct{}),
		},
		bodySlots:            make(chan struct{}, 1),
		bodyClientSlotsInUse: make(map[string]uint8),
		stop:                 make(chan struct{}),
	}
}

func TestRESTAuthVersionDispatcherRejectsUnsafeLegacyRuntime(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	now := harness.fixture.now
	compatibility := RESTAuthPreviewCompatibility{Owner: "android-preview", ExpiresAt: now.Add(time.Hour)}
	assertRejected := func(t *testing.T, legacy *Middleware) {
		t.Helper()
		boundary := &RESTAuthV2HTTPBoundary{verifier: harness.verifier, admission: legacy}
		dispatcher, err := newRESTAuthVersionDispatcherWithClock(
			RESTAuthDispatchPreviewDual, legacy, boundary, compatibility, func() time.Time { return now },
		)
		if dispatcher != nil || !errors.Is(err, ErrRESTAuthDispatcherConfiguration) {
			t.Fatalf("unsafe legacy accepted: dispatcher=%v err=%v", dispatcher, err)
		}
	}

	t.Run("New nil lookup", func(t *testing.T) {
		legacy := New(nil)
		t.Cleanup(legacy.Close)
		assertRejected(t, legacy)
	})
	t.Run("New typed nil lookup", func(t *testing.T) {
		var typedNilLookup *restV2VerifierLookup
		legacy := New(typedNilLookup)
		t.Cleanup(legacy.Close)
		assertRejected(t, legacy)
	})

	mutations := map[string]func(*Middleware){
		"nil lookup":              func(value *Middleware) { value.lookup = nil },
		"nil key cache":           func(value *Middleware) { value.keys = nil },
		"nil key cache entries":   func(value *Middleware) { value.keys.entries = nil },
		"nil nonce cache":         func(value *Middleware) { value.nonces = nil },
		"nil nonce entries":       func(value *Middleware) { value.nonces.entries = nil },
		"zero nonce capacity":     func(value *Middleware) { value.nonces.maxEntries = 0 },
		"nil body ingress":        func(value *Middleware) { value.bodyIngress = nil },
		"nil ingress buckets":     func(value *Middleware) { value.bodyIngress.buckets = nil },
		"zero ingress capacity":   func(value *Middleware) { value.bodyIngress.capacity = 0 },
		"zero ingress refill":     func(value *Middleware) { value.bodyIngress.refill = 0 },
		"zero ingress idle ttl":   func(value *Middleware) { value.bodyIngress.idleTTL = 0 },
		"nil ingress stop":        func(value *Middleware) { value.bodyIngress.stop = nil },
		"closed ingress stop":     func(value *Middleware) { close(value.bodyIngress.stop) },
		"nil body slots":          func(value *Middleware) { value.bodySlots = nil },
		"unbuffered body slots":   func(value *Middleware) { value.bodySlots = make(chan struct{}) },
		"nil per-client body map": func(value *Middleware) { value.bodyClientSlotsInUse = nil },
		"nil middleware stop":     func(value *Middleware) { value.stop = nil },
		"closed middleware stop":  func(value *Middleware) { close(value.stop) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			legacy := completeLegacyMiddlewareForDispatcherTest(harness.lookup)
			mutate(legacy)
			assertRejected(t, legacy)
		})
	}
}
