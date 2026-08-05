package authmw

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
)

type restV2HTTPHarness struct {
	fixture  restV2VerifierFixture
	lookup   *restV2VerifierLookup
	replay   RESTAuthV2ReplayStore
	shared   *Middleware
	verifier *RESTAuthV2Verifier
	boundary *RESTAuthV2HTTPBoundary
}

func newRESTV2HTTPHarness(t *testing.T, replay RESTAuthV2ReplayStore) *restV2HTTPHarness {
	t.Helper()
	fixture := newRESTV2VerifierFixture(t)
	lookup := &restV2VerifierLookup{keys: map[string]ed25519.PublicKey{
		restV2VerifierUserA: fixture.publicKey,
	}}
	if replay == nil {
		replay = newRESTV2VerifierReplayStore()
	}
	verifier := fixture.verifier(t, lookup, replay)
	shared := New(lookup)
	t.Cleanup(shared.Close)
	boundary, err := NewRESTAuthV2HTTPBoundary(verifier, shared)
	if err != nil {
		t.Fatal(err)
	}
	return &restV2HTTPHarness{
		fixture: fixture, lookup: lookup, replay: replay,
		shared: shared, verifier: verifier, boundary: boundary,
	}
}

func (harness *restV2HTTPHarness) request(
	t *testing.T,
	method, target string,
	body []byte,
	policyMediaType string,
) *http.Request {
	t.Helper()
	proof := harness.fixture.request(
		t,
		restV2VerifierUserA,
		harness.fixture.privateKey,
		harness.fixture.now,
		harness.fixture.nonce,
		method,
		target,
		body,
	)
	request := httptest.NewRequest(method, "https://untrusted-request-host.invalid"+target, nil)
	// httptest preserves an absolute-form input in RequestURI. The boundary
	// signs the server-observed origin-form bytes, so make those bytes explicit.
	request.RequestURI = target
	if body != nil {
		request.Body = io.NopCloser(bytes.NewReader(body))
		request.ContentLength = int64(len(body))
	}
	request.Header[RESTAuthV2VersionHeader] = append([]string(nil), proof.Headers.Versions...)
	request.Header[RESTAuthV2UserHeader] = append([]string(nil), proof.Headers.Users...)
	request.Header[RESTAuthV2TimestampHeader] = append([]string(nil), proof.Headers.Timestamps...)
	request.Header[RESTAuthV2NonceHeader] = append([]string(nil), proof.Headers.Nonces...)
	request.Header[RESTAuthV2SignatureHeader] = append([]string(nil), proof.Headers.Signatures...)
	if policyMediaType != "" {
		request.Header.Set("Content-Type", policyMediaType)
	}
	return request
}

type restV2PublicError struct {
	Code  string `json:"code"`
	Error string `json:"error"`
}

func requireRESTV2HTTPError(t *testing.T, recorder *httptest.ResponseRecorder, status int, code string) restV2PublicError {
	t.Helper()
	if recorder.Code != status {
		t.Fatalf("status=%d body=%q, want %d", recorder.Code, recorder.Body.String(), status)
	}
	var payload restV2PublicError
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode public error: %v body=%q", err, recorder.Body.String())
	}
	if payload.Code != code || payload.Error == "" {
		t.Fatalf("public error=%+v, want code=%q and fixed message", payload, code)
	}
	return payload
}

type observedReadCloser struct {
	reader           *bytes.Reader
	readErr          error
	closeErr         error
	reads            int
	closed           int
	lookup           *restV2VerifierLookup
	lookupBeforeRead bool
}

func newObservedReadCloser(body []byte) *observedReadCloser {
	return &observedReadCloser{reader: bytes.NewReader(body)}
}

func (body *observedReadCloser) Read(output []byte) (int, error) {
	body.reads++
	if body.lookup != nil && body.lookup.callCount() > 0 {
		body.lookupBeforeRead = true
	}
	if body.readErr != nil {
		return 0, body.readErr
	}
	return body.reader.Read(output)
}

func (body *observedReadCloser) Close() error {
	body.closed++
	return body.closeErr
}

func assertRESTV2HTTPFailureDidNotPublishPrincipal(t *testing.T, request *http.Request, called bool) {
	t.Helper()
	if called {
		t.Fatal("failed REST authentication invoked downstream handler")
	}
	if _, ok := VerifiedUserID(request.Context()); ok {
		t.Fatal("failed REST authentication published a principal context")
	}
	if values, present := collectRESTAuthV2HTTPHeader(request.Header, "X-User-ID"); present || len(values) != 0 {
		t.Fatalf("failed REST authentication retained X-User-ID values=%v present=%v", values, present)
	}
	assertRESTAuthV2ProofHeadersScrubbed(t, request)
}

func assertRESTAuthV2ProofHeadersScrubbed(t *testing.T, request *http.Request) {
	t.Helper()
	for _, name := range []string{
		RESTAuthV2VersionHeader,
		RESTAuthV2UserHeader,
		RESTAuthV2TimestampHeader,
		RESTAuthV2NonceHeader,
		RESTAuthV2SignatureHeader,
	} {
		if values, present := collectRESTAuthV2HTTPHeader(request.Header, name); present || len(values) != 0 {
			t.Fatalf("REST v2 proof header %s retained values=%v present=%v", name, values, present)
		}
	}
}

func TestRESTAuthV2HTTPBoundaryUsesRawTargetAndRestoresExactChunkedBody(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy, err := NewRESTAuthV2JSONHTTPPolicy(1024)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("{\n  \"device_id\" : \"0011\"\n}")
	target := "/v1/prekeys?b=%2F&a=1&a=2"
	request := harness.request(t, http.MethodPost, target, body, "application/json")
	stream := newObservedReadCloser(body)
	stream.lookup = harness.lookup
	request.Body = stream
	request.ContentLength = 0
	request.TransferEncoding = []string{"chunked"}
	request.Host = "relayed-node.invalid:443"
	request.Header.Set("X-Forwarded-Host", "another-node.invalid")
	request.Header["x-vEiL-ReSt-aUtH-vErSiOn"] = request.Header[RESTAuthV2VersionHeader]
	delete(request.Header, RESTAuthV2VersionHeader)
	request.Header["x-vEiL-uSeR"] = request.Header[RESTAuthV2UserHeader]
	delete(request.Header, RESTAuthV2UserHeader)
	request.Header["x-vEiL-tImEsTaMp"] = request.Header[RESTAuthV2TimestampHeader]
	delete(request.Header, RESTAuthV2TimestampHeader)
	request.Header["x-vEiL-nOnCe"] = request.Header[RESTAuthV2NonceHeader]
	delete(request.Header, RESTAuthV2NonceHeader)
	request.Header["x-vEiL-sIgNaTuRe"] = request.Header[RESTAuthV2SignatureHeader]
	delete(request.Header, RESTAuthV2SignatureHeader)
	request.Header["x-uSeR-iD"] = []string{"attacker-selected"}

	called := false
	handler := harness.boundary.RequireSigned(policy, func(w http.ResponseWriter, authenticated *http.Request) {
		called = true
		assertRESTAuthV2ProofHeadersScrubbed(t, authenticated)
		principal, ok := VerifiedUserID(authenticated.Context())
		if !ok || principal != restV2VerifierUserA || authenticated.Header.Get("X-User-ID") != restV2VerifierUserA {
			t.Fatalf("principal=%q ok=%v header=%q", principal, ok, authenticated.Header.Get("X-User-ID"))
		}
		if authenticated.RequestURI != target {
			t.Fatalf("RequestURI=%q, want exact %q", authenticated.RequestURI, target)
		}
		restored, readErr := io.ReadAll(authenticated.Body)
		if readErr != nil || !bytes.Equal(restored, body) {
			t.Fatalf("restored body=%q err=%v", restored, readErr)
		}
		if len(harness.shared.bodySlots) != 1 {
			t.Fatalf("shared body slot released before handler returned: %d", len(harness.shared.bodySlots))
		}
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if !called || recorder.Code != http.StatusNoContent || !stream.lookupBeforeRead || stream.closed != 1 {
		t.Fatalf("called=%v status=%d lookup_before_read=%v closed=%d", called, recorder.Code, stream.lookupBeforeRead, stream.closed)
	}
	if len(harness.shared.bodySlots) != 0 {
		t.Fatalf("shared body slot leaked after handler: %d", len(harness.shared.bodySlots))
	}
	if harness.lookup.callCount() != 1 || harness.replay.(*restV2VerifierReplayStore).callCount() != 1 {
		t.Fatalf("lookup=%d replay=%d", harness.lookup.callCount(), harness.replay.(*restV2VerifierReplayStore).callCount())
	}
	if values, present := collectRESTAuthV2HTTPHeader(request.Header, "X-User-ID"); !present || len(values) != 1 || values[0] != restV2VerifierUserA {
		t.Fatalf("authoritative X-User-ID values=%v present=%v", values, present)
	}
	assertRESTAuthV2ProofHeadersScrubbed(t, request)
}

func TestRESTAuthV2AllowedBodyPolicyOwnsExactBoundedMediaTypes(t *testing.T) {
	input := []string{"image/jpeg", "image/png"}
	policy, err := NewRESTAuthV2AllowedBodyHTTPPolicy(input, 2<<20)
	if err != nil || !policy.valid() || !policy.allowsMediaType("image/jpeg") || !policy.allowsMediaType("image/png") {
		t.Fatalf("valid media allowlist rejected: policy=%+v err=%v", policy, err)
	}
	input[0] = "application/octet-stream"
	if policy.allowsMediaType("application/octet-stream") || !policy.allowsMediaType("image/jpeg") {
		t.Fatal("caller mutation changed the owned media allowlist")
	}
	for _, invalid := range [][]string{
		nil,
		{"image/jpeg", "image/jpeg"},
		{"image/jpeg; charset=binary"},
		{"Image/JPEG"},
		{"image/jpeg", "image/png", "image/webp", "image/gif", "image/avif", "image/bmp", "image/tiff", "image/svg+xml", "application/octet-stream"},
	} {
		if candidate, candidateErr := NewRESTAuthV2AllowedBodyHTTPPolicy(invalid, 2<<20); candidateErr == nil || candidate.valid() {
			t.Fatalf("invalid media allowlist accepted: %#v", invalid)
		}
	}
}

func TestRESTAuthV2OptionalJSONPolicyKeepsAbsentAndJSONBodiesUnambiguous(t *testing.T) {
	policy, err := NewRESTAuthV2OptionalJSONHTTPPolicy(64)
	if err != nil || !policy.valid() {
		t.Fatalf("valid optional JSON policy rejected: policy=%+v err=%v", policy, err)
	}

	testCases := []struct {
		name        string
		body        string
		contentType string
		wantErr     bool
	}{
		{name: "absent"},
		{name: "exact JSON", body: `{}`, contentType: "application/json"},
		{name: "unlabelled body", body: `{}`, wantErr: true},
		{name: "wrong media", body: `{}`, contentType: "text/plain", wantErr: true},
		{name: "metadata without body", contentType: "application/json", wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			var body io.Reader
			if testCase.body != "" {
				body = strings.NewReader(testCase.body)
			}
			request := httptest.NewRequest(http.MethodDelete, "/v1/servers/s/members/u", body)
			if testCase.contentType != "" {
				request.Header.Set("Content-Type", testCase.contentType)
			}
			err := validateRESTAuthV2HTTPMetadata(request, policy)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("metadata error=%v, want error=%v", err, testCase.wantErr)
			}
		})
	}
}

func TestRESTAuthV2HTTPBoundaryNeverReconstructsTargetFromURLOrHost(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy := RESTAuthV2BodylessHTTPPolicy()
	signedTarget := "/v1/prekeys/identity?device=7&device=8"
	request := harness.request(t, http.MethodGet, signedTarget, nil, "")
	request.URL.Path = "/different/parsed/path"
	request.URL.RawQuery = "normalized=1"
	request.Host = "host-must-not-enter-v2.invalid"
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})(recorder, request)
	if !called || recorder.Code != http.StatusNoContent {
		t.Fatalf("raw target proof status=%d called=%v body=%q", recorder.Code, called, recorder.Body.String())
	}
}

func TestRESTAuthV2HTTPBoundaryRejectsHeaderAliasesBeforeLookupOrBodyRead(t *testing.T) {
	mutations := map[string]func(*http.Request){
		"duplicate version across case variants": func(request *http.Request) {
			request.Header["x-veil-rest-auth-version"] = []string{"2"}
		},
		"comma version": func(request *http.Request) {
			request.Header[RESTAuthV2VersionHeader] = []string{"2, 2"}
		},
		"nil version field": func(request *http.Request) {
			request.Header[RESTAuthV2VersionHeader] = nil
		},
		"duplicate user": func(request *http.Request) {
			request.Header["x-veil-user"] = []string{restV2VerifierUserA}
		},
		"duplicate timestamp": func(request *http.Request) {
			request.Header[RESTAuthV2TimestampHeader] = append(request.Header[RESTAuthV2TimestampHeader], request.Header.Get(RESTAuthV2TimestampHeader))
		},
		"comma nonce": func(request *http.Request) {
			request.Header[RESTAuthV2NonceHeader][0] += ",x"
		},
		"duplicate signature": func(request *http.Request) {
			request.Header["x-veil-signature"] = append([]string(nil), request.Header[RESTAuthV2SignatureHeader]...)
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			harness := newRESTV2HTTPHarness(t, nil)
			policy, err := NewRESTAuthV2JSONHTTPPolicy(1024)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(`{"x":1}`)
			request := harness.request(t, http.MethodPost, "/v1/prekeys", body, "application/json")
			stream := newObservedReadCloser(body)
			request.Body = stream
			request.Header["x-user-id"] = []string{"forged"}
			mutate(request)
			called := false
			recorder := httptest.NewRecorder()
			harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
			requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
			assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
			if harness.lookup.callCount() != 0 || stream.reads != 0 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
				t.Fatalf("lookup=%d reads=%d replay=%d", harness.lookup.callCount(), stream.reads, harness.replay.(*restV2VerifierReplayStore).callCount())
			}
		})
	}
}

func TestRESTAuthV2HTTPBoundaryEnforcesBodyAndRepresentationPolicies(t *testing.T) {
	tests := []struct {
		name       string
		bodyless   bool
		body       []byte
		configure  func(*http.Request)
		wantStatus int
		wantCode   string
		wantLookup int
		wantReads  bool
	}{
		{
			name: "required content type missing", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.Header.Del("Content-Type") },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "required content type parameter", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.Header.Set("Content-Type", "application/json; charset=utf-8") },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "duplicate content type", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.Header["content-type"] = []string{"application/json"} },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "content encoding", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.Header.Set("Content-Encoding", "identity") },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "declared trailer", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.Trailer = http.Header{"X-Checksum": nil} },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "unsupported transfer coding", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.TransferEncoding = []string{"gzip"} },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "non-exact chunked transfer coding", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.TransferEncoding = []string{"Chunked"} },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "multiple transfer codings", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.TransferEncoding = []string{"gzip", "chunked"} },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "invalid negative content length", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.ContentLength = -2 },
			wantStatus: http.StatusBadRequest, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "declared oversized", body: []byte(`{}`),
			configure:  func(request *http.Request) { request.ContentLength = 9 },
			wantStatus: http.StatusRequestEntityTooLarge, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "required body empty", body: []byte{},
			wantStatus: http.StatusBadRequest, wantCode: publicerr.CodeInvalidRequest,
			wantLookup: 1, wantReads: true,
		},
		{
			name: "bodyless content type", bodyless: true,
			configure:  func(request *http.Request) { request.Header.Set("Content-Type", "application/json") },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
		},
		{
			name: "bodyless hidden bytes at content length zero", bodyless: true, body: []byte("x"),
			configure:  func(request *http.Request) { request.ContentLength = 0 },
			wantStatus: http.StatusUnsupportedMediaType, wantCode: publicerr.CodeInvalidRequest,
			wantLookup: 1, wantReads: true,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newRESTV2HTTPHarness(t, nil)
			policy, err := NewRESTAuthV2JSONHTTPPolicy(8)
			mediaType := "application/json"
			method := http.MethodPost
			if testCase.bodyless {
				policy = RESTAuthV2BodylessHTTPPolicy()
				mediaType = ""
				method = http.MethodGet
			}
			if err != nil {
				t.Fatal(err)
			}
			request := harness.request(t, method, "/v1/test", testCase.body, mediaType)
			stream := newObservedReadCloser(testCase.body)
			request.Body = stream
			if testCase.configure != nil {
				testCase.configure(request)
			}
			request.Header["x-user-id"] = []string{"forged-a"}
			request.Header["X-USER-ID"] = []string{"forged-b"}
			called := false
			recorder := httptest.NewRecorder()
			harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
			requireRESTV2HTTPError(t, recorder, testCase.wantStatus, testCase.wantCode)
			assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
			if harness.lookup.callCount() != testCase.wantLookup {
				t.Fatalf("lookup calls=%d, want %d", harness.lookup.callCount(), testCase.wantLookup)
			}
			if (stream.reads > 0) != testCase.wantReads {
				t.Fatalf("body reads=%d, want reads=%v", stream.reads, testCase.wantReads)
			}
			if harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
				t.Fatal("representation failure reached replay store")
			}
		})
	}
}

func TestRESTAuthV2HTTPBoundaryBoundsUnknownLengthBeforeReplay(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy, err := NewRESTAuthV2JSONHTTPPolicy(4)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("12345")
	request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
	stream := newObservedReadCloser(body)
	stream.lookup = harness.lookup
	request.Body = stream
	request.ContentLength = -1
	request.TransferEncoding = []string{"chunked"}
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusRequestEntityTooLarge, publicerr.CodeInvalidRequest)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if harness.lookup.callCount() != 1 || !stream.lookupBeforeRead || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
		t.Fatalf("lookup=%d lookup_before_read=%v replay=%d", harness.lookup.callCount(), stream.lookupBeforeRead, harness.replay.(*restV2VerifierReplayStore).callCount())
	}
	if stream.closed != 1 {
		t.Fatalf("oversized body close count=%d", stream.closed)
	}
}

func TestRESTAuthV2HTTPBoundaryFailsClosedOnReadAndCloseErrors(t *testing.T) {
	for _, testCase := range []struct {
		name     string
		readErr  error
		closeErr error
	}{
		{name: "read failure", readErr: errors.New("synthetic body read detail")},
		{name: "close failure", closeErr: errors.New("synthetic body close detail")},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			harness := newRESTV2HTTPHarness(t, nil)
			policy, err := NewRESTAuthV2JSONHTTPPolicy(32)
			if err != nil {
				t.Fatal(err)
			}
			body := []byte(`{}`)
			request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
			stream := newObservedReadCloser(body)
			stream.readErr, stream.closeErr, stream.lookup = testCase.readErr, testCase.closeErr, harness.lookup
			request.Body = stream
			request.Header["x-user-id"] = []string{"forged"}
			called := false
			recorder := httptest.NewRecorder()
			harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
			payload := requireRESTV2HTTPError(t, recorder, http.StatusBadRequest, publicerr.CodeInvalidRequest)
			if strings.Contains(payload.Error, "synthetic") || strings.Contains(recorder.Body.String(), "detail") {
				t.Fatalf("private I/O error leaked: %q", recorder.Body.String())
			}
			assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
			if !stream.lookupBeforeRead || stream.closed != 1 || harness.replay.(*restV2VerifierReplayStore).callCount() != 0 {
				t.Fatalf("lookup_before_read=%v closes=%d replay=%d", stream.lookupBeforeRead, stream.closed, harness.replay.(*restV2VerifierReplayStore).callCount())
			}
		})
	}
}

func TestRESTAuthV2HTTPBoundarySharesAdmissionAndRetainsSlotThroughHandler(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	policy, err := NewRESTAuthV2JSONHTTPPolicy(64)
	if err != nil {
		t.Fatal(err)
	}
	for range cap(harness.shared.bodySlots) {
		harness.shared.bodySlots <- struct{}{}
	}
	body := []byte(`{}`)
	request := harness.request(t, http.MethodPost, "/v1/test", body, "application/json")
	stream := newObservedReadCloser(body)
	stream.lookup = harness.lookup
	request.Body = stream
	called := false
	recorder := httptest.NewRecorder()
	harness.boundary.RequireSigned(policy, func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
	requireRESTV2HTTPError(t, recorder, http.StatusTooManyRequests, publicerr.CodeRateLimited)
	assertRESTV2HTTPFailureDidNotPublishPrincipal(t, request, called)
	if !stream.lookupBeforeRead && stream.reads != 0 {
		t.Fatal("unexpected body read ordering")
	}
	if harness.lookup.callCount() != 1 || stream.reads != 0 || recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("lookup=%d reads=%d retry=%q", harness.lookup.callCount(), stream.reads, recorder.Header().Get("Retry-After"))
	}
	for range cap(harness.shared.bodySlots) {
		<-harness.shared.bodySlots
	}
}
