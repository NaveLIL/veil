package authmw

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRESTAuthDispatcherAcceptsOnlyExactV2(t *testing.T) {
	harness := newRESTV2HTTPHarness(t, nil)
	dispatcher, err := NewRESTAuthVersionDispatcher(harness.boundary)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
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
	})

	for _, name := range []string{"missing version", "v1 version", "duplicate version"} {
		t.Run(name, func(t *testing.T) {
			request := harness.request(t, http.MethodGet, "/v1/prekeys/identity", nil, "")
			switch name {
			case "missing version":
				deleteRESTAuthV2HTTPHeader(request.Header, RESTAuthV2VersionHeader)
			case "v1 version":
				request.Header.Set(RESTAuthV2VersionHeader, "1")
			case "duplicate version":
				request.Header[RESTAuthV2VersionHeader] = []string{"2", "2"}
			}
			called := false
			recorder := httptest.NewRecorder()
			dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) { called = true })(recorder, request)
			if called || recorder.Code != http.StatusBadRequest {
				t.Fatalf("called=%v status=%d body=%q", called, recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRESTAuthDispatcherRejectsInvalidConstructionAndUse(t *testing.T) {
	if _, err := NewRESTAuthVersionDispatcher(nil); err == nil {
		t.Fatal("nil boundary accepted")
	}
	var dispatcher *RESTAuthVersionDispatcher
	recorder := httptest.NewRecorder()
	dispatcher.RequireSigned(RESTAuthV2BodylessHTTPPolicy(), func(http.ResponseWriter, *http.Request) {
		t.Fatal("nil dispatcher reached downstream")
	})(recorder, httptest.NewRequest(http.MethodGet, "/v1/prekeys/identity", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d, want 503", recorder.Code)
	}
}
