package profiles

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/jackc/pgx/v5"
)

const testUserID = "5a636f65-3ab4-48b9-84b8-f4996ab73c88"

var testTimestampOffset atomic.Int64

type fakeStore struct {
	profile        *Profile
	getErr         error
	updateErr      error
	updatedUserID  string
	updatedVersion int64
	updatedName    *string
	updatedAbout   string
}

func (s *fakeStore) GetProfile(context.Context, string) (*Profile, error) {
	return s.profile, s.getErr
}

func (s *fakeStore) UpdateProfile(_ context.Context, userID string, version int64, name *string, about string) (*Profile, error) {
	s.updatedUserID = userID
	s.updatedVersion = version
	s.updatedName = name
	s.updatedAbout = about
	return s.profile, s.updateErr
}

func requestWithPrincipal(t *testing.T, privateKey ed25519.PrivateKey, method, target, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	timestamp := strconv.FormatInt(time.Now().UnixMilli()+testTimestampOffset.Add(1), 10)
	canonical, err := authmw.CanonicalRequest(method, request.Host, request.URL.RequestURI(), timestamp, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Veil-User", testUserID)
	request.Header.Set("X-Veil-Timestamp", timestamp)
	request.Header.Set("X-Veil-Signature", base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical)))
	return request
}

func newSignedMux(t *testing.T, store Store) (*http.ServeMux, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	middleware := authmw.New(authmw.LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return publicKey, nil
	}))
	t.Cleanup(middleware.Close)
	handler := NewHandler(store, middleware, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux, privateKey
}

func TestRoutesRequireVerifiedPrincipalEvenWithoutMiddleware(t *testing.T) {
	handler := NewHandler(&fakeStore{}, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/users/"+testUserID+"/profile", nil),
		httptest.NewRequest(http.MethodPut, "/v1/users/me/profile", strings.NewReader(`{"expected_version":0,"about":""}`)),
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d, want 401", request.Method, request.URL.Path, response.Code)
		}
	}
}

func TestUpdateUsesVerifiedPrincipalAndNormalizesText(t *testing.T) {
	store := &fakeStore{profile: &Profile{
		UserID: testUserID, Username: "alice", About: "Café", ProfileVersion: 8,
		ProfileUpdatedAt: time.Unix(1, 0).UTC(),
	}}
	mux, privateKey := newSignedMux(t, store)

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, requestWithPrincipal(t, privateKey, http.MethodPut, "/v1/users/me/profile",
		`{"expected_version":7,"display_name":"  Alice  ","about":" Cafe\u0301 "}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.updatedUserID != testUserID || store.updatedVersion != 7 || store.updatedName == nil || *store.updatedName != "Alice" || store.updatedAbout != "Café" {
		t.Fatalf("unexpected update: %#v", store)
	}
}

func TestUpdateRejectsUnknownFieldsTrailingJSONAndStaleVersion(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		storeError error
		wantStatus int
		wantCode   string
	}{
		{name: "unknown", body: `{"expected_version":0,"about":"","avatar_url":"https://example.test/x"}`, wantStatus: 400, wantCode: "invalid_profile"},
		{name: "missing version", body: `{"about":"safe"}`, wantStatus: 400, wantCode: "invalid_profile"},
		{name: "trailing", body: `{"expected_version":0,"about":""}{}`, wantStatus: 400, wantCode: "invalid_profile"},
		{name: "bidi", body: `{"expected_version":0,"about":"safe\u202eevil"}`, wantStatus: 400, wantCode: "invalid_profile_text"},
		{name: "conflict", body: `{"expected_version":4,"about":"safe"}`, storeError: ErrVersionConflict, wantStatus: 409, wantCode: "profile_version_conflict"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{updateErr: test.storeError}
			mux, privateKey := newSignedMux(t, store)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, requestWithPrincipal(t, privateKey, http.MethodPut, "/v1/users/me/profile", test.body))
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var detail map[string]any
			if err := json.Unmarshal(response.Body.Bytes(), &detail); err != nil {
				t.Fatal(err)
			}
			if detail["code"] != test.wantCode {
				t.Fatalf("code=%v, want %s", detail["code"], test.wantCode)
			}
		})
	}
}

func TestGetMapsMissingAndPrivateStoreErrorsToBoundedResponses(t *testing.T) {
	for _, test := range []struct {
		storeErr   error
		wantStatus int
	}{
		{storeErr: pgx.ErrNoRows, wantStatus: http.StatusNotFound},
		{storeErr: errors.New("secret database path and account id"), wantStatus: http.StatusInternalServerError},
	} {
		store := &fakeStore{getErr: test.storeErr}
		mux, privateKey := newSignedMux(t, store)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, requestWithPrincipal(t, privateKey, http.MethodGet, "/v1/users/"+testUserID+"/profile", ""))
		if response.Code != test.wantStatus || strings.Contains(response.Body.String(), "secret") {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
}
