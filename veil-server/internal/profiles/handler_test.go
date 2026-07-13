package profiles

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
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
	recipients     []string
	recipientsErr  error
	avatar         *AvatarAsset
}

type countingReader struct{ reads int }

func (r *countingReader) Read([]byte) (int, error) {
	r.reads++
	return 0, io.EOF
}

func (s *fakeStore) UpdateAvatar(_ context.Context, userID string, version int64, asset *AvatarAsset) (*Profile, error) {
	s.updatedUserID = userID
	s.updatedVersion = version
	s.avatar = asset
	return s.profile, s.updateErr
}

func (s *fakeStore) GetAvatar(context.Context, string) (*AvatarAsset, error) {
	return s.avatar, s.getErr
}

func (s *fakeStore) ProfileUpdateRecipients(context.Context, string) ([]string, error) {
	return s.recipients, s.recipientsErr
}

type broadcastCall struct {
	recipients []string
	envelope   *pb.Envelope
}

type fakeBroadcaster struct {
	calls []broadcastCall
}

func (b *fakeBroadcaster) BroadcastToUsers(recipients []string, envelope *pb.Envelope) {
	b.calls = append(b.calls, broadcastCall{recipients: append([]string(nil), recipients...), envelope: envelope})
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

func newSignedMux(t *testing.T, store Store, broadcasters ...Broadcaster) (*http.ServeMux, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	middleware := authmw.New(authmw.LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return publicKey, nil
	}))
	t.Cleanup(middleware.Close)
	var broadcaster Broadcaster
	if len(broadcasters) > 0 {
		broadcaster = broadcasters[0]
	}
	handler := NewHandler(store, middleware, nil, nil, broadcaster)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	return mux, privateKey
}

func TestRoutesRequireVerifiedPrincipalEvenWithoutMiddleware(t *testing.T) {
	handler := NewHandler(&fakeStore{}, nil, nil, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/v1/users/"+testUserID+"/profile", nil),
		httptest.NewRequest(http.MethodPut, "/v1/users/me/profile", strings.NewReader(`{"expected_version":0,"about":""}`)),
		httptest.NewRequest(http.MethodPut, "/v1/users/me/profile/avatar?expected_version=0", strings.NewReader("image")),
		httptest.NewRequest(http.MethodDelete, "/v1/users/me/profile/avatar?expected_version=0", nil),
		httptest.NewRequest(http.MethodGet, "/v1/profile-avatars/550e8400-e29b-41d4-a716-446655440000", nil),
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status=%d, want 401", request.Method, request.URL.Path, response.Code)
		}
	}
}

func TestAvatarAdmissionRejectsBeforeDownstreamBodyReads(t *testing.T) {
	handler := NewHandler(&fakeStore{}, nil, nil, nil, nil)
	for range cap(handler.avatarAdmission) {
		handler.avatarAdmission <- struct{}{}
	}
	defer func() {
		for range cap(handler.avatarAdmission) {
			<-handler.avatarAdmission
		}
	}()
	reader := &countingReader{}
	request := httptest.NewRequest(http.MethodPut, "/v1/users/me/profile/avatar?expected_version=0", reader)
	response := httptest.NewRecorder()
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || reader.reads != 0 {
		t.Fatalf("status=%d body reads=%d, want 429 before body read", response.Code, reader.reads)
	}
}

func TestUpdateUsesVerifiedPrincipalAndNormalizesText(t *testing.T) {
	store := &fakeStore{profile: &Profile{
		UserID: testUserID, Username: "alice", About: "Café", ProfileVersion: 8,
		ProfileUpdatedAt: time.Unix(1, 0).UTC(),
	}, recipients: []string{testUserID, "550e8400-e29b-41d4-a716-446655440000"}}
	broadcaster := &fakeBroadcaster{}
	mux, privateKey := newSignedMux(t, store, broadcaster)

	response := httptest.NewRecorder()
	mux.ServeHTTP(response, requestWithPrincipal(t, privateKey, http.MethodPut, "/v1/users/me/profile",
		`{"expected_version":7,"display_name":"  Alice  ","about":" Cafe\u0301 "}`))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if store.updatedUserID != testUserID || store.updatedVersion != 7 || store.updatedName == nil || *store.updatedName != "Alice" || store.updatedAbout != "Café" {
		t.Fatalf("unexpected update: %#v", store)
	}
	if len(broadcaster.calls) != 1 {
		t.Fatalf("broadcast calls=%d, want 1", len(broadcaster.calls))
	}
	call := broadcaster.calls[0]
	if len(call.recipients) != 2 || call.envelope.GetProfileUpdated().GetUserId() != testUserID || call.envelope.GetProfileUpdated().GetProfileVersion() != 8 {
		t.Fatalf("unexpected profile event: recipients=%v envelope=%v", call.recipients, call.envelope)
	}
}

func TestUpdateAudienceFailureDoesNotRewriteCommittedSuccess(t *testing.T) {
	store := &fakeStore{
		profile: &Profile{
			UserID: testUserID, Username: "alice", ProfileVersion: 2,
			ProfileUpdatedAt: time.Unix(1, 0).UTC(),
		},
		recipientsErr: errors.New("private relationship query detail"),
	}
	broadcaster := &fakeBroadcaster{}
	mux, privateKey := newSignedMux(t, store, broadcaster)
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, requestWithPrincipal(t, privateKey, http.MethodPut, "/v1/users/me/profile",
		`{"expected_version":1,"about":"safe"}`))
	if response.Code != http.StatusOK || len(broadcaster.calls) != 0 {
		t.Fatalf("status=%d broadcasts=%d body=%s", response.Code, len(broadcaster.calls), response.Body.String())
	}
}

func TestProfileMutationLimiterRunsAfterVerifiedPrincipal(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	middleware := authmw.New(authmw.LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return publicKey, nil
	}))
	t.Cleanup(middleware.Close)
	mutationLimiter := authmw.NewRateLimit(1, time.Hour)
	t.Cleanup(mutationLimiter.Close)
	store := &fakeStore{profile: &Profile{
		UserID: testUserID, Username: "alice", ProfileVersion: 1,
		ProfileUpdatedAt: time.Unix(1, 0).UTC(),
	}}
	handler := NewHandler(store, middleware, nil, mutationLimiter, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	first := httptest.NewRecorder()
	mux.ServeHTTP(first, requestWithPrincipal(t, privateKey, http.MethodPut,
		"/v1/users/me/profile", `{"expected_version":0,"about":"first"}`))
	if first.Code != http.StatusOK {
		t.Fatalf("first mutation status=%d body=%s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	mux.ServeHTTP(second, requestWithPrincipal(t, privateKey, http.MethodPut,
		"/v1/users/me/profile", `{"expected_version":0,"about":"second"}`))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second mutation status=%d body=%s", second.Code, second.Body.String())
	}

	read := httptest.NewRecorder()
	mux.ServeHTTP(read, requestWithPrincipal(t, privateKey, http.MethodGet,
		"/v1/users/"+testUserID+"/profile", ""))
	if read.Code != http.StatusOK {
		t.Fatalf("read was incorrectly charged to mutation limiter: status=%d body=%s", read.Code, read.Body.String())
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

func TestAvatarRoutesRequireSignedExactVersionAndServeOnlyNormalizedBytes(t *testing.T) {
	assetID := "550e8400-e29b-41d4-a716-446655440000"
	digest := strings.Repeat("ab", 32)
	contentType := "image/jpeg"
	store := &fakeStore{profile: &Profile{
		UserID: testUserID, Username: "alice", ProfileVersion: 4,
		ProfileUpdatedAt: time.Unix(1, 0).UTC(), AvatarAssetID: &assetID,
		AvatarDigest: &digest, AvatarContentType: &contentType,
	}}
	mux, privateKey := newSignedMux(t, store)
	pngBytes := encodedAvatar(t, "png", 600, 400)
	request := requestWithPrincipal(t, privateKey, http.MethodPut,
		"/v1/users/me/profile/avatar?expected_version=3", string(pngBytes))
	request.Header.Set("Content-Type", "image/png")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK || store.updatedVersion != 3 || store.avatar == nil {
		t.Fatalf("status=%d version=%d avatar=%v body=%s", response.Code, store.updatedVersion, store.avatar != nil, response.Body.String())
	}
	if store.avatar.ContentType != "image/jpeg" || store.avatar.Width != 512 || len(store.avatar.Data) > maxAvatarOutputBytes {
		t.Fatalf("avatar was not normalized: %#v", store.avatar)
	}

	store.avatar.ID = assetID
	get := requestWithPrincipal(t, privateKey, http.MethodGet, "/v1/profile-avatars/"+assetID, "")
	getResponse := httptest.NewRecorder()
	mux.ServeHTTP(getResponse, get)
	if getResponse.Code != http.StatusOK || getResponse.Header().Get("Content-Type") != "image/jpeg" ||
		getResponse.Header().Get("Cache-Control") != "private, no-store" || !bytes.Equal(getResponse.Body.Bytes(), store.avatar.Data) {
		t.Fatalf("unexpected avatar response: status=%d headers=%v bytes=%d", getResponse.Code, getResponse.Header(), getResponse.Body.Len())
	}
}

func TestAvatarUploadQuotaReturnsBoundedRetryableError(t *testing.T) {
	store := &fakeStore{updateErr: ErrAvatarUploadQuota}
	mux, privateKey := newSignedMux(t, store)
	pngBytes := encodedAvatar(t, "png", 8, 8)
	request := requestWithPrincipal(t, privateKey, http.MethodPut,
		"/v1/users/me/profile/avatar?expected_version=3", string(pngBytes))
	request.Header.Set("Content-Type", "image/png")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") == "" ||
		!strings.Contains(response.Body.String(), "avatar_upload_quota") {
		t.Fatalf("unexpected quota response: status=%d headers=%v body=%s", response.Code, response.Header(), response.Body.String())
	}
}
