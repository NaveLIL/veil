package uploads

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	tusd "github.com/tus/tusd/v2/pkg/handler"
)

// fakeStore is an in-memory implementation of Store used by hook tests.
type fakeStore struct {
	mu              sync.Mutex
	rows            map[string]*db.TusUpload
	downloadAllowed map[string]map[string]bool
	failSum         bool
	failFinish      bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		rows:            map[string]*db.TusUpload{},
		downloadAllowed: map[string]map[string]bool{},
	}
}

func (f *fakeStore) CreateTusUpload(_ context.Context, fileID, userID string, sz int64, backend string, exp time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.rows[fileID]; ok {
		return errors.New("duplicate")
	}
	f.rows[fileID] = &db.TusUpload{
		ID: fileID, UserID: userID, SizeBytes: sz, Backend: backend,
		CreatedAt: time.Now(), ExpiresAt: exp,
	}
	return nil
}
func (f *fakeStore) ReserveTusUpload(_ context.Context, fileID, userID string, sz int64, backend string, exp, _ time.Time, maxBytes int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failSum {
		return errors.New("boom")
	}
	var used int64
	for _, row := range f.rows {
		if row.UserID == userID {
			used += row.SizeBytes
		}
	}
	if sz <= 0 || maxBytes < sz || used > maxBytes-sz {
		return db.ErrTusQuotaExceeded
	}
	if _, exists := f.rows[fileID]; exists {
		return errors.New("duplicate")
	}
	f.rows[fileID] = &db.TusUpload{
		ID: fileID, UserID: userID, SizeBytes: sz, Backend: backend,
		CreatedAt: time.Now(), ExpiresAt: exp,
	}
	return nil
}
func (f *fakeStore) BumpTusReceivedBytes(_ context.Context, fileID string, n int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.rows[fileID]; ok {
		r.ReceivedBytes = n
	}
	return nil
}
func (f *fakeStore) FinishTusUpload(_ context.Context, fileID string, retainUntil time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFinish {
		return errors.New("finish failed")
	}
	r, ok := f.rows[fileID]
	if !ok {
		return errors.New("not found")
	}
	now := time.Now()
	r.FinishedAt = &now
	r.ExpiresAt = retainUntil
	r.ReceivedBytes = r.SizeBytes
	return nil
}
func (f *fakeStore) SumTusBytesInWindow(_ context.Context, userID string, _ time.Time) (int64, error) {
	if f.failSum {
		return 0, errors.New("boom")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var n int64
	for _, r := range f.rows {
		if r.UserID == userID {
			n += r.SizeBytes
		}
	}
	return n, nil
}
func (f *fakeStore) GetTusUpload(_ context.Context, fileID string) (*db.TusUpload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[fileID]
	if r == nil {
		return nil, errors.New("not found")
	}
	return r, nil
}
func (f *fakeStore) CanDownloadTusUpload(_ context.Context, fileID, userID string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.rows[fileID]
	if r == nil {
		return false, errors.New("not found")
	}
	return r.UserID == userID || f.downloadAllowed[fileID][userID], nil
}
func (f *fakeStore) ListExpiredTusUploads(_ context.Context, before time.Time, _ int) ([]db.TusUpload, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]db.TusUpload, 0)
	for _, r := range f.rows {
		if !r.ExpiresAt.After(before) {
			out = append(out, *r)
		}
	}
	return out, nil
}
func (f *fakeStore) DeleteTusUpload(_ context.Context, fileID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.rows, fileID)
	return nil
}

func newHookEvent(userID string, size int64) tusd.HookEvent {
	h := http.Header{}
	if userID != "" {
		h.Set(headerVeilUser, userID)
	}
	return tusd.HookEvent{
		Upload: tusd.FileInfo{Size: size},
		HTTPRequest: tusd.HTTPRequest{
			Method: "POST", URI: "/v1/uploads/files/", Header: h,
		},
	}
}

func newHooks(store Store, cfg Config) *hooks {
	return &hooks{store: store, cfg: cfg, logger: slog.Default()}
}

func defaultCfg() Config {
	return Config{
		LocalDir:             "/tmp/veil-tests",
		BasePath:             "/v1/uploads/files/",
		MaxUploadSize:        10 * 1024 * 1024,
		QuotaWindow:          time.Hour,
		UserDailyQuota:       1024 * 1024,
		RetentionAfterFinish: time.Hour,
		AbortAfterIdle:       10 * time.Minute,
		SweepInterval:        time.Minute,
		TokenTTL:             time.Hour,
	}
}

func TestPreCreate_AcceptsAndAssignsID(t *testing.T) {
	store := newFakeStore()
	h := newHooks(store, defaultCfg())
	_, changes, err := h.PreCreate(newHookEvent("alice", 1024))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if len(changes.ID) != 32 {
		t.Fatalf("want 32-char hex id, got %q", changes.ID)
	}
	if got := store.rows[changes.ID]; got == nil || got.UserID != "alice" || got.SizeBytes != 1024 {
		t.Fatalf("row not persisted: %+v", got)
	}
}

func TestPreCreate_RejectsAnonymous(t *testing.T) {
	h := newHooks(newFakeStore(), defaultCfg())
	_, _, err := h.PreCreate(newHookEvent("", 1024))
	if err == nil {
		t.Fatal("expected unauth error")
	}
}

func TestPreCreate_QuotaGate(t *testing.T) {
	cfg := defaultCfg()
	cfg.UserDailyQuota = 2000
	store := newFakeStore()
	store.rows["existing"] = &db.TusUpload{ID: "existing", UserID: "bob", SizeBytes: 1500}
	h := newHooks(store, cfg)
	// First upload of 600 would push to 2100 > 2000 → reject.
	_, _, err := h.PreCreate(newHookEvent("bob", 600))
	if err == nil {
		t.Fatal("expected quota rejection")
	}
}

func TestPreCreate_QuotaReservationIsAtomic(t *testing.T) {
	cfg := defaultCfg()
	cfg.UserDailyQuota = 1000
	store := newFakeStore()
	h := newHooks(store, cfg)
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := h.PreCreate(newHookEvent("alice", 600))
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	accepted, rejected := 0, 0
	for err := range errs {
		if err == nil {
			accepted++
		} else {
			rejected++
		}
	}
	if accepted != 1 || rejected != 1 {
		t.Fatalf("atomic quota results accepted=%d rejected=%d", accepted, rejected)
	}
}

func TestPreCreate_RejectsOversize(t *testing.T) {
	cfg := defaultCfg()
	cfg.MaxUploadSize = 500
	h := newHooks(newFakeStore(), cfg)
	_, _, err := h.PreCreate(newHookEvent("alice", 600))
	if err == nil {
		t.Fatal("expected per-file limit rejection")
	}
}

func TestPreFinish_PromotesRetention(t *testing.T) {
	cfg := defaultCfg()
	store := newFakeStore()
	h := newHooks(store, cfg)
	_, changes, err := h.PreCreate(newHookEvent("alice", 100))
	if err != nil {
		t.Fatal(err)
	}
	id := changes.ID
	finishEvent := tusd.HookEvent{Upload: tusd.FileInfo{ID: id}}
	_, _ = h.PreFinish(finishEvent)
	row := store.rows[id]
	if row == nil || row.FinishedAt == nil {
		t.Fatal("row not finished")
	}
	if row.ReceivedBytes != row.SizeBytes {
		t.Fatalf("received != size after finish: %d vs %d", row.ReceivedBytes, row.SizeBytes)
	}
}

func TestPreFinish_FailsClosedWhenBookkeepingFails(t *testing.T) {
	store := newFakeStore()
	store.failFinish = true
	h := newHooks(store, defaultCfg())
	_, err := h.PreFinish(tusd.HookEvent{Upload: tusd.FileInfo{ID: strings.Repeat("a", 32)}})
	if err == nil {
		t.Fatal("finish bookkeeping failure was acknowledged")
	}
	var tusErr tusd.Error
	if !errors.As(err, &tusErr) || tusErr.HTTPResponse.StatusCode != http.StatusInternalServerError {
		t.Fatalf("finish error = %#v, want tus 500", err)
	}
}

func TestIssueAndVerifyToken(t *testing.T) {
	key, err := keyFromString("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	tok, exp, err := IssueToken(key, "alice", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Before(time.Now()) {
		t.Fatal("expiry in the past")
	}
	user, err := VerifyToken(key, tok)
	if err != nil || user != "alice" {
		t.Fatalf("verify: user=%q err=%v", user, err)
	}
	// tamper
	if _, err := VerifyToken(key, tok+"x"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func keyFromString(s string) ([]byte, error) {
	if len(s) < MinTokenKeyLen {
		return nil, errors.New("too short")
	}
	return []byte(s), nil
}

// TestServiceTokenEndpoint exercises the /v1/uploads/token issuer
// without a signed-mw wrapper (we pass nil so the endpoint reads
// X-Veil-User directly — the same pattern push uses).
func TestServiceTokenEndpoint(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	svc, err := New(cfg, key, newFakeStore(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)

	req := httptest.NewRequest("POST", "/v1/uploads/token", strings.NewReader(""))
	req.Header.Set("X-Veil-User", "alice")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "\"token\"") {
		t.Fatalf("missing token in body: %s", rec.Body.String())
	}
}

// TestBearerMiddlewareRejectsBadToken ensures the tusd-mounted routes
// 401 when the bearer is invalid (so anonymous PATCH never reaches the
// filestore).
func TestBearerMiddlewareRejectsBadToken(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	svc, _ := New(cfg, key, newFakeStore(), slog.Default())
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)

	u, _ := url.Parse("/v1/uploads/files/")
	req := httptest.NewRequest("POST", u.Path, nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", rec.Code)
	}
}

func TestTusLocationUsesTrustedForwardedOrigin(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	cfg.RespectForwardedHeaders = true
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	svc, err := New(cfg, key, newFakeStore(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)
	token, _, err := IssueToken(key, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway:8080"+cfg.BasePath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Length", "1")
	req.Header.Set("X-Forwarded-Host", "veil.erez.pro")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "https://veil.erez.pro"+cfg.BasePath) {
		t.Fatalf("Location = %q, want trusted public HTTPS origin", location)
	}
	fileID := strings.TrimPrefix(location, "https://veil.erez.pro"+cfg.BasePath)
	if len(fileID) != 32 {
		t.Fatalf("Location file id length = %d, want 32: %q", len(fileID), location)
	}
}

func TestTusLocationIgnoresForwardedOriginWithoutProxyTrust(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	cfg.RespectForwardedHeaders = false
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	svc, err := New(cfg, key, newFakeStore(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)
	token, _, err := IssueToken(key, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://gateway:8080"+cfg.BasePath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Tus-Resumable", "1.0.0")
	req.Header.Set("Upload-Length", "1")
	req.Header.Set("X-Forwarded-Host", "attacker.invalid")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create status = %d, want 201; body=%q", rec.Code, rec.Body.String())
	}
	location := rec.Header().Get("Location")
	if !strings.HasPrefix(location, "http://gateway:8080"+cfg.BasePath) {
		t.Fatalf("Location = %q, want direct request origin", location)
	}
}

func TestTusMutationRequiresUploadOwner(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	store := newFakeStore()
	fileID := strings.Repeat("a", 32)
	store.rows[fileID] = &db.TusUpload{
		ID: fileID, UserID: "alice", SizeBytes: 16,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour),
	}
	svc, err := New(cfg, key, store, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)
	bobToken, _, err := IssueToken(key, "bob", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodHead, http.MethodPatch, http.MethodDelete} {
		req := httptest.NewRequest(method, cfg.BasePath+fileID, nil)
		req.Header.Set("Authorization", "Bearer "+bobToken)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s foreign upload status = %d, want 403", method, rec.Code)
		}
	}
	concat := httptest.NewRequest(http.MethodPost, cfg.BasePath, nil)
	concat.Header.Set("Authorization", "Bearer "+bobToken)
	concat.Header.Set("Tus-Resumable", "1.0.0")
	concat.Header.Set("Upload-Concat", "final;"+cfg.BasePath+fileID)
	concatResponse := httptest.NewRecorder()
	mux.ServeHTTP(concatResponse, concat)
	if concatResponse.Code == http.StatusCreated {
		t.Fatalf("disabled concatenation cloned a foreign upload: status=%d body=%q", concatResponse.Code, concatResponse.Body.String())
	}
	store.mu.Lock()
	rowCount := len(store.rows)
	store.mu.Unlock()
	if rowCount != 1 {
		t.Fatalf("concatenation created an authorization row: count=%d", rowCount)
	}
}

func TestDownloadAllowsAuthorizedRecipientAndRejectsExpiredBlob(t *testing.T) {
	cfg := defaultCfg()
	cfg.LocalDir = t.TempDir()
	key, _ := keyFromString("0123456789abcdef0123456789abcdef")
	store := newFakeStore()
	fileID := strings.Repeat("b", 32)
	now := time.Now()
	store.rows[fileID] = &db.TusUpload{
		ID: fileID, UserID: "alice", SizeBytes: 10, ReceivedBytes: 10,
		CreatedAt: now, FinishedAt: &now, ExpiresAt: now.Add(time.Hour),
	}
	store.downloadAllowed[fileID] = map[string]bool{"bob": true}
	if err := os.WriteFile(cfg.LocalDir+string(os.PathSeparator)+fileID, []byte("ciphertext"), 0o600); err != nil {
		t.Fatal(err)
	}
	svc, err := New(cfg, key, store, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	svc.RegisterRoutes(mux, nil, nil)
	ownerToken, _, err := IssueToken(key, "alice", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tusRequest := httptest.NewRequest(http.MethodGet, cfg.BasePath+fileID, nil)
	tusRequest.Header.Set("Authorization", "Bearer "+ownerToken)
	tusResponse := httptest.NewRecorder()
	mux.ServeHTTP(tusResponse, tusRequest)
	if tusResponse.Code == http.StatusOK || tusResponse.Body.String() == "ciphertext" {
		t.Fatalf("stock tus GET bypassed blob ACL: status=%d body=%q", tusResponse.Code, tusResponse.Body.String())
	}

	request := func(user string) *httptest.ResponseRecorder {
		token, _, issueErr := IssueToken(key, user, time.Hour)
		if issueErr != nil {
			t.Fatal(issueErr)
		}
		req := httptest.NewRequest(http.MethodGet, "/v1/uploads/blob/"+fileID, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	if rec := request("bob"); rec.Code != http.StatusOK || rec.Body.String() != "ciphertext" {
		t.Fatalf("authorized recipient status=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec := request("mallory"); rec.Code != http.StatusForbidden {
		t.Fatalf("unrelated caller status=%d, want 403", rec.Code)
	}
	store.rows[fileID].ExpiresAt = time.Now().Add(-time.Second)
	if rec := request("alice"); rec.Code != http.StatusNotFound {
		t.Fatalf("expired uploader download status=%d, want 404", rec.Code)
	}
}
