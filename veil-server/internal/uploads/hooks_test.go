package uploads
import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/db"
	tusd "github.com/tus/tusd/v2/pkg/handler"
)

// fakeStore is an in-memory implementation of Store used by hook tests.
type fakeStore struct {
	mu      sync.Mutex
	rows    map[string]*db.TusUpload
	failSum bool
}

func newFakeStore() *fakeStore { return &fakeStore{rows: map[string]*db.TusUpload{}} }

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
		QuotaWindow:           time.Hour,
		UserDailyQuota:        1024 * 1024,
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
