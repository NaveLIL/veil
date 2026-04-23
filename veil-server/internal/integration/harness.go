//go:build integration

// Package integration provides a shared test harness for end-to-end tests
// of the veil-server REST surface. It spins up an ephemeral PostgreSQL
// instance via testcontainers-go, applies all migrations, and mounts the
// full HTTP mux (chat + servers + auth handlers, all gated by the real
// authmw signing middleware).
//
// Tests opt in via the `integration` build tag:
//
//	go test -tags=integration ./internal/...
//
// Without the tag, this file is skipped entirely so unit tests still run
// without a Docker daemon.
package integration

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/servers"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"

	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Harness is a fully wired veil-server REST stack backed by an ephemeral
// PostgreSQL container. It is safe to use from one test at a time; create a
// fresh harness per top-level test (subtests are fine to share it provided
// they isolate their own data).
type Harness struct {
	t      *testing.T
	DB     *db.DB
	Server *httptest.Server
	mw     *authmw.Middleware

	pgContainer testcontainers.Container
}

// nullBroadcaster is a stub server.Broadcaster that drops all envelopes.
// REST integration tests do not exercise the WebSocket fan-out path.
type nullBroadcaster struct{}

func (nullBroadcaster) BroadcastToUsers([]string, *pb.Envelope) {}

// New brings up a Postgres container, applies every SQL file in the
// veil-server `migrations/` directory in lexicographic order, and starts an
// httptest server with the production handler chain (chat + servers + auth).
// All resources are cleaned up via t.Cleanup.
func New(t *testing.T) *Harness {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("load migrations: %v", err)
	}

	pgC, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("veil"),
		tcpostgres.WithUsername("veil"),
		tcpostgres.WithPassword("veil"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		_ = pgC.Terminate(context.Background())
	})

	dsn, err := pgC.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("postgres dsn: %v", err)
	}

	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(database.Close)

	for _, m := range migs {
		if _, err := database.Pool.Exec(ctx, m.sql); err != nil {
			t.Fatalf("apply migration %s: %v", m.name, err)
		}
	}

	cfg := &config.Config{
		AuthChallengeTTL:      30 * time.Second,
		AuthMaxAttempts:       3,
		PreKeyLowWarning:      10,
		MaxMessageSize:        64 * 1024,
		MessageBatchLimit:     100,
		MaxConversationFanout: 16,
	}

	authSvc := auth.NewService(database, cfg)
	chatSvc := chat.NewService(database, cfg)
	serversSvc := servers.NewService(database, nullBroadcaster{})

	mw := authmw.New(serversSvc.SigningKeyLookup())
	t.Cleanup(mw.Close)

	mux := http.NewServeMux()
	auth.NewHandler(authSvc, mw, nil).RegisterRoutes(mux)
	chat.NewHandler(chatSvc, mw, nil).RegisterRoutes(mux)
	servers.NewHandler(serversSvc, mw, nil).RegisterRoutes(mux)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &Harness{
		t:           t,
		DB:          database,
		Server:      srv,
		mw:          mw,
		pgContainer: pgC,
	}
}

// User is a registered test user with the secret material needed to sign
// requests on its behalf.
type User struct {
	ID         string
	Username   string
	SigningKey ed25519.PrivateKey
}

// CreateUser inserts a user with a fresh ed25519 signing key and returns
// the credentials needed for SignedRequest.
func (h *Harness) CreateUser(username string) *User {
	h.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		h.t.Fatalf("generate key: %v", err)
	}
	// identity_key column requires a unique 32-byte BYTEA; reuse the public
	// signing key as identity for test purposes (production clients keep them
	// separate but the schema only enforces uniqueness).
	identity := make([]byte, 32)
	if _, err := rand.Read(identity); err != nil {
		h.t.Fatalf("rand identity: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	u, err := h.DB.CreateUser(ctx, identity, []byte(pub), username)
	if err != nil {
		h.t.Fatalf("CreateUser: %v", err)
	}
	return &User{ID: u.ID, Username: username, SigningKey: priv}
}

// Do issues a signed REST request and returns (status, body bytes,
// parsed-JSON-or-nil). path must start with "/".
func (h *Harness) Do(u *User, method, path string, body any) (int, []byte, map[string]any) {
	h.t.Helper()
	var raw []byte
	if body != nil {
		switch b := body.(type) {
		case []byte:
			raw = b
		case string:
			raw = []byte(b)
		default:
			b2, err := json.Marshal(body)
			if err != nil {
				h.t.Fatalf("marshal body: %v", err)
			}
			raw = b2
		}
	}
	tsMs := time.Now().UnixMilli()
	hash := sha256.Sum256(raw)
	canonical := method + "\n" + path + "\n" + strconv.FormatInt(tsMs, 10) + "\n" + hex.EncodeToString(hash[:])
	sig := ed25519.Sign(u.SigningKey, []byte(canonical))

	req, err := http.NewRequest(method, h.Server.URL+path, bytes.NewReader(raw))
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Veil-User", u.ID)
	req.Header.Set("X-Veil-Timestamp", strconv.FormatInt(tsMs, 10))
	req.Header.Set("X-Veil-Signature", base64.StdEncoding.EncodeToString(sig))
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("http do: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var parsed map[string]any
	if len(respBody) > 0 {
		_ = json.Unmarshal(respBody, &parsed)
	}
	return resp.StatusCode, respBody, parsed
}

// DoUnsigned issues a request without the X-Veil-* triplet. Used to assert
// that authmw rejects bare/legacy requests with 401.
func (h *Harness) DoUnsigned(method, path string, body any) (int, []byte) {
	h.t.Helper()
	var raw []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			h.t.Fatalf("marshal: %v", err)
		}
		raw = b
	}
	req, err := http.NewRequest(method, h.Server.URL+path, bytes.NewReader(raw))
	if err != nil {
		h.t.Fatalf("new request: %v", err)
	}
	if raw != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatalf("http do: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody
}

// migration is one ordered SQL file from migrations/.
type migration struct {
	name string
	sql  string
}

func loadMigrations() ([]migration, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, fmt.Errorf("locate repo root: %w", err)
	}
	dir := filepath.Join(root, "migrations")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, migration{name: e.Name(), sql: string(data)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, nil
}

// repoRoot walks upward from the current working directory looking for
// go.mod (the veil-server module root).
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
