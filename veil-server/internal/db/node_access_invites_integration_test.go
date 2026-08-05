//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"golang.org/x/crypto/curve25519"
)

func TestNodeAccessInviteLifecycle(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	invites, err := database.CreateNodeAccessInvites(ctx, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(invites) != 3 {
		t.Fatalf("unexpected generated invite count: %d", len(invites))
	}
	if len(invites[0].Token) != db.NodeAccessInviteTokenSize || bytes.Equal(invites[0].Token, invites[1].Token) {
		t.Fatalf("unexpected generated invite token shape: first_token_bytes=%d", len(invites[0].Token))
	}
	firstHash := sha256.Sum256(invites[0].Token)
	var storedHash []byte
	if err := database.Pool.QueryRow(ctx,
		`SELECT token_hash FROM node_access_invites WHERE token_hash = $1`, firstHash[:],
	).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(storedHash, firstHash[:]) || bytes.Equal(storedHash, invites[0].Token) {
		t.Fatal("database did not retain only the invite digest")
	}

	account := newAuthIdentity(t)
	if _, err := database.CreateUserWithNodeAccessInvite(
		ctx, invites[0].Token, account.identityPublic, account.signingPublic, "invited",
	); err != nil {
		t.Fatalf("valid invited registration: %v", err)
	}
	for name, token := range map[string][]byte{
		"reused":    invites[0].Token,
		"malformed": []byte("short"),
	} {
		identity := newAuthIdentity(t)
		if _, err := database.CreateUserWithNodeAccessInvite(
			ctx, token, identity.identityPublic, identity.signingPublic, name,
		); !errors.Is(err, db.ErrNodeAccessInviteInvalid) {
			t.Fatalf("%s invite error=%v, want ErrNodeAccessInviteInvalid", name, err)
		}
	}

	// An expired digest is indistinguishable from malformed and reused tokens.
	expiredToken := bytes.Repeat([]byte{0x73}, db.NodeAccessInviteTokenSize)
	expiredHash := sha256.Sum256(expiredToken)
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO node_access_invites (token_hash, created_at, expires_at)
		 VALUES ($1, now() - interval '2 hours', now() - interval '1 hour')`,
		expiredHash[:],
	); err != nil {
		t.Fatal(err)
	}
	expiredIdentity := newAuthIdentity(t)
	if _, err := database.CreateUserWithNodeAccessInvite(
		ctx, expiredToken, expiredIdentity.identityPublic, expiredIdentity.signingPublic, "expired",
	); !errors.Is(err, db.ErrNodeAccessInviteInvalid) {
		t.Fatalf("expired invite error=%v, want ErrNodeAccessInviteInvalid", err)
	}

	// Use the second invite in a deliberate account-insert failure. The token
	// must remain usable because account creation and consumption share one tx.
	existing := newAuthIdentity(t)
	if _, err := database.CreateUser(ctx, existing.identityPublic, existing.signingPublic, "existing"); err != nil {
		t.Fatal(err)
	}
	conflicting := newAuthIdentity(t)
	if _, err := database.CreateUserWithNodeAccessInvite(
		ctx, invites[1].Token, conflicting.identityPublic, existing.signingPublic, "conflict",
	); err == nil {
		t.Fatal("duplicate signing key unexpectedly created an invited account")
	}
	replacement := newAuthIdentity(t)
	if _, err := database.CreateUserWithNodeAccessInvite(
		ctx, invites[1].Token, replacement.identityPublic, replacement.signingPublic, "replacement",
	); err != nil {
		t.Fatalf("invite was consumed by rolled-back account insert: %v", err)
	}
}

func TestNodeAccessInviteConcurrentConsumeCreatesOneAccount(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	invites, err := database.CreateNodeAccessInvites(ctx, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	identities := []authIdentity{newAuthIdentity(t), newAuthIdentity(t)}
	start := make(chan struct{})
	errorsOut := make(chan error, len(identities))
	var wg sync.WaitGroup
	for i := range identities {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			_, err := database.CreateUserWithNodeAccessInvite(
				ctx, invites[0].Token,
				identities[index].identityPublic, identities[index].signingPublic,
				"concurrent",
			)
			errorsOut <- err
		}(i)
	}
	close(start)
	wg.Wait()
	close(errorsOut)

	var succeeded, rejected int
	for err := range errorsOut {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, db.ErrNodeAccessInviteInvalid):
			rejected++
		default:
			t.Fatalf("unexpected concurrent registration error: %v", err)
		}
	}
	if succeeded != 1 || rejected != 1 {
		t.Fatalf("concurrent results: succeeded=%d rejected=%d", succeeded, rejected)
	}
}

type authIdentity struct {
	identityPrivate []byte
	identityPublic  []byte
	signingPublic   ed25519.PublicKey
	signingPrivate  ed25519.PrivateKey
	deviceID        []byte
}

func newAuthIdentity(t *testing.T) authIdentity {
	t.Helper()
	identityPrivate := make([]byte, 32)
	if _, err := rand.Read(identityPrivate); err != nil {
		t.Fatal(err)
	}
	identityPublic, err := curve25519.X25519(identityPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := make([]byte, 16)
	if _, err := rand.Read(deviceID); err != nil {
		t.Fatal(err)
	}
	return authIdentity{identityPrivate, identityPublic, signingPublic, signingPrivate, deviceID}
}

func newInviteIntegrationDB(t *testing.T) *db.DB {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	container, err := tcpostgres.Run(ctx,
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
		t.Fatalf("start PostgreSQL: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)

	migrationDir := filepath.Join("..", "..", "migrations")
	entries, err := os.ReadDir(migrationDir)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			continue
		}
		sql, err := os.ReadFile(filepath.Join(migrationDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.Pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("apply migration %s: %v", entry.Name(), err)
		}
	}
	return database
}
