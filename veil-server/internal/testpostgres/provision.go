//go:build integration

// Package testpostgres provisions isolated PostgreSQL integration databases.
package testpostgres

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Provision uses testcontainers by default. TEST_DATABASE_URL optionally points
// to a dedicated local PostgreSQL admin database when Docker is unavailable.
// Every invocation creates a new database and drops only that generated name;
// migrations and fixture cleanup never run in the supplied database.
func Provision(t *testing.T, ctx context.Context) string {
	t.Helper()
	if dsn := os.Getenv("TEST_DATABASE_URL"); dsn != "" {
		endpoint, err := url.Parse(dsn)
		if err != nil || (endpoint.Scheme != "postgres" && endpoint.Scheme != "postgresql") ||
			(endpoint.Hostname() != "localhost" && endpoint.Hostname() != "127.0.0.1" && endpoint.Hostname() != "::1") {
			t.Fatal("TEST_DATABASE_URL must be a dedicated local PostgreSQL URL")
		}
		admin, err := pgx.Connect(ctx, dsn)
		if err != nil {
			t.Fatalf("connect test PostgreSQL admin: %v", err)
		}
		name := "veil_integration_" + uuid.NewString()
		identifier := pgx.Identifier{name}.Sanitize()
		if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier); err != nil {
			_ = admin.Close(ctx)
			t.Fatalf("create isolated integration database: %v", err)
		}
		t.Cleanup(func() {
			cleanup, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			defer admin.Close(cleanup)
			if _, err := admin.Exec(cleanup, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
				t.Errorf("drop isolated integration database: %v", err)
			}
		})
		endpoint.Path = "/" + name
		endpoint.RawPath = ""
		query := endpoint.Query()
		query.Del("database")
		query.Del("dbname")
		endpoint.RawQuery = query.Encode()
		return endpoint.String()
	}
	container, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("veil"), tcpostgres.WithUsername("veil"), tcpostgres.WithPassword("veil"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second)))
	if err != nil {
		t.Fatalf("start PostgreSQL test container: %v", err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := container.Terminate(cleanup); err != nil {
			t.Errorf("terminate PostgreSQL test container: %v", err)
		}
	})
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("PostgreSQL test container DSN: %v", err)
	}
	return dsn
}
