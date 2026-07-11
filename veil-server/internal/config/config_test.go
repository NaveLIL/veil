package config_test

import (
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/config"
)

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("VEIL_ALLOW_INSECURE_DEV_DATABASE", "")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load succeeded without DATABASE_URL or explicit dev opt-in")
	}
}

func TestLoadDefaultsWithExplicitDevOptIn(t *testing.T) {
	t.Setenv("PORT", "")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("VEIL_ALLOW_INSECURE_DEV_DATABASE", "1")
	t.Setenv("AUTH_CHALLENGE_TTL", "")
	t.Setenv("AUTH_MAX_ATTEMPTS", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != "8080" {
		t.Errorf("default Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.AuthChallengeTTL != 30*time.Second {
		t.Errorf("default AuthChallengeTTL = %v, want 30s", cfg.AuthChallengeTTL)
	}
	if cfg.AuthMaxAttempts != 3 {
		t.Errorf("default AuthMaxAttempts = %d, want 3", cfg.AuthMaxAttempts)
	}
	if cfg.MaxMessageSize != 64*1024 {
		t.Errorf("default MaxMessageSize = %d, want %d", cfg.MaxMessageSize, 64*1024)
	}
	if cfg.DatabaseURL != "postgres://veil:veil@localhost:5432/veil?sslmode=disable" {
		t.Errorf("unexpected explicit dev DatabaseURL %q", cfg.DatabaseURL)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://app:secret@db.internal:5432/veil_prod?sslmode=require")
	t.Setenv("VEIL_ALLOW_INSECURE_DEV_DATABASE", "")
	t.Setenv("PORT", "9090")
	t.Setenv("AUTH_CHALLENGE_TTL", "1m")
	t.Setenv("AUTH_MAX_ATTEMPTS", "5")

	cfg, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Port != "9090" {
		t.Errorf("Port = %q, want %q", cfg.Port, "9090")
	}
	if cfg.AuthChallengeTTL != time.Minute {
		t.Errorf("AuthChallengeTTL = %v, want 1m", cfg.AuthChallengeTTL)
	}
	if cfg.AuthMaxAttempts != 5 {
		t.Errorf("AuthMaxAttempts = %d, want 5", cfg.AuthMaxAttempts)
	}
}

func TestLoadRejectsMalformedDatabaseURL(t *testing.T) {
	t.Setenv("VEIL_ALLOW_INSECURE_DEV_DATABASE", "")
	for _, value := range []string{
		"mysql://db.internal/veil",
		"postgres:///veil",
		"postgres://db.internal",
		" postgres://db.internal/veil",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("DATABASE_URL", value)
			if _, err := config.Load(); err == nil {
				t.Fatalf("Load accepted malformed DATABASE_URL %q", value)
			}
		})
	}
}
