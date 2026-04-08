package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/config"
)

func TestLoadDefaults(t *testing.T) {
	// Unset all env vars to test defaults
	os.Unsetenv("PORT")
	os.Unsetenv("DATABASE_URL")
	os.Unsetenv("AUTH_CHALLENGE_TTL")
	os.Unsetenv("AUTH_MAX_ATTEMPTS")

	cfg := config.Load()

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
}

func TestLoadFromEnv(t *testing.T) {
	os.Setenv("PORT", "9090")
	os.Setenv("AUTH_CHALLENGE_TTL", "1m")
	os.Setenv("AUTH_MAX_ATTEMPTS", "5")
	defer func() {
		os.Unsetenv("PORT")
		os.Unsetenv("AUTH_CHALLENGE_TTL")
		os.Unsetenv("AUTH_MAX_ATTEMPTS")
	}()

	cfg := config.Load()

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
