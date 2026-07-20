package config_test

import (
	"os"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/config"
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
	t.Setenv("VEIL_ALLOW_REGISTRATION", "")

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
	if cfg.AllowRegistration {
		t.Error("default AllowRegistration = true, want fail-closed false")
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
	t.Setenv("VEIL_PUBLIC_ORIGIN", "not-a-canonical-origin")
	t.Setenv("PORT", "9090")
	t.Setenv("AUTH_CHALLENGE_TTL", "1m")
	t.Setenv("AUTH_MAX_ATTEMPTS", "5")
	t.Setenv("VEIL_ALLOW_REGISTRATION", "true")

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
	if !cfg.AllowRegistration {
		t.Error("AllowRegistration = false, want true")
	}
	if !cfg.PublicOrigin.IsZero() {
		t.Errorf("PublicOrigin = %q, want empty for shared Load", cfg.PublicOrigin.String())
	}
}

func TestLoadGatewayRequiresPublicOrigin(t *testing.T) {
	setGatewayDatabaseEnv(t)

	t.Run("missing", func(t *testing.T) {
		t.Setenv("VEIL_PUBLIC_ORIGIN", "temporary")
		if err := os.Unsetenv("VEIL_PUBLIC_ORIGIN"); err != nil {
			t.Fatal(err)
		}
		if _, err := config.LoadGateway(); err == nil {
			t.Fatal("LoadGateway succeeded without VEIL_PUBLIC_ORIGIN")
		}
	})

	for name, value := range map[string]string{
		"empty":               "",
		"leading whitespace":  " https://veil.example:443",
		"trailing whitespace": "https://veil.example:443 ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("VEIL_PUBLIC_ORIGIN", value)
			if _, err := config.LoadGateway(); err == nil {
				t.Fatalf("LoadGateway accepted VEIL_PUBLIC_ORIGIN %q", value)
			}
		})
	}
}

func TestLoadGatewayAcceptsExactPublicOrigin(t *testing.T) {
	setGatewayDatabaseEnv(t)

	for _, value := range []string{
		"https://veil.example:443",
		"http://localhost:80",
		"http://127.0.0.1:8080",
		"http://[::1]:3000",
	} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("VEIL_PUBLIC_ORIGIN", value)
			cfg, err := config.LoadGateway()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.PublicOrigin.IsZero() || cfg.PublicOrigin.String() != value {
				t.Errorf("PublicOrigin = %q, want exact configured value %q", cfg.PublicOrigin.String(), value)
			}
		})
	}
}

func TestLoadGatewayRejectsNonCanonicalPublicOrigin(t *testing.T) {
	setGatewayDatabaseEnv(t)

	for name, value := range map[string]string{
		"implicit port":     "https://veil.example",
		"uppercase host":    "https://Veil.example:443",
		"path":              "https://veil.example:443/",
		"query":             "https://veil.example:443?source=test",
		"userinfo":          "https://user@veil.example:443",
		"leading zero port": "https://veil.example:0443",
		"non-loopback http": "http://veil.example:80",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("VEIL_PUBLIC_ORIGIN", value)
			if _, err := config.LoadGateway(); err == nil {
				t.Fatalf("LoadGateway accepted non-canonical VEIL_PUBLIC_ORIGIN %q", value)
			}
		})
	}
}

func setGatewayDatabaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgresql://app:secret@db.internal:5432/veil_prod?sslmode=require")
	t.Setenv("VEIL_ALLOW_INSECURE_DEV_DATABASE", "")
	t.Setenv("VEIL_ALLOW_REGISTRATION", "")
}

func TestLoadRejectsMalformedRegistrationFlag(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgresql://app:secret@db.internal:5432/veil_prod?sslmode=require")
	t.Setenv("VEIL_ALLOW_REGISTRATION", "sometimes")
	if _, err := config.Load(); err == nil {
		t.Fatal("Load accepted malformed VEIL_ALLOW_REGISTRATION")
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
