package config_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
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
	t.Setenv("VEIL_ALLOW_LEGACY_WS_V2", "")

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
	if cfg.AllowLegacyWSV2 {
		t.Error("default AllowLegacyWSV2 = true, want fail-closed false")
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
	t.Setenv("VEIL_ALLOW_LEGACY_WS_V2", "true")

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
	if !cfg.AllowLegacyWSV2 {
		t.Error("AllowLegacyWSV2 = false, want true")
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

func TestLoadGatewayIdentityTransparencyIsExplicitAndStrict(t *testing.T) {
	setGatewayDatabaseEnv(t)
	t.Setenv("VEIL_PUBLIC_ORIGIN", "https://veil.example:443")
	canonicalSeed := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))

	t.Run("disabled by default", func(t *testing.T) {
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "")
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", "")
		cfg, err := config.LoadGateway()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.IdentityTransparency != nil {
			t.Fatal("identity transparency unexpectedly enabled")
		}
	})

	t.Run("requires explicit enable", func(t *testing.T) {
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "false")
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", canonicalSeed)
		if _, err := config.LoadGateway(); err == nil {
			t.Fatal("seed was accepted while identity transparency was disabled")
		}
	})

	t.Run("requires seed", func(t *testing.T) {
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "true")
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", "")
		if _, err := config.LoadGateway(); err == nil {
			t.Fatal("identity transparency was enabled without a signing seed")
		}
	})

	for name, value := range map[string]string{
		"padded":       canonicalSeed + "=",
		"short":        base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 31)),
		"whitespace":   " " + canonicalSeed,
		"standard b64": "+/" + canonicalSeed[2:],
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "true")
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", value)
			if _, err := config.LoadGateway(); err == nil {
				t.Fatalf("accepted malformed signing seed %q", name)
			}
		})
	}

	t.Run("accepts canonical seed", func(t *testing.T) {
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "true")
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", canonicalSeed)
		cfg, err := config.LoadGateway()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.IdentityTransparency == nil ||
			!bytes.Equal(cfg.IdentityTransparency.SigningSeed[:], bytes.Repeat([]byte{0x42}, 32)) {
			t.Fatal("canonical signing seed was not preserved exactly")
		}
	})

	t.Run("accepts an explicit external witness quorum", func(t *testing.T) {
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "true")
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", canonicalSeed)
		witnessKey := hex.EncodeToString(bytes.Repeat([]byte{0x24}, 32))
		t.Setenv(
			"VEIL_IDENTITY_TRANSPARENCY_WITNESSES",
			"https://witness.example:443/v1/checkpoint|"+witnessKey,
		)
		t.Setenv("VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM", "1")
		cfg, err := config.LoadGateway()
		if err != nil {
			t.Fatal(err)
		}
		if len(cfg.IdentityTransparency.Witnesses) != 1 ||
			cfg.IdentityTransparency.WitnessThreshold != 1 ||
			cfg.IdentityTransparency.Witnesses[0].URL != "https://witness.example:443/v1/checkpoint" ||
			hex.EncodeToString(cfg.IdentityTransparency.Witnesses[0].SigningKey[:]) != witnessKey {
			t.Fatalf("witness configuration changed: %#v", cfg.IdentityTransparency)
		}
	})

	for name, values := range map[string][2]string{
		"partial":         {"https://witness.example:443/v1/checkpoint|" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), ""},
		"non tls":         {"http://witness.example:80/v1/checkpoint|" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "1"},
		"leading zero":    {"https://witness.example:443/v1/checkpoint|" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "01"},
		"quorum too high": {"https://witness.example:443/v1/checkpoint|" + hex.EncodeToString(bytes.Repeat([]byte{1}, 32)), "2"},
	} {
		t.Run("rejects witness "+name, func(t *testing.T) {
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_ENABLED", "true")
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED", canonicalSeed)
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_WITNESSES", values[0])
			t.Setenv("VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM", values[1])
			if _, err := config.LoadGateway(); err == nil {
				t.Fatalf("accepted invalid witness configuration %q", name)
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
