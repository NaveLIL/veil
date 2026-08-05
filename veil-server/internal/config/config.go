package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

const insecureDevDatabaseURL = "postgres://veil:veil@localhost:5432/veil?sslmode=disable"

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port         string
	DatabaseURL  string
	PublicOrigin nodeorigin.Canonical

	// Auth
	AuthChallengeTTL     time.Duration // How long a challenge is valid
	PreKeyLowWarning     int           // Warn when OPKs drop below this count
	AllowRegistration    bool          // Whether first-time identities may create accounts
	IdentityTransparency *IdentityTransparencyConfig

	// Chat
	MaxMessageSize        int // Max ciphertext size (bytes)
	MessageBatchLimit     int // Max messages per sync request
	MaxConversationFanout int // Max recipients in a DM fan-out
}

// IdentityTransparencyConfig contains the Node-local seed used only to sign
// witnessed transparency tree heads. It is opt-in and intentionally has no
// text/String representation, so ordinary configuration logging cannot expose
// the secret.
type IdentityTransparencyConfig struct {
	SigningSeed      [32]byte
	Witnesses        []IdentityTransparencyWitnessConfig
	WitnessThreshold uint16
}

type IdentityTransparencyWitnessConfig struct {
	URL        string
	SigningKey [32]byte
}

// LoadGateway loads the shared server configuration and the gateway's
// fail-closed, exact public origin. The configured value is validated as-is
// and is never inferred from an incoming request.
func LoadGateway() (*Config, error) {
	cfg, err := Load()
	if err != nil {
		return nil, err
	}

	publicOrigin, configured := os.LookupEnv("VEIL_PUBLIC_ORIGIN")
	if !configured || publicOrigin == "" {
		return nil, errors.New("VEIL_PUBLIC_ORIGIN is required for the gateway")
	}
	if strings.TrimSpace(publicOrigin) != publicOrigin {
		return nil, errors.New("VEIL_PUBLIC_ORIGIN must not contain surrounding whitespace")
	}
	canonicalOrigin, err := nodeorigin.ParseCanonical(publicOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid VEIL_PUBLIC_ORIGIN: %w", err)
	}

	cfg.PublicOrigin = canonicalOrigin
	transparencyConfig, err := loadIdentityTransparencyConfig()
	if err != nil {
		return nil, err
	}
	cfg.IdentityTransparency = transparencyConfig
	return cfg, nil
}

func loadIdentityTransparencyConfig() (*IdentityTransparencyConfig, error) {
	enabled, err := envBoolOrDefault("VEIL_IDENTITY_TRANSPARENCY_ENABLED", false)
	if err != nil {
		return nil, err
	}
	rawSeed, seedConfigured := os.LookupEnv("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED")
	rawWitnesses, witnessesConfigured := os.LookupEnv("VEIL_IDENTITY_TRANSPARENCY_WITNESSES")
	rawThreshold, thresholdConfigured := os.LookupEnv("VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM")
	if !enabled {
		if seedConfigured && rawSeed != "" || witnessesConfigured && rawWitnesses != "" ||
			thresholdConfigured && rawThreshold != "" {
			return nil, errors.New("identity transparency secrets or witnesses are set while identity transparency is disabled")
		}
		return nil, nil
	}
	if !seedConfigured || rawSeed == "" {
		return nil, errors.New("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED is required when identity transparency is enabled")
	}
	if strings.TrimSpace(rawSeed) != rawSeed || strings.Contains(rawSeed, "=") {
		return nil, errors.New("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED must be canonical unpadded base64url")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(rawSeed)
	if err != nil || len(decoded) != ed25519SeedSize || base64.RawURLEncoding.EncodeToString(decoded) != rawSeed {
		return nil, errors.New("VEIL_IDENTITY_TRANSPARENCY_SIGNING_SEED must encode exactly 32 bytes as canonical unpadded base64url")
	}
	var seed [ed25519SeedSize]byte
	copy(seed[:], decoded)
	witnesses, threshold, err := parseIdentityTransparencyWitnesses(
		rawWitnesses, witnessesConfigured, rawThreshold, thresholdConfigured,
	)
	if err != nil {
		clear(seed[:])
		return nil, err
	}
	return &IdentityTransparencyConfig{
		SigningSeed: seed, Witnesses: witnesses, WitnessThreshold: threshold,
	}, nil
}

func parseIdentityTransparencyWitnesses(
	rawWitnesses string,
	witnessesConfigured bool,
	rawThreshold string,
	thresholdConfigured bool,
) ([]IdentityTransparencyWitnessConfig, uint16, error) {
	if (!witnessesConfigured || rawWitnesses == "") && (!thresholdConfigured || rawThreshold == "") {
		return nil, 0, nil
	}
	if !witnessesConfigured || rawWitnesses == "" || !thresholdConfigured || rawThreshold == "" ||
		strings.TrimSpace(rawWitnesses) != rawWitnesses || strings.TrimSpace(rawThreshold) != rawThreshold {
		return nil, 0, errors.New("identity transparency witnesses and quorum must be configured together without whitespace")
	}
	parsedThreshold, err := strconv.ParseUint(rawThreshold, 10, 16)
	if err != nil || parsedThreshold == 0 || strconv.FormatUint(parsedThreshold, 10) != rawThreshold {
		return nil, 0, errors.New("VEIL_IDENTITY_TRANSPARENCY_WITNESS_QUORUM must be a canonical positive decimal integer")
	}
	items := strings.Split(rawWitnesses, ",")
	if len(items) == 0 || len(items) > 32 || int(parsedThreshold) > len(items) {
		return nil, 0, errors.New("identity transparency witness quorum is invalid")
	}
	witnesses := make([]IdentityTransparencyWitnessConfig, len(items))
	for index, item := range items {
		parts := strings.Split(item, "|")
		if len(parts) != 2 || parts[0] == "" || len(parts[1]) != 64 {
			return nil, 0, errors.New("VEIL_IDENTITY_TRANSPARENCY_WITNESSES entry is invalid")
		}
		endpoint, err := url.Parse(parts[0])
		if err != nil || endpoint.String() != parts[0] || endpoint.User != nil || endpoint.RawQuery != "" ||
			endpoint.Fragment != "" || endpoint.Hostname() == "" || endpoint.Port() == "" ||
			endpoint.Path == "" || (endpoint.Scheme != "https" &&
			!(endpoint.Scheme == "http" && isLoopbackHostname(endpoint.Hostname()))) {
			return nil, 0, errors.New("transparency witness URL must be canonical HTTPS with an explicit port (HTTP is loopback-only)")
		}
		key, err := hex.DecodeString(parts[1])
		if err != nil || hex.EncodeToString(key) != parts[1] || allZeroConfigBytes(key) {
			return nil, 0, errors.New("transparency witness signing key must be canonical lowercase 32-byte hex")
		}
		witnesses[index].URL = parts[0]
		copy(witnesses[index].SigningKey[:], key)
		for previous := 0; previous < index; previous++ {
			if witnesses[previous].URL == witnesses[index].URL ||
				bytes.Equal(witnesses[previous].SigningKey[:], witnesses[index].SigningKey[:]) {
				return nil, 0, errors.New("transparency witness endpoints and signing keys must be unique")
			}
		}
	}
	return witnesses, uint16(parsedThreshold), nil
}

func isLoopbackHostname(hostname string) bool {
	return hostname == "localhost" || hostname == "127.0.0.1" || hostname == "::1"
}

func allZeroConfigBytes(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

const ed25519SeedSize = 32

func Load() (*Config, error) {
	if _, configured := os.LookupEnv("VEIL_ALLOW_LEGACY_WS_V2"); configured {
		return nil, errors.New("VEIL_ALLOW_LEGACY_WS_V2 was removed; legacy WebSocket v2 cannot be enabled")
	}
	databaseURL, err := loadDatabaseURL()
	if err != nil {
		return nil, err
	}
	allowRegistration, err := envBoolOrDefault("VEIL_ALLOW_REGISTRATION", false)
	if err != nil {
		return nil, err
	}
	return &Config{
		Port:                  envOrDefault("PORT", "8080"),
		DatabaseURL:           databaseURL,
		AuthChallengeTTL:      envDurationOrDefault("AUTH_CHALLENGE_TTL", 30*time.Second),
		PreKeyLowWarning:      envIntOrDefault("PREKEY_LOW_WARNING", 10),
		AllowRegistration:     allowRegistration,
		MaxMessageSize:        envIntOrDefault("MAX_MESSAGE_SIZE", 64*1024),
		MessageBatchLimit:     envIntOrDefault("MESSAGE_BATCH_LIMIT", 100),
		MaxConversationFanout: envIntOrDefault("MAX_CONVERSATION_FANOUT", 2),
	}, nil
}

func loadDatabaseURL() (string, error) {
	raw, configured := os.LookupEnv("DATABASE_URL")
	if !configured || raw == "" {
		if os.Getenv("VEIL_ALLOW_INSECURE_DEV_DATABASE") == "1" {
			return insecureDevDatabaseURL, nil
		}
		return "", errors.New("DATABASE_URL is required (set VEIL_ALLOW_INSECURE_DEV_DATABASE=1 only for an isolated local development database)")
	}
	if strings.TrimSpace(raw) != raw {
		return "", errors.New("DATABASE_URL must not contain surrounding whitespace")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid DATABASE_URL: %w", err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return "", errors.New("DATABASE_URL scheme must be postgres or postgresql")
	}
	if parsed.Hostname() == "" {
		return "", errors.New("DATABASE_URL must include a database host")
	}
	if parsed.Path == "" || parsed.Path == "/" {
		return "", errors.New("DATABASE_URL must include a database name")
	}
	return raw, nil
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func envBoolOrDefault(key string, fallback bool) (bool, error) {
	raw, configured := os.LookupEnv(key)
	if !configured || raw == "" {
		return fallback, nil
	}
	if strings.TrimSpace(raw) != raw {
		return false, fmt.Errorf("%s must not contain surrounding whitespace", key)
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return value, nil
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
