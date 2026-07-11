package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const insecureDevDatabaseURL = "postgres://veil:veil@localhost:5432/veil?sslmode=disable"

// Config holds all server configuration, loaded from environment variables.
type Config struct {
	Port        string
	DatabaseURL string

	// Auth
	AuthChallengeTTL time.Duration // How long a challenge is valid
	AuthMaxAttempts  int           // Max auth attempts per connection before disconnect
	PreKeyLowWarning int           // Warn when OPKs drop below this count

	// Chat
	MaxMessageSize        int // Max ciphertext size (bytes)
	MessageBatchLimit     int // Max messages per sync request
	MaxConversationFanout int // Max recipients in a DM fan-out
}

func Load() (*Config, error) {
	databaseURL, err := loadDatabaseURL()
	if err != nil {
		return nil, err
	}
	return &Config{
		Port:                  envOrDefault("PORT", "8080"),
		DatabaseURL:           databaseURL,
		AuthChallengeTTL:      envDurationOrDefault("AUTH_CHALLENGE_TTL", 30*time.Second),
		AuthMaxAttempts:       envIntOrDefault("AUTH_MAX_ATTEMPTS", 3),
		PreKeyLowWarning:      envIntOrDefault("PREKEY_LOW_WARNING", 10),
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

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
