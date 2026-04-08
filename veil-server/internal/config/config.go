package config

import (
	"os"
	"strconv"
	"time"
)

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

func Load() *Config {
	return &Config{
		Port:                  envOrDefault("PORT", "8080"),
		DatabaseURL:           envOrDefault("DATABASE_URL", "postgres://veil:veil@localhost:5432/veil?sslmode=disable"),
		AuthChallengeTTL:      envDurationOrDefault("AUTH_CHALLENGE_TTL", 30*time.Second),
		AuthMaxAttempts:       envIntOrDefault("AUTH_MAX_ATTEMPTS", 3),
		PreKeyLowWarning:      envIntOrDefault("PREKEY_LOW_WARNING", 10),
		MaxMessageSize:        envIntOrDefault("MAX_MESSAGE_SIZE", 64*1024),
		MessageBatchLimit:     envIntOrDefault("MESSAGE_BATCH_LIMIT", 100),
		MaxConversationFanout: envIntOrDefault("MAX_CONVERSATION_FANOUT", 2),
	}
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
