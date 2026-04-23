package uploads

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config bundles every operator-tunable knob for the uploads subsystem.
// Defaults are reasonable for a small self-hosted deployment; override
// via env vars (see LoadConfigFromEnv).
type Config struct {
	// LocalDir is the filesystem directory tusd's filestore writes into.
	LocalDir string

	// BasePath is the public URL prefix (must end with `/`). tusd uses
	// it to build Location headers; it must match the route mount.
	BasePath string

	// MaxUploadSize is the per-upload byte cap. Zero disables the cap
	// (tusd will allow any single upload).
	MaxUploadSize int64

	// QuotaWindow is the trailing window over which UserDailyQuota is
	// enforced.
	QuotaWindow time.Duration

	// UserDailyQuota is the byte budget per user per QuotaWindow.
	UserDailyQuota int64

	// RetentionAfterFinish is how long completed uploads survive before
	// the sweeper deletes them.
	RetentionAfterFinish time.Duration

	// AbortAfterIdle is how long an unfinished upload may sit before
	// the sweeper terminates it (recovers quota + disk).
	AbortAfterIdle time.Duration

	// SweepInterval is the period for the background sweeper goroutine.
	SweepInterval time.Duration

	// TokenTTL bounds the lifetime of bearer tokens issued via
	// /v1/uploads/token.
	TokenTTL time.Duration
}

// LoadConfigFromEnv pulls every UPLOAD_* env var (with sensible
// defaults). Returns the resolved config; never errors — bad values
// silently fall back to defaults so a typo can't take the gateway down.
func LoadConfigFromEnv() Config {
	cfg := Config{
		LocalDir:             envOrDefault("UPLOAD_LOCAL_DIR", "/var/veil/uploads"),
		BasePath:             "/v1/uploads/files/",
		MaxUploadSize:        envInt64OrDefault("UPLOAD_MAX_BYTES", 1<<30), // 1 GiB
		QuotaWindow:          envDurationOrDefault("UPLOAD_QUOTA_WINDOW", 24*time.Hour),
		UserDailyQuota:       envInt64OrDefault("UPLOAD_USER_DAILY_QUOTA_BYTES", 5<<30), // 5 GiB
		RetentionAfterFinish: envDurationOrDefault("UPLOAD_RETENTION", 30*24*time.Hour),
		AbortAfterIdle:       envDurationOrDefault("UPLOAD_ABORT_TTL", 24*time.Hour),
		SweepInterval:        envDurationOrDefault("UPLOAD_SWEEP_INTERVAL", time.Hour),
		TokenTTL:             envDurationOrDefault("UPLOAD_TOKEN_TTL", DefaultTokenTTL),
	}
	return cfg
}

func envOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt64OrDefault(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return fallback
	}
	return n
}

func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
