package uploads

import "testing"

func TestUploadMaxBytesDefaultsToTwoGiBPlaintextCiphertextGeometry(t *testing.T) {
	t.Setenv("UPLOAD_MAX_BYTES", "")

	cfg := LoadConfigFromEnv()
	want := int64(2_147_483_648 + 32_768)
	if cfg.MaxUploadSize != want {
		t.Fatalf("MaxUploadSize = %d, want %d", cfg.MaxUploadSize, want)
	}
}

func TestUploadMaxBytesExplicitOverrideStillWins(t *testing.T) {
	const configured = "3145728"
	t.Setenv("UPLOAD_MAX_BYTES", configured)

	cfg := LoadConfigFromEnv()
	if cfg.MaxUploadSize != 3_145_728 {
		t.Fatalf("MaxUploadSize = %d, want explicit override %s", cfg.MaxUploadSize, configured)
	}
}

func TestUploadMaxBytesInvalidOverrideFallsBackSafely(t *testing.T) {
	t.Setenv("UPLOAD_MAX_BYTES", "not-a-number")

	cfg := LoadConfigFromEnv()
	if cfg.MaxUploadSize != defaultMaxUploadSize {
		t.Fatalf(
			"MaxUploadSize = %d, want fallback %d",
			cfg.MaxUploadSize,
			defaultMaxUploadSize,
		)
	}
}

func TestUploadForwardedHeadersFollowExplicitProxyTrust(t *testing.T) {
	t.Setenv("VEIL_TRUST_PROXY_HEADERS", "true")

	cfg := LoadConfigFromEnv()
	if !cfg.RespectForwardedHeaders {
		t.Fatal("RespectForwardedHeaders = false, want true for trusted proxy deployment")
	}
}

func TestUploadForwardedHeadersFailClosedByDefault(t *testing.T) {
	t.Setenv("VEIL_TRUST_PROXY_HEADERS", "")

	cfg := LoadConfigFromEnv()
	if cfg.RespectForwardedHeaders {
		t.Fatal("RespectForwardedHeaders = true without an explicit trusted proxy")
	}
}

func TestUploadForwardedHeadersFailClosedForInvalidSetting(t *testing.T) {
	t.Setenv("VEIL_TRUST_PROXY_HEADERS", "definitely-not-a-boolean")

	cfg := LoadConfigFromEnv()
	if cfg.RespectForwardedHeaders {
		t.Fatal("RespectForwardedHeaders = true for an invalid trust setting")
	}
}
