// Package uploads wraps the tus.io resumable upload protocol (via
// github.com/tus/tusd/v2) with three veil-specific layers:
//
//  1. Bearer-token auth — clients exchange a single signed REST call
//     (POST /v1/uploads/token, verified by the existing X-Veil triplet)
//     for a short-lived bearer token that authorises tusd's POST/PATCH/
//     HEAD/DELETE traffic. Resumable PATCH chunks therefore don't need
//     per-request Ed25519 signatures (which would force buffering the
//     entire body for hashing).
//  2. Quota gate — the pre-create hook rejects uploads that would push
//     a user over their trailing-24h byte budget.
//  3. Sweeper — a goroutine deletes finished uploads after their TTL
//     and aborts any stale-but-unfinished uploads beyond a grace window.
//
// The server stays E2EE-blind: only declared sizes / timestamps live
// in tus_uploads. Ciphertext bytes sit on the chosen storage backend
// (local filesystem in v1; S3 planned).
package uploads

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	// TokenVersion is the prefix carried in every issued token; it lets
	// us evolve the format later (e.g. add a key id) without breaking
	// in-flight resumes.
	TokenVersion = "v1"

	// MinTokenKeyLen is the minimum acceptable HMAC key length.
	MinTokenKeyLen = 32

	// DefaultTokenTTL is the upload session lifetime granted by
	// /v1/uploads/token. The roadmap allows resumes for hours; we err on
	// the long side here because aborts are cheap (sweeper handles them).
	DefaultTokenTTL = 24 * time.Hour
)

// LoadTokenKey reads VEIL_UPLOAD_TOKEN_KEY (base64) from the environment.
// Returns nil + nil error in disabled mode (key unset) so callers can
// fall back to a "uploads disabled" path. Surfacing a too-short key as
// an error prevents a silent demotion to a weak HMAC.
func LoadTokenKey(env func(string) string) ([]byte, error) {
	raw := strings.TrimSpace(env("VEIL_UPLOAD_TOKEN_KEY"))
	if raw == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("VEIL_UPLOAD_TOKEN_KEY: invalid base64: %w", err)
	}
	if len(key) < MinTokenKeyLen {
		return nil, fmt.Errorf("VEIL_UPLOAD_TOKEN_KEY: must be at least %d bytes", MinTokenKeyLen)
	}
	return key, nil
}

// IssueToken signs a short-lived bearer token binding userID to the
// expiry instant. Format:
//
//	v1.<userID>.<expiresUnix>.<base64url(hmac-sha256)>
//
// Dots are safe because userID is a UUID. We base64url the MAC so the
// whole token is URL/header friendly without escaping.
func IssueToken(key []byte, userID string, ttl time.Duration) (string, time.Time, error) {
	if len(key) < MinTokenKeyLen {
		return "", time.Time{}, errors.New("upload token key too short")
	}
	if userID == "" {
		return "", time.Time{}, errors.New("user id required")
	}
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}
	expires := time.Now().Add(ttl).UTC()
	expStr := strconv.FormatInt(expires.Unix(), 10)
	mac := computeMAC(key, userID, expStr)
	return fmt.Sprintf("%s.%s.%s.%s", TokenVersion, userID, expStr, mac), expires, nil
}

// VerifyToken parses and verifies a token. It returns the bound user ID
// on success. We use constant-time comparison on the MAC to avoid
// leaking timing differences between forged and partially-correct tokens.
func VerifyToken(key []byte, token string) (string, error) {
	if len(key) < MinTokenKeyLen {
		return "", errors.New("upload token key not configured")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != TokenVersion {
		return "", errors.New("malformed token")
	}
	userID, expStr, gotMAC := parts[1], parts[2], parts[3]
	if userID == "" {
		return "", errors.New("malformed token")
	}
	expUnix, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return "", errors.New("malformed token")
	}
	if time.Now().After(time.Unix(expUnix, 0)) {
		return "", errors.New("token expired")
	}
	want := computeMAC(key, userID, expStr)
	if !hmac.Equal([]byte(want), []byte(gotMAC)) {
		return "", errors.New("bad signature")
	}
	return userID, nil
}

func computeMAC(key []byte, userID, expStr string) string {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(TokenVersion))
	h.Write([]byte{'|'})
	h.Write([]byte(userID))
	h.Write([]byte{'|'})
	h.Write([]byte(expStr))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// GenerateRandomKey is exposed for `veil-server` operators (and tests)
// to mint a fresh VEIL_UPLOAD_TOKEN_KEY value without shelling out.
func GenerateRandomKey() (string, error) {
	b := make([]byte, MinTokenKeyLen)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}
