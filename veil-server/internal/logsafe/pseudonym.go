// Package logsafe provides short-lived, non-reversible correlation references
// for identifiers that must never be written to operational logs in raw form.
package logsafe

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"
)

const secretSize = 32

type Pseudonymizer struct {
	secret [secretSize]byte
	now    func() time.Time
}

func New(secret []byte) (*Pseudonymizer, error) {
	p := &Pseudonymizer{now: time.Now}
	switch len(secret) {
	case 0:
		if _, err := rand.Read(p.secret[:]); err != nil {
			return nil, err
		}
	case secretSize:
		copy(p.secret[:], secret)
	default:
		return nil, errors.New("log pseudonym secret must be exactly 32 bytes")
	}
	return p, nil
}

func (p *Pseudonymizer) Ref(domain, raw string) string {
	if p == nil || raw == "" || raw == "-" {
		return "-"
	}
	day := p.now().UTC().Format("2006-01-02")
	daily := hmac.New(sha256.New, p.secret[:])
	_, _ = daily.Write([]byte("veil-log-v1\x00" + day))

	digest := hmac.New(sha256.New, daily.Sum(nil))
	_, _ = digest.Write([]byte(domain))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(raw))
	return "v1_" + hex.EncodeToString(digest.Sum(nil)[:12])
}

var process = func() *Pseudonymizer {
	p, err := New(nil)
	if err != nil {
		panic(fmt.Errorf("logsafe: initialize process pseudonymizer: %w", err))
	}
	return p
}()

// Ref is stable only within one UTC day and one gateway process.
func Ref(domain, raw string) string {
	return process.Ref(domain, raw)
}

// ErrorClass returns a bounded operational label without ever rendering the
// error text. Database drivers, URL errors and filesystem errors routinely
// embed query values, secret endpoint paths or local filenames in Error();
// those strings must not cross the production logging boundary.
func ErrorClass(err error) string {
	switch {
	case err == nil:
		return "-"
	case errors.Is(err, context.Canceled):
		return "context_canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "context_deadline"
	}

	var sqlErr interface{ SQLState() string }
	if errors.As(err, &sqlErr) {
		if state := sqlErr.SQLState(); validSQLState(state) {
			return "database_" + state
		}
		return "database_error"
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return "filesystem_error"
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return "network_timeout"
		}
		return "network_error"
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return "network_timeout"
		}
		return "network_error"
	}

	return "internal_error"
}

func validSQLState(state string) bool {
	if len(state) != 5 {
		return false
	}
	for _, c := range state {
		if (c < '0' || c > '9') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}
