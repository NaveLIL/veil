// Package logsafe provides short-lived, non-reversible correlation references
// for identifiers that must never be written to operational logs in raw form.
package logsafe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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
		panic("logsafe: cannot initialize process pseudonymizer: " + err.Error())
	}
	return p
}()

// Ref is stable only within one UTC day and one gateway process.
func Ref(domain, raw string) string {
	return process.Ref(domain, raw)
}
