package nodeorigin

import (
	"strings"
	"testing"
)

func TestValidateCanonicalAcceptsExactOrigins(t *testing.T) {
	for _, origin := range []string{
		"https://node.example.test:443",
		"https://node.example.test:8443",
		"https://127.0.0.1:443",
		"https://192.0.2.1:443",
		"https://[2001:db8::1]:443",
		"https://xn--bcher-kva.example:443",
		"https://ab--cd.example:443",
		"http://localhost:80",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	} {
		t.Run(origin, func(t *testing.T) {
			if err := ValidateCanonical(origin); err != nil {
				t.Fatalf("ValidateCanonical(%q): %v", origin, err)
			}
		})
	}
}

func TestValidateCanonicalRejectsAliasesAndUnsafeOrigins(t *testing.T) {
	for _, origin := range []string{
		"",
		"https://node.example.test",
		"HTTPS://node.example.test:443",
		"https://Node.example.test:443",
		"https://node.example.test:0443",
		"https://node.example.test.:443",
		"https://user@node.example.test:443",
		"https://node.example.test:443/",
		"https://node.example.test:443?x=1",
		"https://node.example.test:443#fragment",
		"https://node.example.test:443\\suffix",
		"http://node.example.test:80",
		"http://127.0.0.2:80",
		"http://[2001:db8::1]:80",
		"https://b\u00fccher.example:443",
		"https://bad_host.example:443",
		"https://-bad.example:443",
		"https://bad-.example:443",
		"https://[fe80::1%25eth0]:443",
		"https://2001:db8::1:443",
		"https://[2001:0DB8::1]:443",
		"https://[2001:db8:0:0:0:0:0:1]:443",
		"https://[::ffff:192.0.2.1]:443",
		"https://127.1:443",
		"https://0x7f000001:443",
		"https://0x7f.0.0.1:443",
		"https://0177.0.0.1:443",
		"https://node.123:443",
		"https://node.0177:443",
		"https://node.0x7f:443",
		"https://node.0x:443",
		"https://999.1.1.1:443",
		"https://12345:443",
		"https://xn--a-ecp.ru:443",
		"https://node.example.test:0",
		"https://node.example.test:65536",
		"https://node.example.test:+443",
		"https://node.example.test:443 ",
	} {
		t.Run(origin, func(t *testing.T) {
			if err := ValidateCanonical(origin); err == nil {
				t.Fatalf("ValidateCanonical(%q) unexpectedly succeeded", origin)
			}
		})
	}
}

func TestParseCanonicalReturnsOpaqueExactValue(t *testing.T) {
	const value = "https://node.example.test:443"
	parsed, err := ParseCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.IsZero() || parsed.String() != value {
		t.Fatalf("parsed origin = %q (zero=%v), want exact %q", parsed.String(), parsed.IsZero(), value)
	}
	if !((Canonical{}).IsZero()) || (Canonical{}).String() != "" {
		t.Fatal("Canonical zero value is not empty")
	}
	if invalid, err := ParseCanonical("https://node.example.test"); err == nil || !invalid.IsZero() {
		t.Fatal("ParseCanonical returned a non-zero value for an invalid origin")
	}
}

func TestValidateCanonicalEnforcesByteLimit(t *testing.T) {
	oversized := "https://" + strings.Repeat("a", MaxBytes) + ":443"
	if err := ValidateCanonical(oversized); err == nil {
		t.Fatal("oversized origin unexpectedly succeeded")
	}
}
