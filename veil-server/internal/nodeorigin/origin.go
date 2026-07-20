// Package nodeorigin validates the exact canonical Node origin used as a
// cryptographic trust scope and as the server's configured public identity.
package nodeorigin

import (
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// MaxBytes is the maximum encoded length of a canonical Node origin.
const MaxBytes = 512

// canonicalDNSProfile mirrors the non-transitional WHATWG URL host settings
// used by Rust's url::Host parser; the manual LDH limits below remain the
// versioned Veil grammar rather than accepting the profile's normalization.
var canonicalDNSProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.CheckHyphens(false),
	idna.VerifyDNSLength(false),
	idna.BidiRule(),
)

// Canonical is an origin that passed the exact Node-origin grammar. Its value
// cannot be constructed outside this package without validation; the zero
// value represents an origin that has not been configured.
type Canonical struct {
	value string
}

// String returns the exact validated bytes without normalization.
func (origin Canonical) String() string {
	return origin.value
}

// IsZero reports whether no canonical origin has been configured.
func (origin Canonical) IsZero() bool {
	return origin.value == ""
}

// ParseCanonical validates value and returns its opaque exact representation.
func ParseCanonical(value string) (Canonical, error) {
	if err := ValidateCanonical(value); err != nil {
		return Canonical{}, err
	}
	return Canonical{value: value}, nil
}

// ValidateCanonical requires a complete, already-canonical origin with an
// explicit port. HTTPS is mandatory except for exact local-loopback HTTP
// development origins. The value is never normalized: textual aliases are
// rejected instead.
func ValidateCanonical(origin string) error {
	if origin == "" || len(origin) > MaxBytes || !printableASCII(origin) {
		return errors.New("node origin is empty, oversized, or non-printable ASCII")
	}

	var scheme, authority string
	switch {
	case strings.HasPrefix(origin, "https://"):
		scheme, authority = "https", strings.TrimPrefix(origin, "https://")
	case strings.HasPrefix(origin, "http://"):
		scheme, authority = "http", strings.TrimPrefix(origin, "http://")
	default:
		return errors.New("node origin has an invalid scheme")
	}
	if authority == "" || strings.ContainsAny(authority, "/?#@\\") {
		return errors.New("node origin must contain only an authority")
	}

	host, port, loopback, err := canonicalAuthority(authority)
	if err != nil {
		return err
	}
	if scheme == "http" && !loopback {
		return errors.New("node HTTP origin is not exact loopback")
	}
	if scheme+"://"+host+":"+port != origin {
		return errors.New("node origin is not canonical")
	}
	return nil
}

func canonicalAuthority(authority string) (host, port string, loopback bool, err error) {
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end <= 1 || end+2 > len(authority) || authority[end+1] != ':' ||
			strings.Contains(authority[1:end], "%") {
			return "", "", false, errors.New("node origin has invalid bracketed IPv6")
		}
		address, parseErr := netip.ParseAddr(authority[1:end])
		if parseErr != nil || !address.Is6() || address.Is4In6() || address.Zone() != "" {
			return "", "", false, errors.New("node origin has invalid IPv6")
		}
		port, err = canonicalPort(authority[end+2:])
		if err != nil {
			return "", "", false, err
		}
		host = "[" + address.String() + "]"
		return host, port, address == netip.IPv6Loopback(), nil
	}

	if strings.Count(authority, ":") != 1 {
		return "", "", false, errors.New("node origin requires one explicit port")
	}
	separator := strings.LastIndexByte(authority, ':')
	host = authority[:separator]
	port, err = canonicalPort(authority[separator+1:])
	if err != nil {
		return "", "", false, err
	}
	if host == "" {
		return "", "", false, errors.New("node origin host is empty")
	}
	if address, parseErr := netip.ParseAddr(host); parseErr == nil {
		if !address.Is4() || address.String() != host {
			return "", "", false, errors.New("node origin IPv4 is not canonical")
		}
		return host, port, address == netip.MustParseAddr("127.0.0.1"), nil
	}
	if err := validateHostname(host); err != nil {
		return "", "", false, err
	}
	return host, port, host == "localhost", nil
}

func canonicalPort(value string) (string, error) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return "", errors.New("node origin port is not canonical")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return "", errors.New("node origin port is invalid")
		}
	}
	parsed, err := strconv.ParseUint(value, 10, 16)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != value {
		return "", errors.New("node origin port is out of range")
	}
	return value, nil
}

func validateHostname(host string) error {
	if len(host) > 253 || host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return errors.New("node origin hostname is not canonical")
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return errors.New("node origin hostname label is invalid")
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if !((character >= 'a' && character <= 'z') ||
				(character >= '0' && character <= '9') || character == '-') {
				return errors.New("node origin hostname is not ASCII LDH")
			}
		}
	}
	canonicalHost, err := canonicalDNSProfile.ToASCII(host)
	if err != nil || canonicalHost != host {
		return errors.New("node origin hostname is not canonical IDNA")
	}
	// WHATWG host parsing routes every name whose final label is an IPv4
	// number into the legacy IPv4 parser. Reject that whole class instead of
	// accepting a DNS spelling that the Rust URL parser normalizes or rejects.
	if numericAddressLabel(labels[len(labels)-1]) {
		return errors.New("node origin has an invalid numeric host alias")
	}
	return nil
}

func numericAddressLabel(label string) bool {
	if strings.HasPrefix(label, "0x") {
		for index := 2; index < len(label); index++ {
			if !((label[index] >= '0' && label[index] <= '9') ||
				(label[index] >= 'a' && label[index] <= 'f')) {
				return false
			}
		}
		return true
	}
	for index := 0; index < len(label); index++ {
		if label[index] < '0' || label[index] > '9' {
			return false
		}
	}
	return len(label) > 0
}

func printableASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}
