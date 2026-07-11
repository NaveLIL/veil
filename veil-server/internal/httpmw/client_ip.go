package httpmw

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
)

// ClientIPPolicy controls whether forwarding headers from the immediate peer
// are trusted. The zero policy ignores them, which is the safe default for
// services reachable without a reverse proxy.
type ClientIPPolicy struct {
	trustAll bool
	cidrs    []*net.IPNet
}

var activeClientIPPolicy atomic.Pointer[ClientIPPolicy]

func init() {
	activeClientIPPolicy.Store(&ClientIPPolicy{})
}

// NewClientIPPolicy builds an immutable policy. trustAll should only be used
// when every connection to the service is forced through a trusted proxy;
// CIDRs are preferred when direct access is possible.
func NewClientIPPolicy(trustAll bool, trustedCIDRs []string) (*ClientIPPolicy, error) {
	p := &ClientIPPolicy{trustAll: trustAll}
	for _, raw := range trustedCIDRs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		_, network, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy CIDR %q: %w", raw, err)
		}
		p.cidrs = append(p.cidrs, network)
	}
	return p, nil
}

// ConfigureClientIPFromEnv applies VEIL_TRUST_PROXY_HEADERS (boolean, default
// false) and VEIL_TRUSTED_PROXY_CIDRS (comma-separated). Forwarded headers are
// accepted only when one of those explicit trust mechanisms matches.
func ConfigureClientIPFromEnv() error {
	trustAll := false
	if raw := strings.TrimSpace(os.Getenv("VEIL_TRUST_PROXY_HEADERS")); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return fmt.Errorf("VEIL_TRUST_PROXY_HEADERS must be a boolean: %w", err)
		}
		trustAll = value
	}
	var cidrs []string
	if raw := strings.TrimSpace(os.Getenv("VEIL_TRUSTED_PROXY_CIDRS")); raw != "" {
		cidrs = strings.Split(raw, ",")
	}
	policy, err := NewClientIPPolicy(trustAll, cidrs)
	if err != nil {
		return err
	}
	SetClientIPPolicy(policy)
	return nil
}

// SetClientIPPolicy replaces the process-wide policy shared by REST access
// logs/rate limits and WebSocket connection limits. It is intended for startup
// wiring and tests, before serving requests.
func SetClientIPPolicy(policy *ClientIPPolicy) {
	if policy == nil {
		policy = &ClientIPPolicy{}
	}
	activeClientIPPolicy.Store(policy)
}

// ClientIP returns the canonical address used for security quotas. A malformed
// or multi-hop X-Forwarded-For value fails closed to the direct peer instead
// of producing an attacker-controlled bucket key.
func ClientIP(r *http.Request) string {
	direct, remote := directClientIP(r.RemoteAddr)
	policy := activeClientIPPolicy.Load()
	if remote == nil || policy == nil || !policy.trusts(remote) {
		return direct
	}
	values := r.Header.Values("X-Forwarded-For")
	if len(values) != 1 {
		return direct
	}
	forwarded := strings.TrimSpace(values[0])
	if forwarded == "" || strings.Contains(forwarded, ",") {
		return direct
	}
	ip := net.ParseIP(forwarded)
	if ip == nil {
		return direct
	}
	return ip.String()
}

func (p *ClientIPPolicy) trusts(ip net.IP) bool {
	if p.trustAll {
		return true
	}
	for _, network := range p.cidrs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func directClientIP(remoteAddr string) (string, net.IP) {
	host := strings.TrimSpace(remoteAddr)
	if split, _, err := net.SplitHostPort(host); err == nil {
		host = split
	}
	host = strings.Trim(host, "[]")
	ip := net.ParseIP(host)
	if ip == nil {
		// One shared value preserves fail-closed rate limiting for malformed
		// peers; returning an empty value would bypass the WS connection cap.
		return "unknown", nil
	}
	return ip.String(), ip
}

func clientIP(r *http.Request) string { return ClientIP(r) }
