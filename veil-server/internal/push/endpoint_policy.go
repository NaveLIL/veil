package push

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPushHTTPTimeout = 10 * time.Second
	maxPushRedirects       = 3
)

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

type pushOriginContextKey struct{}

// EndpointPolicy validates push destinations at registration and delivery.
// Private endpoints are allowed only for exact operator-configured origins
// (scheme + host + effective port), never by a process-wide boolean bypass.
type EndpointPolicy struct {
	allowedPrivateOrigins map[string]struct{}
	resolver              ipResolver
}

// NewEndpointPolicy constructs a policy from exact private origins such as
// "http://ntfy:80". Paths, credentials, query strings and fragments are not
// valid in the allowlist; paths remain free within an allowed origin.
func NewEndpointPolicy(allowedPrivateOrigins ...string) (*EndpointPolicy, error) {
	policy := &EndpointPolicy{
		allowedPrivateOrigins: make(map[string]struct{}, len(allowedPrivateOrigins)),
		resolver:              net.DefaultResolver,
	}
	for _, raw := range allowedPrivateOrigins {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" ||
			(u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" ||
			u.User != nil || (u.Path != "" && u.Path != "/") ||
			u.RawQuery != "" || u.Fragment != "" {
			return nil, fmt.Errorf("invalid private push origin %q", raw)
		}
		origin, err := normalizedPushOrigin(u)
		if err != nil {
			return nil, fmt.Errorf("invalid private push origin %q: %w", raw, err)
		}
		policy.allowedPrivateOrigins[origin] = struct{}{}
	}
	return policy, nil
}

func defaultEndpointPolicy() *EndpointPolicy {
	policy, err := NewEndpointPolicy()
	if err != nil {
		panic(err)
	}
	return policy
}

// LoadEndpointPolicy reads a comma-separated exact-origin allowlist. The
// default is empty/fail-closed. A Compose deployment may set, for example,
// VEIL_PUSH_ALLOWED_PRIVATE_ORIGINS=http://ntfy:80.
func LoadEndpointPolicy() (*EndpointPolicy, error) {
	raw := strings.TrimSpace(os.Getenv("VEIL_PUSH_ALLOWED_PRIVATE_ORIGINS"))
	if raw == "" {
		return NewEndpointPolicy()
	}
	return NewEndpointPolicy(strings.Split(raw, ",")...)
}

// ValidateEndpoint returns a normalized endpoint after strict URL and DNS/IP
// validation. DNS is checked again by the transport dialer at delivery time.
func (p *EndpointPolicy) ValidateEndpoint(ctx context.Context, raw string) (*url.URL, error) {
	if p == nil {
		return nil, errors.New("push endpoint policy is required")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u == nil || !u.IsAbs() || u.Opaque != "" {
		return nil, errors.New("push endpoint must be an absolute URL")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return nil, errors.New("push endpoint must use HTTP(S)")
	}
	if u.Host == "" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, errors.New("push endpoint has forbidden URL components")
	}
	if strings.Contains(u.Hostname(), "%") || len(u.Hostname()) > 253 {
		return nil, errors.New("push endpoint host is invalid")
	}
	if port := u.Port(); port != "" {
		n, parseErr := strconv.Atoi(port)
		if parseErr != nil || n < 1 || n > 65535 {
			return nil, errors.New("push endpoint port is invalid")
		}
	}
	origin, err := normalizedPushOrigin(u)
	if err != nil {
		return nil, err
	}
	_, privateOriginAllowed := p.allowedPrivateOrigins[origin]
	if u.Scheme != "https" && !privateOriginAllowed {
		return nil, errors.New("push endpoint must use HTTPS")
	}

	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := p.resolveAllowed(lookupCtx, u.Hostname(), privateOriginAllowed); err != nil {
		return nil, err
	}
	return u, nil
}

func normalizedPushOrigin(u *url.URL) (string, error) {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" || strings.Contains(host, "%") {
		return "", errors.New("invalid origin host")
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", errors.New("invalid origin scheme")
		}
	}
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host + ":" + port, nil
}

func (p *EndpointPolicy) resolveAllowed(ctx context.Context, host string, privateOriginAllowed bool) ([]net.IPAddr, error) {
	if literal := net.ParseIP(host); literal != nil {
		addresses := []net.IPAddr{{IP: literal}}
		if err := validatePushAddresses(addresses, privateOriginAllowed); err != nil {
			return nil, err
		}
		return addresses, nil
	}
	addresses, err := p.resolver.LookupIPAddr(ctx, host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("push endpoint host could not be resolved")
	}
	if err := validatePushAddresses(addresses, privateOriginAllowed); err != nil {
		return nil, err
	}
	return addresses, nil
}

func validatePushAddresses(addresses []net.IPAddr, privateOriginAllowed bool) error {
	for _, address := range addresses {
		ip := address.IP
		if ip == nil || ip.IsUnspecified() || ip.IsMulticast() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("push endpoint resolves to a forbidden address")
		}
		if !privateOriginAllowed && !isPublicPushIP(ip) {
			return errors.New("push endpoint resolves to a private or reserved address")
		}
	}
	return nil
}

var additionallyBlockedPushCIDRs = mustPushCIDRs(
	"100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15",
	"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32",
)

func mustPushCIDRs(raw ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(raw))
	for _, value := range raw {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, network)
	}
	return out
}

func isPublicPushIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	for _, network := range additionallyBlockedPushCIDRs {
		if network.Contains(ip) {
			return false
		}
	}
	return true
}

func (p *EndpointPolicy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("invalid push dial address")
	}
	origin, _ := ctx.Value(pushOriginContextKey{}).(string)
	_, privateOriginAllowed := p.allowedPrivateOrigins[origin]
	addresses, err := p.resolveAllowed(ctx, host, privateOriginAllowed)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, candidate := range addresses {
		conn, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.IP.String(), port))
		if dialErr == nil {
			return conn, nil
		}
		lastErr = dialErr
	}
	if lastErr == nil {
		lastErr = errors.New("push endpoint has no dialable address")
	}
	return nil, lastErr
}

func (p *EndpointPolicy) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxPushRedirects {
		return errors.New("too many push endpoint redirects")
	}
	_, err := p.ValidateEndpoint(req.Context(), req.URL.String())
	return err
}

type pushPolicyTransport struct {
	base *http.Transport
}

func (t *pushPolicyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	origin, err := normalizedPushOrigin(req.URL)
	if err != nil {
		return nil, err
	}
	ctx := context.WithValue(req.Context(), pushOriginContextKey{}, origin)
	return t.base.RoundTrip(req.WithContext(ctx))
}

func (p *EndpointPolicy) newHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A generic HTTP proxy can resolve a forbidden destination on our behalf,
	// bypassing the validated dialer. Push delivery therefore connects direct.
	transport.Proxy = nil
	transport.DialContext = p.dialContext
	transport.MaxResponseHeaderBytes = 64 << 10
	return &http.Client{
		Transport:     &pushPolicyTransport{base: transport},
		Timeout:       defaultPushHTTPTimeout,
		CheckRedirect: p.checkRedirect,
	}
}
