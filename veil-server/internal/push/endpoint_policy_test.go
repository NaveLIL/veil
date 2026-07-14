package push

import (
	"context"
	"net"
	"net/http"
	"testing"
)

type staticResolver map[string][]net.IPAddr

func (r staticResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	return r[host], nil
}

func TestEndpointPolicyRejectsPrivateAndMetadataDestinations(t *testing.T) {
	policy, err := NewEndpointPolicy()
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = staticResolver{
		"push.example":             {{IP: net.ParseIP("93.184.216.34")}},
		"postgres":                 {{IP: net.ParseIP("172.18.0.3")}},
		"metadata.google.internal": {{IP: net.ParseIP("169.254.169.254")}},
	}
	if _, err := policy.ValidateEndpoint(context.Background(), "https://push.example/topic"); err != nil {
		t.Fatalf("public HTTPS endpoint rejected: %v", err)
	}
	for _, endpoint := range []string{
		"http://push.example/topic",
		"https://postgres/admin",
		"https://metadata.google.internal/computeMetadata/v1/",
		"https://127.0.0.1/private",
	} {
		if _, err := policy.ValidateEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
}

func TestEndpointPolicyAllowsOnlyExactConfiguredPrivateOrigin(t *testing.T) {
	policy, err := NewEndpointPolicy("http://ntfy:80")
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = staticResolver{
		"ntfy":     {{IP: net.ParseIP("172.18.0.2")}},
		"postgres": {{IP: net.ParseIP("172.18.0.3")}},
	}
	if _, err := policy.ValidateEndpoint(context.Background(), "http://ntfy/topic-a"); err != nil {
		t.Fatalf("allowlisted ntfy origin rejected: %v", err)
	}
	for _, endpoint := range []string{
		"http://ntfy:81/topic-a",
		"https://ntfy/topic-a",
		"http://postgres:80/topic-a",
		"http://172.18.0.2:80/topic-a",
	} {
		if _, err := policy.ValidateEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("non-allowlisted private origin accepted: %s", endpoint)
		}
	}
}

func TestEndpointPolicyAlwaysRejectsAllowlistedLinkLocalMetadata(t *testing.T) {
	policy, err := NewEndpointPolicy(
		"http://ntfy:80",
		"http://metadata-v4:80",
		"http://metadata-v6:80",
	)
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = staticResolver{
		"ntfy":        {{IP: net.ParseIP("172.18.0.2")}},
		"metadata-v4": {{IP: net.ParseIP("169.254.169.254")}},
		"metadata-v6": {{IP: net.ParseIP("fe80::1")}},
	}
	if _, err := policy.ValidateEndpoint(context.Background(), "http://ntfy/topic"); err != nil {
		t.Fatalf("ordinary exact private origin rejected: %v", err)
	}
	for _, endpoint := range []string{
		"http://metadata-v4/latest/meta-data/",
		"http://metadata-v6/latest/meta-data/",
	} {
		if _, err := policy.ValidateEndpoint(context.Background(), endpoint); err == nil {
			t.Fatalf("allowlisted link-local metadata endpoint accepted: %s", endpoint)
		}
	}
}

func TestEndpointPolicyRevalidatesRedirectDestination(t *testing.T) {
	policy, err := NewEndpointPolicy("http://ntfy:80")
	if err != nil {
		t.Fatal(err)
	}
	policy.resolver = staticResolver{
		"ntfy":     {{IP: net.ParseIP("172.18.0.2")}},
		"postgres": {{IP: net.ParseIP("172.18.0.3")}},
	}
	allowed, _ := http.NewRequest(http.MethodPost, "http://ntfy/next", nil)
	if err := policy.checkRedirect(allowed, []*http.Request{{}}); err != nil {
		t.Fatalf("same allowlisted origin redirect rejected: %v", err)
	}
	blocked, _ := http.NewRequest(http.MethodPost, "http://postgres/internal", nil)
	if err := policy.checkRedirect(blocked, []*http.Request{{}}); err == nil {
		t.Fatal("redirect to neighboring private service was accepted")
	}
}
