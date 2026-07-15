package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type pingerFunc func(context.Context) error

func (f pingerFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestReadinessReflectsDatabaseAvailability(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{name: "ready", status: http.StatusOK, body: `{"status":"ready"}`},
		{name: "database unavailable", err: errors.New("offline"), status: http.StatusServiceUnavailable, body: `{"status":"unavailable"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := readinessHandler(pingerFunc(func(context.Context) error { return tc.err }))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if recorder.Code != tc.status || recorder.Body.String() != tc.body {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), tc.status, tc.body)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestNodeAccessPassKeepsBearerOutOfHTTPRequestsAndCaches(t *testing.T) {
	recorder := httptest.NewRecorder()
	nodeAccessPassHandler(enrollHTML).ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/enroll#invite=not-sent-by-http", nil),
	)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	for name, want := range map[string]string{
		"Cache-Control":          "no-store",
		"Referrer-Policy":        "no-referrer",
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-Robots-Tag":           "noindex, nofollow",
	} {
		if got := recorder.Header().Get(name); got != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	csp := recorder.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "connect-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("unexpected Content-Security-Policy: %q", csp)
	}

	page := recorder.Body.String()
	for _, required := range []string{
		"location.hash",
		"history.replaceState",
		"veil://enroll/v1?origin=",
		"&invite=",
		"document.getElementById('origin').textContent = location.origin",
		"location.origin + '/enroll#invite=' + token",
		"navigator.clipboard.writeText(enrollmentLink)",
	} {
		if !strings.Contains(page, required) {
			t.Fatalf("access pass page is missing %q", required)
		}
	}
	for _, forbidden := range []string{"location.search", "fetch("} {
		if strings.Contains(page, forbidden) {
			t.Fatalf("access pass page must not contain %q", forbidden)
		}
	}
	if clearAt, validateAt := strings.Index(page, "history.replaceState"), strings.Index(page, "const canonical"); clearAt < 0 || validateAt < 0 || clearAt > validateAt {
		t.Fatal("the bearer fragment must be removed before validation returns")
	}
}

func TestParseCORSOriginsFailsClosedWhenUnset(t *testing.T) {
	t.Setenv("VEIL_CORS_ORIGINS", "")
	got, err := parseCORSOrigins()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unset origins = %v, want deny-all", got)
	}
}

func TestParseCORSOriginsValidatesExactOrigins(t *testing.T) {
	t.Setenv("VEIL_CORS_ORIGINS", "https://APP.example, http://127.0.0.1:1420")
	got, err := parseCORSOrigins()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.example", "http://127.0.0.1:1420"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("origins = %v, want %v", got, want)
	}

	t.Setenv("VEIL_CORS_ORIGINS", "https://app.example/path")
	if _, err := parseCORSOrigins(); err == nil {
		t.Fatal("origin containing a path must be rejected")
	}
}

func TestSourceMetadataUsesOnlyCanonicalCommit(t *testing.T) {
	const commit = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
	metadata, err := sourceMetadataForBuild(commit, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	const revision = "abcdef0123456789abcdef0123456789abcdef01"
	if metadata.Revision != revision ||
		metadata.ArchiveURL != projectRepositoryURL+"/archive/"+revision+".tar.gz" ||
		metadata.BrowseURL != projectRepositoryURL+"/tree/"+revision {
		t.Fatalf("unexpected source metadata: %#v", metadata)
	}

	for _, invalid := range []string{
		"development",
		"abcdef0123456789abcdef0123456789abcdef0g",
		"abcdef0123456789abcdef0123456789abcdef01/../../issues",
	} {
		metadata, err := sourceMetadataForBuild(invalid, "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		if metadata.Revision != "" || metadata.ArchiveURL != "" || metadata.BrowseURL != projectRepositoryURL {
			t.Fatalf("sourceMetadataForBuild(%q) = %#v, want repository fallback", invalid, metadata)
		}
	}
}

func TestSourceMetadataOverrideIsCompleteAndHTTPS(t *testing.T) {
	const revision = "abcdef0123456789abcdef0123456789abcdef01"
	metadata, err := sourceMetadataForBuild(
		"development",
		revision,
		"https://code.example/veil/source.tar.gz",
		"https://code.example/veil/tree/"+revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.Revision != revision || metadata.ArchiveURL != "https://code.example/veil/source.tar.gz" {
		t.Fatalf("unexpected override metadata: %#v", metadata)
	}

	invalid := []struct {
		name     string
		revision string
		archive  string
		browse   string
	}{
		{name: "partial", revision: revision},
		{name: "short revision", revision: "abc", archive: "https://code.example/source.tar.gz", browse: "https://code.example/tree"},
		{name: "non https", revision: revision, archive: "http://code.example/source.tar.gz", browse: "https://code.example/tree"},
		{name: "credentialed", revision: revision, archive: "https://user@code.example/source.tar.gz", browse: "https://code.example/tree"},
		{name: "ephemeral query", revision: revision, archive: "https://code.example/source.tar.gz?token=x", browse: "https://code.example/tree"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := sourceMetadataForBuild("development", tc.revision, tc.archive, tc.browse); err == nil {
				t.Fatal("expected invalid source metadata to fail")
			}
		})
	}
}
