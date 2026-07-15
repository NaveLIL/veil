package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
)

func TestBuildEnrollmentURLCarriesTokenOnceInFragment(t *testing.T) {
	token := make([]byte, db.NodeAccessInviteTokenSize)
	for i := range token {
		token[i] = byte(i + 1)
	}
	code := base64.RawURLEncoding.EncodeToString(token)
	got, err := buildEnrollmentURL(defaultEnrollmentURL, token)
	if err != nil {
		t.Fatal(err)
	}
	want := defaultEnrollmentURL + "#invite=" + code
	if got != want {
		t.Fatalf("URL = %q, want %q", got, want)
	}
	if strings.Count(got, code) != 1 {
		t.Fatalf("bearer token appears %d times, want once", strings.Count(got, code))
	}
}

func TestBuildEnrollmentURLRejectsLeakProneBaseURLs(t *testing.T) {
	token := make([]byte, db.NodeAccessInviteTokenSize)
	for name, baseURL := range map[string]string{
		"plain HTTP":     "http://veil.erez.pro/enroll",
		"query":          "https://veil.erez.pro/enroll?source=admin",
		"empty query":    "https://veil.erez.pro/enroll?",
		"fragment":       "https://veil.erez.pro/enroll#old",
		"credentials":    "https://operator:secret@veil.erez.pro/enroll",
		"relative":       "/enroll",
		"wrong path":     "https://veil.erez.pro/invite",
		"trailing slash": "https://veil.erez.pro/enroll/",
		"encoded path":   "https://veil.erez.pro/%65nroll",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := buildEnrollmentURL(baseURL, token); err == nil {
				t.Fatalf("unsafe base URL %q accepted", baseURL)
			}
		})
	}
}

func TestParseCreateInviteOptions(t *testing.T) {
	options, err := parseCreateInviteOptions([]string{
		"invite", "create", "--count", "20", "--expires", "168h",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.count != 20 || options.lifetime != 7*24*time.Hour || options.baseURL != defaultEnrollmentURL {
		t.Fatalf("unexpected options: %#v", options)
	}
}

func TestHelpDocumentsIdentityAndConsumptionSemantics(t *testing.T) {
	var output bytes.Buffer
	if err := run(context.Background(), []string{"invite", "create", "--help"}, &output); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"exactly one new account identity",
		"later sign-ins do not require an invite",
		"does not consume that invite",
		"printed exactly once",
	} {
		if !strings.Contains(output.String(), required) {
			t.Fatalf("help does not document %q:\n%s", required, output.String())
		}
	}
}
