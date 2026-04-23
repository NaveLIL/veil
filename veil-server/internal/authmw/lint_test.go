package authmw_test

// W3 invariant lint: handlers MUST only read X-User-ID after the
// authmw.RequireSigned middleware has set it from a verified Ed25519
// signature. This test enforces the invariant by walking every Go source
// file in internal/{auth,chat,servers}/ and asserting that whenever the
// magic string `r.Header.Get("X-User-ID")` appears, the same package also
// wraps its routes through `mw.RequireSigned(...)` (or equivalent
// `signed(...)` helper that ultimately invokes RequireSigned).
//
// Background: the legacy unsigned bypass (`allowUnsigned=true`) was deleted
// in W3, but a future regression could still expose user data if a new
// handler reads X-User-ID directly while being registered without the
// middleware. This test fails fast when that happens.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestW3_HandlersUseSignedMiddlewareWhenReadingXUserID(t *testing.T) {
	// Walk up from this test file to the veil-server module root.
	root, err := moduleRoot()
	if err != nil {
		t.Fatalf("locate module root: %v", err)
	}

	pkgs := []string{"internal/auth", "internal/chat", "internal/servers"}
	for _, pkg := range pkgs {
		dir := filepath.Join(root, pkg)
		readsXUserID, hasMiddleware := false, false
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			if strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s/%s: %v", pkg, e.Name(), err)
			}
			body := string(data)
			if strings.Contains(body, `r.Header.Get("X-User-ID")`) {
				readsXUserID = true
			}
			if strings.Contains(body, ".RequireSigned(") {
				hasMiddleware = true
			}
		}
		if readsXUserID && !hasMiddleware {
			t.Fatalf("%s reads X-User-ID but never wraps a handler with RequireSigned — every X-User-ID consumer MUST be gated by authmw.RequireSigned (W3 invariant)", pkg)
		}
	}
}

// moduleRoot finds the directory containing go.mod, walking up from the
// current test file's working directory.
func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
