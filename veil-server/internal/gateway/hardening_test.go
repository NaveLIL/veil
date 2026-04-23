package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/AegisSec/veil-server/internal/gateway"
)

func wsURL(s *httptest.Server) string {
	return "ws" + strings.TrimPrefix(s.URL, "http") + "/ws"
}

func TestWS_OriginAllowList_Reject(t *testing.T) {
	gateway.SetAllowedOrigins([]string{"https://app.veil.example"})
	t.Cleanup(func() { gateway.SetAllowedOrigins(nil) })

	server, _ := setupTestServer(t)
	defer server.Close()

	dialer := *websocket.DefaultDialer
	hdr := http.Header{}
	hdr.Set("Origin", "https://evil.example")
	_, resp, err := dialer.Dial(wsURL(server), hdr)
	if err == nil {
		t.Fatal("expected dial to fail for disallowed origin")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		t.Fatalf("want 403 from CheckOrigin, got %d (err=%v)", got, err)
	}
}

func TestWS_OriginAllowList_AllowMatching(t *testing.T) {
	gateway.SetAllowedOrigins([]string{"https://app.veil.example"})
	t.Cleanup(func() { gateway.SetAllowedOrigins(nil) })

	server, _ := setupTestServer(t)
	defer server.Close()

	hdr := http.Header{}
	hdr.Set("Origin", "https://app.veil.example")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server), hdr)
	if err != nil {
		t.Fatalf("expected dial success for allowed origin: %v", err)
	}
	conn.Close()
}

func TestWS_OriginAllowList_NativeClientNoOriginAllowed(t *testing.T) {
	// Tauri/mobile clients omit Origin entirely. Even with a strict allow-
	// list configured, those connections must succeed.
	gateway.SetAllowedOrigins([]string{"https://app.veil.example"})
	t.Cleanup(func() { gateway.SetAllowedOrigins(nil) })

	server, _ := setupTestServer(t)
	defer server.Close()

	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server), nil)
	if err != nil {
		t.Fatalf("native client (no Origin) must be allowed: %v", err)
	}
	conn.Close()
}

func TestWS_PerIPCap_RejectsExcessConnections(t *testing.T) {
	t.Setenv("VEIL_WS_MAX_CONNS_PER_IP", "2")
	t.Setenv("VEIL_WS_ORIGINS", "*")
	if err := gateway.ConfigureFromEnv(); err != nil {
		t.Fatalf("ConfigureFromEnv: %v", err)
	}
	t.Cleanup(func() {
		t.Setenv("VEIL_WS_MAX_CONNS_PER_IP", "0")
		t.Setenv("VEIL_WS_ORIGINS", "*")
		_ = gateway.ConfigureFromEnv()
		gateway.SetAllowedOrigins(nil)
	})

	server, _ := setupTestServer(t)
	defer server.Close()

	dial := func() (*websocket.Conn, *http.Response, error) {
		return websocket.DefaultDialer.Dial(wsURL(server), nil)
	}

	c1, _, err := dial()
	if err != nil {
		t.Fatalf("dial #1: %v", err)
	}
	defer c1.Close()
	c2, _, err := dial()
	if err != nil {
		t.Fatalf("dial #2: %v", err)
	}
	defer c2.Close()

	// 3rd connection from the same loopback IP must be refused with 429.
	_, resp, err := dial()
	if err == nil {
		t.Fatal("expected dial #3 to fail (per-IP cap)")
	}
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		t.Fatalf("want 429, got %d (err=%v)", got, err)
	}

	// After closing one, a new dial must succeed again.
	c1.Close()
	// Give the hub a beat to process unregister.
	time.Sleep(50 * time.Millisecond)
	c4, _, err := dial()
	if err != nil {
		t.Fatalf("dial after release: %v", err)
	}
	c4.Close()
}

// TestWS_OriginAllowList_FailClosed verifies the W7 ideal-fix behaviour:
// with no allow-list configured (nil/empty), browser-style requests carrying
// an Origin header are rejected, while native clients without Origin still
// connect successfully.
func TestWS_OriginAllowList_FailClosed(t *testing.T) {
	gateway.SetAllowedOrigins(nil)
	t.Cleanup(func() { gateway.SetAllowedOrigins(nil) })

	server, _ := setupTestServer(t)
	defer server.Close()

	// Browser request with Origin → 403.
	hdr := http.Header{}
	hdr.Set("Origin", "https://anyone.example")
	_, resp, err := websocket.DefaultDialer.Dial(wsURL(server), hdr)
	if err == nil {
		t.Fatal("expected dial to fail when allow-list is empty (fail-closed)")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		got := 0
		if resp != nil {
			got = resp.StatusCode
		}
		t.Fatalf("want 403 from CheckOrigin (fail-closed default), got %d (err=%v)", got, err)
	}

	// Native client (no Origin) must still connect — Tauri/mobile path.
	conn, _, err := websocket.DefaultDialer.Dial(wsURL(server), nil)
	if err != nil {
		t.Fatalf("native client (no Origin) must remain allowed under fail-closed default: %v", err)
	}
	conn.Close()
}

// TestWS_ConfigureFromEnv_RequiresOrigins documents the fail-fast contract
// of ConfigureFromEnv: an unset VEIL_WS_ORIGINS must produce an error so
// production deploys cannot accidentally inherit a permissive default.
func TestWS_ConfigureFromEnv_RequiresOrigins(t *testing.T) {
	t.Setenv("VEIL_WS_ORIGINS", "")
	if err := gateway.ConfigureFromEnv(); err == nil {
		t.Fatal("ConfigureFromEnv must return an error when VEIL_WS_ORIGINS is unset")
	}

	// Explicit "*" opt-in must succeed (and log a warning, not asserted here).
	t.Setenv("VEIL_WS_ORIGINS", "*")
	if err := gateway.ConfigureFromEnv(); err != nil {
		t.Fatalf("ConfigureFromEnv with explicit \"*\" must succeed, got: %v", err)
	}
	t.Cleanup(func() { gateway.SetAllowedOrigins(nil) })
}
