//go:build integration

// End-to-end tests for the servers REST surface (servers/channels/roles/
// invites). They drive the real http handler through authmw, against a
// disposable Postgres container. Run with:
//
//	go test -tags=integration ./internal/integration/...
package integration

import (
	"net/http"
	"testing"
)

func TestServers_CreateAndGet(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("alice")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers", map[string]string{"name": "Aegis"})
	if status != http.StatusOK {
		t.Fatalf("create: status=%d body=%v", status, body)
	}
	srvID, _ := body["id"].(string)
	if srvID == "" {
		t.Fatalf("create: missing id in %v", body)
	}

	status, _, got := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID, nil)
	if status != http.StatusOK {
		t.Fatalf("get: status=%d body=%v", status, got)
	}
	if got["name"] != "Aegis" {
		t.Fatalf("get: name=%v", got["name"])
	}
	if got["owner_id"] != owner.ID {
		t.Fatalf("get: owner_id=%v want %s", got["owner_id"], owner.ID)
	}
}

func TestServers_RejectsUnsigned(t *testing.T) {
	h := New(t)
	status, _ := h.DoUnsigned(http.MethodPost, "/v1/servers", map[string]string{"name": "x"})
	if status != http.StatusUnauthorized {
		t.Fatalf("want 401 for unsigned, got %d", status)
	}
}

func TestServers_NonOwnerCannotDelete(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	intruder := h.CreateUser("intruder")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers", map[string]string{"name": "Sec"})
	if status != http.StatusOK {
		t.Fatalf("create: status=%d %v", status, body)
	}
	srvID := body["id"].(string)

	status, _, _ = h.Do(intruder, http.MethodDelete, "/v1/servers/"+srvID, nil)
	if status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Fatalf("non-owner delete: want 403/401, got %d", status)
	}

	// Owner can still see it.
	status, _, got := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID, nil)
	if status != http.StatusOK || got["id"] != srvID {
		t.Fatalf("owner GET after intruder delete attempt: status=%d body=%v", status, got)
	}
}

func TestServers_ListIncludesNew(t *testing.T) {
	h := New(t)
	u := h.CreateUser("listuser")
	for _, name := range []string{"alpha", "beta", "gamma"} {
		status, _, _ := h.Do(u, http.MethodPost, "/v1/servers", map[string]string{"name": name})
		if status != http.StatusOK {
			t.Fatalf("create %s: status=%d", name, status)
		}
	}
	status, _, body := h.Do(u, http.MethodGet, "/v1/servers", nil)
	if status != http.StatusOK {
		t.Fatalf("list: status=%d body=%v", status, body)
	}
	list, _ := body["servers"].([]any)
	if len(list) < 3 {
		t.Fatalf("list: want >=3 servers, got %d (%v)", len(list), body)
	}
}

func TestChannels_CreateAndList(t *testing.T) {
	h := New(t)
	u := h.CreateUser("chanowner")
	_, _, body := h.Do(u, http.MethodPost, "/v1/servers", map[string]string{"name": "Chans"})
	srvID := body["id"].(string)

	status, _, ch := h.Do(u, http.MethodPost, "/v1/servers/"+srvID+"/channels", map[string]any{
		"name": "general",
		"type": 0,
	})
	if status != http.StatusOK {
		t.Fatalf("create channel: status=%d body=%v", status, ch)
	}
	if ch["name"] != "general" {
		t.Fatalf("created channel name=%v want general", ch["name"])
	}

	status, _, list := h.Do(u, http.MethodGet, "/v1/servers/"+srvID+"/channels", nil)
	if status != http.StatusOK {
		t.Fatalf("list channels: status=%d body=%v", status, list)
	}
	chs, _ := list["channels"].([]any)
	if len(chs) == 0 {
		t.Fatalf("list channels: empty (%v)", list)
	}
}

func TestServers_InvitePreviewIsPublic(t *testing.T) {
	// PreviewInvite is intentionally unsigned. An unknown invite code must
	// return a clean 404 (not 401), proving the route bypasses authmw.
	h := New(t)
	resp, err := http.Get(h.Server.URL + "/v1/invites/does-not-exist")
	if err != nil {
		t.Fatalf("GET preview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		t.Fatalf("preview must NOT require signing, got 401")
	}
	if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusGone {
		t.Fatalf("preview unknown code: want 404/410, got %d", resp.StatusCode)
	}
}
