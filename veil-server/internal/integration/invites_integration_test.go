//go:build integration

// End-to-end tests for the invite surface (create/list/preview/use/revoke +
// expiry and max-uses enforcement). Run with the integration tag:
//
//	go test -tags=integration ./internal/integration/...
package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestInvites_CreateListAndUseJoinsServer(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	joiner := h.CreateUser("joiner")
	srvID := mkServer(t, h, owner, "Joinable")

	// Create invite.
	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/invites", map[string]any{
		"max_uses":        0,
		"expires_in_secs": 0,
	})
	if status != http.StatusCreated {
		t.Fatalf("create invite: status=%d body=%v", status, body)
	}
	code, _ := body["code"].(string)
	if code == "" {
		t.Fatalf("create invite: missing code (%v)", body)
	}

	// List invites — owner can see it.
	status, _, list := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/invites", nil)
	if status != http.StatusOK {
		t.Fatalf("list invites: status=%d body=%v", status, list)
	}
	invs, _ := list["invites"].([]any)
	if len(invs) == 0 {
		t.Fatalf("list invites: empty (%v)", list)
	}

	// Joiner uses invite — should be added to server.
	status, _, used := h.Do(joiner, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status != http.StatusOK {
		t.Fatalf("use invite: status=%d body=%v", status, used)
	}
	if used["id"] != srvID {
		t.Fatalf("use invite: returned server id=%v want %s", used["id"], srvID)
	}

	// Joiner can now list members.
	status, _, members := h.Do(joiner, http.MethodGet, "/v1/servers/"+srvID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("joiner list members after join: status=%d body=%v", status, members)
	}
	mlist, _ := members["members"].([]any)
	if len(mlist) != 2 {
		t.Fatalf("members after join: want 2, got %d (%v)", len(mlist), members)
	}
}

func TestInvites_PreviewIsPublicAndReturnsServer(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	srvID := mkServer(t, h, owner, "Public")
	code := mkInviteCode(t, h, owner, srvID)

	resp, err := http.Get(h.Server.URL + "/v1/invites/" + code)
	if err != nil {
		t.Fatalf("GET preview: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("preview: status=%d body=%s", resp.StatusCode, raw)
	}
	var parsed map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("decode preview: %v body=%s", err, raw)
	}
	srv, _ := parsed["server"].(map[string]any)
	if srv["id"] != srvID {
		t.Fatalf("preview: server id=%v want %s (%v)", srv["id"], srvID, parsed)
	}
}

func TestInvites_RevokePreventsUse(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	joiner := h.CreateUser("joiner")
	srvID := mkServer(t, h, owner, "Revoked")
	code := mkInviteCode(t, h, owner, srvID)

	status, _, _ := h.Do(owner, http.MethodDelete, "/v1/invites/"+code, nil)
	if status != http.StatusOK {
		t.Fatalf("revoke: status=%d", status)
	}

	status, _, body := h.Do(joiner, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status == http.StatusOK {
		t.Fatalf("revoked invite must not be usable, got 200 (%v)", body)
	}
}

func TestInvites_MaxUsesEnforced(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	first := h.CreateUser("first")
	second := h.CreateUser("second")
	srvID := mkServer(t, h, owner, "Capped")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/invites", map[string]any{
		"max_uses":        1,
		"expires_in_secs": 0,
	})
	if status != http.StatusCreated {
		t.Fatalf("create invite: status=%d body=%v", status, body)
	}
	code := body["code"].(string)

	// First use must succeed.
	status, _, _ = h.Do(first, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status != http.StatusOK {
		t.Fatalf("first use: status=%d", status)
	}

	// Second use must be rejected.
	status, _, body2 := h.Do(second, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status == http.StatusOK {
		t.Fatalf("second use over max_uses=1 must fail, got 200 (%v)", body2)
	}
}

func TestInvites_ExpiredCannotBeUsed(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	joiner := h.CreateUser("joiner")
	srvID := mkServer(t, h, owner, "Expiring")

	// 1-second TTL invite.
	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/invites", map[string]any{
		"max_uses":        0,
		"expires_in_secs": 1,
	})
	if status != http.StatusCreated {
		t.Fatalf("create invite: status=%d body=%v", status, body)
	}
	code := body["code"].(string)

	time.Sleep(1500 * time.Millisecond)

	status, _, body2 := h.Do(joiner, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status == http.StatusOK {
		t.Fatalf("expired invite must not be usable, got 200 (%v)", body2)
	}
}
