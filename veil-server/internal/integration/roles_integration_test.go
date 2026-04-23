//go:build integration

// End-to-end tests for the role surface (create/list/update/delete +
// assign/unassign on members). Run with the integration tag:
//
//	go test -tags=integration ./internal/integration/...
package integration

import (
	"net/http"
	"testing"
)

// helper: owner creates a server and returns its id.
func mkServer(t *testing.T, h *Harness, owner *User, name string) string {
	t.Helper()
	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers", map[string]string{"name": name})
	if status != http.StatusCreated {
		t.Fatalf("create server: status=%d body=%v", status, body)
	}
	id, _ := body["id"].(string)
	if id == "" {
		t.Fatalf("create server: missing id (%v)", body)
	}
	return id
}

// helper: owner mints an invite, returns code.
func mkInviteCode(t *testing.T, h *Harness, owner *User, srvID string) string {
	t.Helper()
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
	return code
}

// helper: user joins the given server via invite code.
func joinViaInvite(t *testing.T, h *Harness, joiner *User, code string) {
	t.Helper()
	status, _, body := h.Do(joiner, http.MethodPost, "/v1/invites/"+code+"/use", nil)
	if status != http.StatusOK {
		t.Fatalf("use invite: status=%d body=%v", status, body)
	}
}

func TestRoles_OwnerCreatesAndLists(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	srvID := mkServer(t, h, owner, "RolesSrv")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/roles", map[string]any{
		"name":        "moderator",
		"permissions": 64, // PermKickMembers
	})
	if status != http.StatusCreated {
		t.Fatalf("create role: status=%d body=%v", status, body)
	}
	roleID, _ := body["id"].(string)
	if roleID == "" {
		t.Fatalf("create role: missing id (%v)", body)
	}
	if body["name"] != "moderator" {
		t.Fatalf("create role: name=%v want moderator", body["name"])
	}

	status, _, list := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/roles", nil)
	if status != http.StatusOK {
		t.Fatalf("list roles: status=%d body=%v", status, list)
	}
	roles, _ := list["roles"].([]any)
	if len(roles) < 2 {
		// expect at least @everyone (default) + moderator
		t.Fatalf("list roles: want >=2 (default+new), got %d (%v)", len(roles), list)
	}
	found := false
	for _, r := range roles {
		m, _ := r.(map[string]any)
		if m["id"] == roleID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("created role not in list: %v", list)
	}
}

func TestRoles_NonAdminCannotCreate(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	intruder := h.CreateUser("intruder")
	srvID := mkServer(t, h, owner, "Locked")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, intruder, code)

	status, _, body := h.Do(intruder, http.MethodPost, "/v1/servers/"+srvID+"/roles", map[string]any{
		"name":        "rogue",
		"permissions": 0,
	})
	if status != http.StatusForbidden {
		t.Fatalf("non-admin create role: want 403, got %d (%v)", status, body)
	}
}

func TestRoles_AssignAndUnassign(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	srvID := mkServer(t, h, owner, "Crew")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, mate, code)

	// Owner creates a custom role.
	_, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/roles", map[string]any{
		"name":        "captain",
		"permissions": 64,
	})
	roleID := body["id"].(string)

	// Assign to mate.
	status, _, asg := h.Do(owner, http.MethodPut,
		"/v1/servers/"+srvID+"/members/"+mate.ID+"/roles/"+roleID, nil)
	if status != http.StatusOK {
		t.Fatalf("assign: status=%d body=%v", status, asg)
	}

	// Verify via ListMembers.
	status, _, mlist := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("list members: status=%d body=%v", status, mlist)
	}
	members, _ := mlist["members"].([]any)
	mateRoles := []any{}
	for _, m := range members {
		mm, _ := m.(map[string]any)
		if mm["user_id"] == mate.ID {
			mateRoles, _ = mm["role_ids"].([]any)
			break
		}
	}
	hasRole := false
	for _, r := range mateRoles {
		if r == roleID {
			hasRole = true
		}
	}
	if !hasRole {
		t.Fatalf("mate missing assigned role %s in %v", roleID, mateRoles)
	}

	// Unassign.
	status, _, _ = h.Do(owner, http.MethodDelete,
		"/v1/servers/"+srvID+"/members/"+mate.ID+"/roles/"+roleID, nil)
	if status != http.StatusOK {
		t.Fatalf("unassign: status=%d", status)
	}

	// Verify gone.
	_, _, mlist2 := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/members", nil)
	members2, _ := mlist2["members"].([]any)
	for _, m := range members2 {
		mm, _ := m.(map[string]any)
		if mm["user_id"] == mate.ID {
			rr, _ := mm["role_ids"].([]any)
			for _, r := range rr {
				if r == roleID {
					t.Fatalf("role still present after unassign: %v", rr)
				}
			}
		}
	}
}

func TestRoles_UpdateAndDelete(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	srvID := mkServer(t, h, owner, "Edit")

	_, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/roles", map[string]any{
		"name":        "old",
		"permissions": 0,
	})
	roleID := body["id"].(string)

	newName := "renamed"
	status, _, _ := h.Do(owner, http.MethodPatch,
		"/v1/servers/"+srvID+"/roles/"+roleID, map[string]any{"name": newName})
	if status != http.StatusOK {
		t.Fatalf("update role: status=%d", status)
	}

	_, _, list := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/roles", nil)
	roles, _ := list["roles"].([]any)
	gotName := ""
	for _, r := range roles {
		m, _ := r.(map[string]any)
		if m["id"] == roleID {
			gotName, _ = m["name"].(string)
		}
	}
	if gotName != newName {
		t.Fatalf("update did not stick: name=%q want %q", gotName, newName)
	}

	status, _, _ = h.Do(owner, http.MethodDelete,
		"/v1/servers/"+srvID+"/roles/"+roleID, nil)
	if status != http.StatusOK {
		t.Fatalf("delete role: status=%d", status)
	}

	_, _, list2 := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/roles", nil)
	roles2, _ := list2["roles"].([]any)
	for _, r := range roles2 {
		m, _ := r.(map[string]any)
		if m["id"] == roleID {
			t.Fatalf("role still present after delete: %v", m)
		}
	}
}
