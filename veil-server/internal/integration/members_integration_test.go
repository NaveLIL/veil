//go:build integration

// End-to-end tests for member-management endpoints (list/kick/leave). Run
// with the integration tag:
//
//	go test -tags=integration ./internal/integration/...
package integration

import (
	"net/http"
	"testing"
)

func TestMembers_OwnerSeesAllMembers(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	srvID := mkServer(t, h, owner, "Crewed")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, mate, code)

	status, _, body := h.Do(owner, http.MethodGet, "/v1/servers/"+srvID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("list members: status=%d body=%v", status, body)
	}
	members, _ := body["members"].([]any)
	if len(members) != 2 {
		t.Fatalf("members: want 2 got %d (%v)", len(members), body)
	}
}

func TestMembers_NonMemberCannotList(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	intruder := h.CreateUser("intruder")
	srvID := mkServer(t, h, owner, "Sealed")

	status, _, _ := h.Do(intruder, http.MethodGet, "/v1/servers/"+srvID+"/members", nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-member list: want 403, got %d", status)
	}
}

func TestMembers_OwnerKicksAndAccessRevoked(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	srvID := mkServer(t, h, owner, "KickIt")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, mate, code)

	// Owner kicks mate.
	status, _, body := h.Do(owner, http.MethodDelete,
		"/v1/servers/"+srvID+"/members/"+mate.ID, map[string]string{"reason": "spam"})
	if status != http.StatusOK {
		t.Fatalf("kick: status=%d body=%v", status, body)
	}

	// Kicked user can no longer fetch the server.
	status, _, _ = h.Do(mate, http.MethodGet, "/v1/servers/"+srvID, nil)
	if status != http.StatusForbidden {
		t.Fatalf("kicked user GET: want 403, got %d", status)
	}
}

func TestMembers_NonAdminCannotKick(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	other := h.CreateUser("other")
	srvID := mkServer(t, h, owner, "Civil")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, mate, code)
	joinViaInvite(t, h, other, code)

	// Regular member cannot kick another member.
	status, _, body := h.Do(mate, http.MethodDelete,
		"/v1/servers/"+srvID+"/members/"+other.ID, nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin kick: want 403, got %d (%v)", status, body)
	}
}

func TestMembers_OwnerCannotKickSelf(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	srvID := mkServer(t, h, owner, "Lonely")

	status, _, body := h.Do(owner, http.MethodDelete,
		"/v1/servers/"+srvID+"/members/"+owner.ID, nil)
	if status == http.StatusOK {
		t.Fatalf("owner self-kick must fail, got 200 (%v)", body)
	}
}

func TestMembers_OwnerCannotLeave(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	srvID := mkServer(t, h, owner, "Owned")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+srvID+"/leave", nil)
	if status == http.StatusOK {
		t.Fatalf("owner leave must fail, got 200 (%v)", body)
	}
}

func TestMembers_RegularMemberCanLeave(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	srvID := mkServer(t, h, owner, "Leavable")
	code := mkInviteCode(t, h, owner, srvID)
	joinViaInvite(t, h, mate, code)

	status, _, body := h.Do(mate, http.MethodPost, "/v1/servers/"+srvID+"/leave", nil)
	if status != http.StatusOK {
		t.Fatalf("leave: status=%d body=%v", status, body)
	}

	// Mate no longer sees the server.
	status, _, _ = h.Do(mate, http.MethodGet, "/v1/servers/"+srvID, nil)
	if status != http.StatusForbidden {
		t.Fatalf("after leave GET: want 403, got %d", status)
	}
}
