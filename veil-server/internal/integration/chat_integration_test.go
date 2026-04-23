//go:build integration

// End-to-end tests for the chat REST surface (DM, groups, message sync).
// Run with: go test -tags=integration ./internal/integration/...
package integration

import (
	"net/http"
	"testing"
)

func TestChat_CreateDMHappyPath(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("alice")
	bob := h.CreateUser("bob")

	status, _, body := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": bob.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("create DM: status=%d body=%v", status, body)
	}
	convID, _ := body["conversation_id"].(string)
	if convID == "" {
		t.Fatalf("create DM: missing conversation_id in %v", body)
	}

	// Both members should see each other in /members.
	status, _, members := h.Do(alice, http.MethodGet, "/v1/conversations/"+convID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("members: status=%d body=%v", status, members)
	}
	list, _ := members["members"].([]any)
	if len(list) != 2 {
		t.Fatalf("members: want 2 got %d (%v)", len(list), members)
	}
}

func TestChat_GetMessagesForbiddenForNonMember(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("alice")
	bob := h.CreateUser("bob")
	intruder := h.CreateUser("intruder")

	_, _, body := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": bob.ID,
	})
	convID := body["conversation_id"].(string)

	status, _, _ := h.Do(intruder, http.MethodGet, "/v1/messages/"+convID, nil)
	if status != http.StatusForbidden {
		t.Fatalf("non-member GET: want 403, got %d", status)
	}
}

func TestChat_GetMessagesEmptyForNewConversation(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("alice")
	bob := h.CreateUser("bob")

	_, _, body := h.Do(alice, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": bob.ID,
	})
	convID := body["conversation_id"].(string)

	status, _, msgs := h.Do(alice, http.MethodGet, "/v1/messages/"+convID, nil)
	if status != http.StatusOK {
		t.Fatalf("get messages: status=%d body=%v", status, msgs)
	}
	list, _ := msgs["messages"].([]any)
	if len(list) != 0 {
		t.Fatalf("expected empty message list, got %d", len(list))
	}
}

func TestChat_CreateGroupAndAddMember(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{
		"name":    "Squad",
		"members": []string{},
	})
	if status != http.StatusOK {
		t.Fatalf("create group: status=%d body=%v", status, body)
	}
	groupID, _ := body["conversation_id"].(string)
	if groupID == "" {
		t.Fatalf("create group: missing conversation_id (%v)", body)
	}

	status, _, addBody := h.Do(owner, http.MethodPost, "/v1/groups/"+groupID+"/members", map[string]string{
		"user_id": mate.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("add member: status=%d body=%v", status, addBody)
	}

	status, _, listBody := h.Do(owner, http.MethodGet, "/v1/groups/"+groupID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("list members: status=%d body=%v", status, listBody)
	}
	members, _ := listBody["members"].([]any)
	if len(members) < 2 {
		t.Fatalf("list members: want >=2 (owner + mate), got %d (%v)", len(members), listBody)
	}
}

func TestChat_RejectsUnsigned(t *testing.T) {
	h := New(t)
	status, _ := h.DoUnsigned(http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": "anything",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("want 401 for unsigned, got %d", status)
	}
}

func TestChat_AddGroupMember_NonMemberCannotAdd(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("owner")
	mate := h.CreateUser("mate")
	intruder := h.CreateUser("intruder")

	_, _, body := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{"name": "Closed"})
	groupID := body["conversation_id"].(string)

	status, _, errBody := h.Do(intruder, http.MethodPost, "/v1/groups/"+groupID+"/members", map[string]string{
		"user_id": mate.ID,
	})
	if status == http.StatusOK {
		t.Fatalf("intruder must not add members; got 200 body=%v", errBody)
	}
	if status != http.StatusForbidden && status != http.StatusUnauthorized {
		t.Fatalf("want 401/403 for non-member add, got %d (%v)", status, errBody)
	}
}
