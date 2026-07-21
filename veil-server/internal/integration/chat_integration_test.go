//go:build integration

// End-to-end tests for the chat REST surface (DM, groups, message sync).
// Run with: go test -tags=integration ./internal/integration/...
package integration

import (
	"context"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
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
	if created, ok := body["created"].(bool); !ok || !created {
		t.Fatalf("first DM response created = %v, want true", body["created"])
	}

	status, _, reverse := h.Do(bob, http.MethodPost, "/v1/conversations/dm", map[string]string{
		"peer_user_id": alice.ID,
	})
	if status != http.StatusOK || reverse["conversation_id"] != convID || reverse["created"] != false {
		t.Fatalf("reversed DM lookup did not reuse conversation: status=%d body=%v", status, reverse)
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

func TestChat_ConcurrentFindOrCreateDMUsesOneCanonicalConversation(t *testing.T) {
	h := New(t)
	first := h.CreateUser("dm-race-first")
	second := h.CreateUser("dm-race-second")

	const calls = 32
	type result struct {
		id      string
		created bool
		err     error
	}
	results := make(chan result, calls)
	start := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(calls)
	for i := 0; i < calls; i++ {
		reversed := i%2 == 1
		go func() {
			defer workers.Done()
			<-start
			userID1, userID2 := first.ID, second.ID
			if reversed {
				userID1, userID2 = userID2, userID1
			}
			id, created, err := h.DB.FindOrCreateDM(context.Background(), userID1, userID2)
			results <- result{id: id, created: created, err: err}
		}()
	}
	close(start)
	workers.Wait()
	close(results)

	conversationID := ""
	createdCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent FindOrCreateDM: %v", result.err)
		}
		if conversationID == "" {
			conversationID = result.id
		}
		if result.id != conversationID {
			t.Fatalf("concurrent DM forked: got %s and %s", conversationID, result.id)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created=true count = %d, want exactly 1", createdCount)
	}

	reversedID, created, err := h.DB.FindOrCreateDM(context.Background(), second.ID, first.ID)
	if err != nil || reversedID != conversationID || created {
		t.Fatalf("post-race reversed lookup = %s, %v, %v; want %s, false, nil", reversedID, created, err, conversationID)
	}

	var storedConversations int
	if err := h.DB.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*)
		 FROM conversations conversation
		 JOIN conversation_members first_member ON first_member.conversation_id = conversation.id
		 JOIN conversation_members second_member ON second_member.conversation_id = conversation.id
		 WHERE conversation.conv_type = 0
		   AND first_member.user_id = $1::uuid
		   AND second_member.user_id = $2::uuid`,
		first.ID, second.ID,
	).Scan(&storedConversations); err != nil {
		t.Fatal(err)
	}
	if storedConversations != 1 {
		t.Fatalf("stored DM conversation count = %d, want 1", storedConversations)
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
	initialMate := h.CreateUser("initial-mate")
	lateMate := h.CreateUser("late-mate")

	status, _, body := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{
		"name": "Squad",
		"members": []map[string]string{{
			"user_id": initialMate.ID, "identity_key": hex.EncodeToString(initialMate.IdentityKey),
		}},
	})
	if status != http.StatusCreated {
		t.Fatalf("create group: status=%d body=%v", status, body)
	}
	groupID, _ := body["conversation_id"].(string)
	if groupID == "" {
		t.Fatalf("create group: missing conversation_id (%v)", body)
	}

	status, _, addBody := h.Do(owner, http.MethodPost, "/v1/groups/"+groupID+"/members", map[string]string{
		"user_id": lateMate.ID,
	})
	if status != http.StatusOK {
		t.Fatalf("add member: status=%d body=%v", status, addBody)
	}

	status, _, listBody := h.Do(owner, http.MethodGet, "/v1/groups/"+groupID+"/members", nil)
	if status != http.StatusOK {
		t.Fatalf("list members: status=%d body=%v", status, listBody)
	}
	members, _ := listBody["members"].([]any)
	if len(members) != 3 {
		t.Fatalf("list members: want 3 (owner + atomic member + later member), got %d (%v)", len(members), listBody)
	}
	for _, raw := range members {
		member, _ := raw.(map[string]any)
		if signingKey, _ := member["signing_key"].(string); len(signingKey) != 64 {
			t.Fatalf("group member missing 32-byte hex signing_key: %v", member)
		}
	}
}

func TestChat_InvitedCircleMemberCanResolveExactLiveDirectory(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("live-circle-owner")
	invitee := h.CreateUser("live-circle-invitee")
	intruder := h.CreateUser("live-circle-intruder")

	status, _, created := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{
		"name": "Immediately visible",
		"members": []map[string]string{{
			"user_id": invitee.ID, "identity_key": hex.EncodeToString(invitee.IdentityKey),
		}},
	})
	if status != http.StatusCreated {
		t.Fatalf("create Circle: status=%d body=%v", status, created)
	}
	conversationID := created["conversation_id"].(string)

	status, _, discovered := h.Do(
		invitee,
		http.MethodGet,
		"/v1/conversations/"+conversationID,
		nil,
	)
	if status != http.StatusOK {
		t.Fatalf("invitee exact discovery: status=%d body=%v", status, discovered)
	}
	if discovered["id"] != conversationID || discovered["name"] != "Immediately visible" {
		t.Fatalf("unexpected exact conversation projection: %v", discovered)
	}
	if members, _ := discovered["members"].([]any); len(members) != 2 {
		t.Fatalf("exact discovery member count=%d, want 2 (%v)", len(members), discovered)
	}

	status, _, _ = h.Do(
		intruder,
		http.MethodGet,
		"/v1/conversations/"+conversationID,
		nil,
	)
	if status != http.StatusNotFound {
		t.Fatalf("inaccessible exact UUID leaked membership: status=%d", status)
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

	_, _, body := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{
		"name": "Closed",
		"members": []map[string]string{{
			"user_id": mate.ID, "identity_key": hex.EncodeToString(mate.IdentityKey),
		}},
	})
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

func TestCircleCreateRejectsOrphanAndStaleLocatorAtomically(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("circle-atomic-owner")
	target := h.CreateUser("circle-atomic-target")
	var before int
	if err := h.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM conversations WHERE conv_type=1`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	for name, members := range map[string]any{
		"orphan": []map[string]string{},
		"stale identity": []map[string]string{{
			"user_id": target.ID, "identity_key": strings.Repeat("00", 32),
		}},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, _ := h.Do(owner, http.MethodPost, "/v1/groups", map[string]any{
				"name": "Must not persist", "members": members,
			})
			if status != http.StatusBadRequest {
				t.Fatalf("invalid Circle create status=%d", status)
			}
		})
	}
	var after int
	if err := h.DB.Pool.QueryRow(t.Context(), `SELECT count(*) FROM conversations WHERE conv_type=1`).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("failed Circle create left orphan rows: before=%d after=%d", before, after)
	}
}
