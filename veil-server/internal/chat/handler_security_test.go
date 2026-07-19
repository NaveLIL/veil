package chat

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
)

func TestResolveDMPeerRejectsThirdPartyConversation(t *testing.T) {
	_, err := resolveDMPeer("alice", CreateDMRequest{UserID1: "bob", UserID2: "mallory"})
	if !errors.Is(err, errDMPrincipalMismatch) {
		t.Fatalf("expected principal mismatch, got %v", err)
	}
}

func TestResolveDMPeerAcceptsCanonicalAndBoundLegacyRequests(t *testing.T) {
	tests := []CreateDMRequest{
		{PeerUserID: "bob"},
		{UserID1: "alice", UserID2: "bob"},
		{UserID1: "bob", UserID2: "alice"},
	}
	for _, req := range tests {
		peer, err := resolveDMPeer("alice", req)
		if err != nil || peer != "bob" {
			t.Fatalf("resolveDMPeer(%+v) = %q, %v; want bob, nil", req, peer, err)
		}
	}
}

func TestPageCursorIsStrictlyScoped(t *testing.T) {
	createdAt := time.Date(2026, 7, 11, 1, 2, 3, 456, time.UTC)
	id := "11111111-1111-4111-8111-111111111111"

	raw, err := encodePageCursor("messages", "conversation-a", createdAt, id)
	if err != nil {
		t.Fatalf("encode cursor: %v", err)
	}
	cursor, err := decodePageCursor(raw, "messages", "conversation-a")
	if err != nil {
		t.Fatalf("decode matching cursor: %v", err)
	}
	if cursor.ID != id || !cursor.CreatedAt.Equal(createdAt) {
		t.Fatalf("cursor round trip = %+v", cursor)
	}

	for _, test := range []struct {
		name  string
		kind  string
		scope string
	}{
		{name: "cross conversation", kind: "messages", scope: "conversation-b"},
		{name: "cross user", kind: "conversations", scope: "conversation-a"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodePageCursor(raw, test.kind, test.scope); err == nil {
				t.Fatal("out-of-scope cursor was accepted")
			}
		})
	}
}

func TestParsePageLimitRejectsUnboundedValues(t *testing.T) {
	for _, raw := range []string{"0", "-1", "101", "1.5", "garbage"} {
		if _, err := parsePageLimit(raw, 100, 100); err == nil {
			t.Fatalf("limit %q was accepted", raw)
		}
	}
	if got, err := parsePageLimit("25", 100, 100); err != nil || got != 25 {
		t.Fatalf("valid limit = %d, %v; want 25, nil", got, err)
	}
}

func TestMessageHistoryCandidateLimitBoundsLegacyRequests(t *testing.T) {
	for requested, want := range map[int]int{
		1: 1, 25: 25, 100: 25, 500: 25,
	} {
		if got := messageHistoryCandidateLimit(requested); got != want {
			t.Fatalf("messageHistoryCandidateLimit(%d)=%d, want %d", requested, got, want)
		}
	}
}

func TestMessageHistoryWireBudgetSelectsLargestExactPrefix(t *testing.T) {
	messages, cursorRows := maxWireHistoryRows(t, 25)
	encoded, included, err := encodeMessageHistoryPageWithinBudget(
		messages,
		cursorRows,
		false,
		maxMessageHistoryResponseBytes,
	)
	if err != nil {
		t.Fatalf("encode bounded history page: %v", err)
	}
	if included <= 0 || included >= len(messages) {
		t.Fatalf("included=%d, want a non-empty strict prefix of %d", included, len(messages))
	}
	if len(encoded) > maxMessageHistoryResponseBytes {
		t.Fatalf("encoded page=%d bytes, budget=%d", len(encoded), maxMessageHistoryResponseBytes)
	}
	if encoded[len(encoded)-1] != '\n' {
		t.Fatal("encoded page does not include its measured trailing newline")
	}

	var page messageHistoryPageJSON
	if err := json.Unmarshal(encoded, &page); err != nil {
		t.Fatalf("decode bounded history page: %v", err)
	}
	if page.Count != included || len(page.Messages) != included || page.NextCursor == nil {
		t.Fatalf("bounded page count/messages/cursor = %d/%d/%v", page.Count, len(page.Messages), page.NextCursor)
	}
	cursor, err := decodePageCursor(*page.NextCursor, "messages", cursorRows[0].ConversationID)
	if err != nil {
		t.Fatalf("decode bounded page cursor: %v", err)
	}
	if cursor.ID != cursorRows[included-1].ID || !cursor.CreatedAt.Equal(cursorRows[included-1].CreatedAt) {
		t.Fatalf("cursor=%+v, want boundary row %+v", cursor, cursorRows[included-1])
	}

	tooMany := included + 1
	var nextCursor *string
	if tooMany < len(messages) {
		cursor, err := encodePageCursor(
			"messages",
			cursorRows[tooMany-1].ConversationID,
			cursorRows[tooMany-1].CreatedAt,
			cursorRows[tooMany-1].ID,
		)
		if err != nil {
			t.Fatalf("encode larger candidate cursor: %v", err)
		}
		nextCursor = &cursor
	}
	oversized, err := marshalMessageHistoryPage(messageHistoryPageJSON{
		Count:      tooMany,
		Messages:   messages[:tooMany],
		NextCursor: nextCursor,
	})
	if err != nil {
		t.Fatalf("encode larger candidate: %v", err)
	}
	if len(oversized) <= maxMessageHistoryResponseBytes {
		t.Fatalf("prefix %d unexpectedly fits in %d bytes", tooMany, len(oversized))
	}
}

func TestMessageHistoryWireBudgetFitsMaxRowAndFailsClosedAboveIt(t *testing.T) {
	messages, cursorRows := maxWireHistoryRows(t, 1)
	encoded, included, err := encodeMessageHistoryPageWithinBudget(
		messages,
		cursorRows,
		false,
		maxMessageHistoryResponseBytes,
	)
	if err != nil || included != 1 || len(encoded) > maxMessageHistoryResponseBytes {
		t.Fatalf("max admitted row encoded=%d included=%d err=%v", len(encoded), included, err)
	}

	messages[0].Ciphertext = strings.Repeat("ab", maxMessageHistoryResponseBytes)
	encoded, included, err = encodeMessageHistoryPageWithinBudget(
		messages,
		cursorRows,
		false,
		maxMessageHistoryResponseBytes,
	)
	if !errors.Is(err, errMessageHistoryRowExceedsWireBudget) || encoded != nil || included != 0 {
		t.Fatalf("oversized first row encoded=%d included=%d err=%v", len(encoded), included, err)
	}
}

func maxWireHistoryRows(t *testing.T, count int) ([]messageHistoryMessageJSON, []db.Message) {
	t.Helper()
	const conversationID = "11111111-1111-4111-8111-111111111111"
	const senderID = "22222222-2222-4222-8222-222222222222"
	ciphertext := strings.Repeat("ab", 64*1024)
	header := strings.Repeat("cd", 42)
	username := strings.Repeat("<", 128)
	messages := make([]messageHistoryMessageJSON, 0, count)
	cursorRows := make([]db.Message, 0, count)
	for index := 1; index <= count; index++ {
		id := fmt.Sprintf("00000000-0000-4000-8000-%012d", index)
		createdAt := time.Date(2026, 7, 18, 0, 0, 0, index, time.UTC)
		reactions := make([]messageHistoryReactionJSON, 0, db.MaxReactionsPerMessage)
		for reaction := 0; reaction < db.MaxReactionsPerMessage; reaction++ {
			reactions = append(reactions, messageHistoryReactionJSON{
				Emoji:    strings.Repeat("<", 60) + fmt.Sprintf("%04x", reaction),
				UserID:   senderID,
				Username: username,
			})
		}
		messages = append(messages, messageHistoryMessageJSON{
			ID:                id,
			ConversationID:    conversationID,
			SenderID:          senderID,
			SenderIdentityKey: strings.Repeat("11", 32),
			SenderSigningKey:  strings.Repeat("22", 32),
			Ciphertext:        ciphertext,
			Header:            header,
			MsgType:           0,
			Reactions:         reactions,
			Attachments:       make([]messageHistoryAttachmentJSON, 0),
			CreatedAt:         createdAt.Format(time.RFC3339Nano),
			ServerTimestamp:   createdAt.UnixMilli(),
			RevisionTimestamp: createdAt.UnixMilli(),
			CryptoProfile:     "legacy_unknown",
		})
		cursorRows = append(cursorRows, db.Message{
			ID:             id,
			ConversationID: conversationID,
			CreatedAt:      createdAt,
		})
	}
	return messages, cursorRows
}

func TestRegisteredChatReadsSetNoStoreBeforeSignatureMiddleware(t *testing.T) {
	middleware := authmw.New(authmw.LookupFunc(
		func(context.Context, string) (ed25519.PublicKey, error) {
			t.Fatal("unsigned request unexpectedly reached key lookup")
			return nil, nil
		},
	))
	defer middleware.Close()
	handler := NewHandler(nil, middleware, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	for _, target := range []string{
		"/v1/messages/11111111-1111-4111-8111-111111111111?limit=25",
		"/v1/conversations?limit=100",
		"/v1/conversations/11111111-1111-4111-8111-111111111111/members",
		"/v1/conversations/11111111-1111-4111-8111-111111111111/device-directory",
		"/v1/groups/11111111-1111-4111-8111-111111111111/members",
	} {
		t.Run(target, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, target, nil)
			response := httptest.NewRecorder()
			mux.ServeHTTP(response, request)

			if response.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s, want 401", response.Code, response.Body.String())
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control=%q, want no-store", got)
			}
		})
	}
}
