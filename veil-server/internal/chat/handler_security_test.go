package chat

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
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
