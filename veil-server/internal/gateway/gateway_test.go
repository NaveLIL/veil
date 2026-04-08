package gateway_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/gateway"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

func setupTestServer(t *testing.T) (*httptest.Server, *gateway.Hub) {
	t.Helper()

	cfg := &config.Config{
		AuthChallengeTTL: 30 * time.Second,
		AuthMaxAttempts:  3,
	}
	authSvc := auth.NewService(nil, cfg)
	hub := gateway.NewHub(authSvc, nil)
	go hub.Run()

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocket(hub, w, r)
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := httptest.NewServer(mux)
	return server, hub
}

func TestHealthEndpoint(t *testing.T) {
	server, _ := setupTestServer(t)
	defer server.Close()

	resp, err := http.Get(server.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}

func TestWebSocket_ReceivesAuthChallenge(t *testing.T) {
	server, _ := setupTestServer(t)
	defer server.Close()

	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Server should send AuthChallenge as the first message
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	var env pb.Envelope
	if err := proto.Unmarshal(msg, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	challenge := env.GetAuthChallenge()
	if challenge == nil {
		t.Fatal("expected AuthChallenge payload, got nil")
	}
	if len(challenge.Challenge) != 32 {
		t.Fatalf("challenge length = %d, want 32", len(challenge.Challenge))
	}
}

func TestWebSocket_RejectsUnauthenticatedMessage(t *testing.T) {
	server, _ := setupTestServer(t)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// Read and discard the auth challenge
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	conn.ReadMessage()

	// Send a message without authenticating first
	sendMsg := &pb.Envelope{
		Seq: 1,
		Payload: &pb.Envelope_TypingEvent{
			TypingEvent: &pb.TypingEvent{
				ConversationId: "fake-convo",
			},
		},
	}
	data, _ := proto.Marshal(sendMsg)
	conn.WriteMessage(websocket.BinaryMessage, data)

	// Should receive an error response (401)
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, resp, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read error response: %v", err)
	}

	var errEnv pb.Envelope
	if err := proto.Unmarshal(resp, &errEnv); err != nil {
		t.Fatalf("unmarshal error envelope: %v", err)
	}

	errMsg := errEnv.GetError()
	if errMsg == nil {
		t.Fatal("expected Error payload for unauthenticated request")
	}
	if errMsg.Code != 401 {
		t.Errorf("error code = %d, want 401", errMsg.Code)
	}
}
