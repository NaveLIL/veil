package gateway_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/gateway"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

func setupTestServer(t *testing.T) (*httptest.Server, *gateway.Hub) {
	t.Helper()

	origin, err := nodeorigin.ParseCanonical("https://node.example:443")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		PublicOrigin:     origin,
		AuthChallengeTTL: 30 * time.Second,
	}
	authSvc := auth.NewService(nil, cfg)
	hub := gateway.NewHub(authSvc, nil)
	go hub.Run()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := hub.Shutdown(ctx); err != nil {
			t.Errorf("hub shutdown: %v", err)
		}
		authSvc.Close()
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/v3/events", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocketV3(hub, w, r)
	})

	return httptest.NewServer(mux), hub
}
