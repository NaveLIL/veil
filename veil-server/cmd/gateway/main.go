package main

import (
	"context"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/gateway"
	"github.com/AegisSec/veil-server/internal/httpmw"
	"github.com/AegisSec/veil-server/internal/metrics"
	"github.com/AegisSec/veil-server/internal/servers"
)

func main() {
	// Switch to structured JSON logging via slog (consumed by httpmw.AccessLog).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg := config.Load()

	// Connect to PostgreSQL
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	database, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer database.Close()
	log.Println("database connected")

	// Initialize services
	authSvc := auth.NewService(database, cfg)
	chatSvc := chat.NewService(database, cfg)

	// Start hub
	hub := gateway.NewHub(authSvc, chatSvc)
	gateway.ConfigureFromEnv()
	go hub.Run()

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocket(hub, w, r)
	})

	// Servers / Channels / Roles / Invites REST endpoints
	serversSvc := servers.NewService(database, hub)

	// Shared signature middleware + per-user rate limit. The middleware reads
	// signing keys via the servers service (any of the three would do; they
	// all share the same DB). allowUnsigned=true keeps backward compatibility
	// during client rollout; flip to false to enforce strict signing.
	signedMw := authmw.New(serversSvc.SigningKeyLookup(), true)
	rl := authmw.NewRateLimit(240, time.Minute) // 4 req/sec sustained, burst 240

	// Auth REST endpoints (prekeys, devices, user lookup)
	authHandler := auth.NewHandler(authSvc, signedMw, rl)
	authHandler.RegisterRoutes(mux)

	// Chat REST endpoints (message sync, conversations)
	chatHandler := chat.NewHandler(chatSvc, signedMw, rl)
	chatHandler.RegisterRoutes(mux)

	serversHandler := servers.NewHandler(serversSvc, signedMw, rl)
	serversHandler.RegisterRoutes(mux)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// Prometheus exposition endpoint. Kept off the signed-request path so
	// scrapers don't need credentials; protect at the network layer (firewall
	// or reverse-proxy auth) for production deployments.
	mux.Handle("GET /metrics", metrics.Handler())

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      httpmw.Chain(httpmw.SecurityHeaders, httpmw.CORS(parseCORSOrigins()), httpmw.AccessLog(slog.Default()))(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("veil-gateway starting on :%s", cfg.Port)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
}

// parseCORSOrigins reads VEIL_CORS_ORIGINS (comma-separated) and returns the
// allow-list. Defaults to "*" (any origin) when unset, matching the previous
// permissive behaviour for desktop/mobile clients on first deploy.
func parseCORSOrigins() []string {
	raw := strings.TrimSpace(os.Getenv("VEIL_CORS_ORIGINS"))
	if raw == "" {
		return []string{"*"}
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}
