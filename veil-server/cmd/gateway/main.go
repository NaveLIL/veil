package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/gateway"
	"github.com/AegisSec/veil-server/internal/servers"
)

func main() {
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
	go hub.Run()

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocket(hub, w, r)
	})

	// Auth REST endpoints (prekeys, devices, user lookup)
	authHandler := auth.NewHandler(authSvc)
	authHandler.RegisterRoutes(mux)

	// Chat REST endpoints (message sync, conversations)
	chatHandler := chat.NewHandler(chatSvc)
	chatHandler.RegisterRoutes(mux)

	// Servers / Channels / Roles / Invites REST endpoints
	serversSvc := servers.NewService(database, hub)
	serversHandler := servers.NewHandler(serversSvc)
	serversHandler.RegisterRoutes(mux)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      mux,
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
