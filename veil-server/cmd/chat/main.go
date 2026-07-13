package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/AegisSec/veil-server/internal/authmw"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
	"github.com/AegisSec/veil-server/internal/httpmw"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if err := httpmw.ConfigureClientIPFromEnv(); err != nil {
		log.Fatalf("proxy configuration error: %v", err)
	}

	port := os.Getenv("CHAT_PORT")
	if port == "" {
		port = "8082"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	database, err := db.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("database connection failed: %v", err)
	}
	defer database.Close()
	if err := database.ValidateCryptographicPublicKeys(ctx); err != nil {
		log.Fatalf("database cryptographic-key preflight failed: %v", err)
	}
	log.Println("database connected")

	chatSvc := chat.NewService(database, cfg)
	signedMw := authmw.New(chatSvc.SigningKeyLookup())
	defer signedMw.Close()
	rl := authmw.NewRateLimit(240, time.Minute)
	defer rl.Close()
	preAuthRL := authmw.NewRateLimit(600, time.Minute)
	defer preAuthRL.Close()
	handler := chat.NewHandler(chatSvc, signedMw, rl)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"service":"veil-chat","status":"ok"}`))
	})

	publicHandler := http.HandlerFunc(preAuthRL.Wrap(mux.ServeHTTP))
	server := &http.Server{
		Addr:         ":" + port,
		Handler:      publicHandler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	log.Printf("veil-chat starting on :%s", port)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
}
