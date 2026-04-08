package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/AegisSec/veil-server/internal/gateway"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	hub := gateway.NewHub()
	go hub.Run()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocket(hub, w, r)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	log.Printf("veil-gateway starting on :%s", port)

	// Graceful shutdown
	go func() {
		if err := http.ListenAndServe(":"+port, nil); err != nil {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")
}
