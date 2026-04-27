package main

import (
	"context"
	_ "embed"
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
	"github.com/AegisSec/veil-server/internal/mls"
	"github.com/AegisSec/veil-server/internal/push"
	"github.com/AegisSec/veil-server/internal/servers"
	"github.com/AegisSec/veil-server/internal/uploads"
)

//go:embed web/index.html
var landingHTML []byte

//go:embed web/privacy.html
var privacyHTML []byte

//go:embed web/terms.html
var termsHTML []byte

//go:embed web/legal.css
var legalCSS []byte

//go:embed web/security.txt
var securityTxt []byte

//go:embed web/robots.txt
var robotsTxt []byte

//go:embed web/sitemap.xml
var sitemapXML []byte

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
	if err := gateway.ConfigureFromEnv(); err != nil {
		log.Fatalf("gateway config: %v", err)
	}
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
	// all share the same DB). The legacy unsigned bypass was removed in W3 —
	// every REST call must carry the X-Veil-{User,Timestamp,Signature} triplet.
	signedMw := authmw.New(serversSvc.SigningKeyLookup())
	rl := authmw.NewRateLimit(240, time.Minute) // 4 req/sec sustained, burst 240

	// Auth REST endpoints (prekeys, devices, user lookup)
	authHandler := auth.NewHandler(authSvc, signedMw, rl)
	authHandler.RegisterRoutes(mux)

	// Chat REST endpoints (message sync, conversations)
	chatHandler := chat.NewHandler(chatSvc, signedMw, rl)
	chatHandler.RegisterRoutes(mux)

	serversHandler := servers.NewHandler(serversSvc, signedMw, rl)
	serversHandler.RegisterRoutes(mux)

	// Phase 4 — UnifiedPush + ntfy. The push notifier wires into the
	// gateway's offline-fanout path: when sendToUser finds zero live
	// WS sessions, the dispatcher POSTs an encrypted envelope to every
	// distributor URL the recipient has registered. Boots in disabled
	// mode when VEIL_PUSH_TRANSPORT_KEY is unset (subscribe/list/delete
	// remain reachable but no traffic leaves the gateway).
	pushKey, err := push.LoadTransportKey()
	if err != nil {
		log.Fatalf("push: %v", err)
	}
	pushDispatcher := push.New(push.Options{
		Store:        push.NewDBStore(database),
		TransportKey: pushKey,
		Salt:         push.LoadSalt(),
		MaxJitter:    push.LoadJitter(),
		Logger:       slog.Default(),
	})
	hub.SetPushNotifier(pushDispatcher)
	pushHandler := push.NewHandler(database, signedMw, rl)
	pushHandler.RegisterRoutes(mux)
	if pushDispatcher.Enabled() {
		log.Printf("push dispatcher enabled (jitter=%s)", push.LoadJitter())
	}

	// Phase 6 — OpenMLS REST surface (key_packages / welcomes / commits).
	// The hub satisfies the mls.Fanout interface, so welcomes and commits
	// arrive at online recipients in real time without polling.
	mlsStore := mls.NewStore(database.Pool)
	mlsHandler := mls.NewHandler(mlsStore, signedMw, rl, hub)
	mlsHandler.RegisterRoutes(mux)

	// Phase 3 — tus.io resumable encrypted uploads. The token-mint
	// route uses the existing signed REST middleware; the tusd traffic
	// (POST/PATCH/HEAD) authenticates via short-lived bearer tokens to
	// avoid hashing every PATCH chunk for an Ed25519 signature.
	uploadKey, err := uploads.LoadTokenKey(os.Getenv)
	if err != nil {
		log.Fatalf("uploads: %v", err)
	}
	uploadCfg := uploads.LoadConfigFromEnv()
	uploadSvc, err := uploads.New(uploadCfg, uploadKey, uploads.NewDBStore(database), slog.Default())
	if err != nil {
		log.Fatalf("uploads: %v", err)
	}
	uploadSvc.RegisterRoutes(mux, signedMw, rl)
	if uploadSvc.Enabled() {
		log.Printf("uploads enabled (dir=%s, quota=%d/%s)",
			uploadCfg.LocalDir, uploadCfg.UserDailyQuota, uploadCfg.QuotaWindow)
		uploadCtx, uploadCancel := context.WithCancel(context.Background())
		defer uploadCancel()
		go uploadSvc.Sweeper(uploadCtx)
	} else {
		log.Printf("uploads disabled (set VEIL_UPLOAD_TOKEN_KEY to enable)")
	}

	// Landing page — served at the root so opening IP:port in a browser shows
	// the project page instead of a blank 404.
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.Write(landingHTML)
	})

	// Юридические страницы (RU). noindex для всех вариантов URL.
	staticHTML := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("X-Robots-Tag", "noindex")
			w.Write(body)
		}
	}
	mux.HandleFunc("GET /privacy", staticHTML(privacyHTML))
	mux.HandleFunc("GET /privacy/", staticHTML(privacyHTML))
	mux.HandleFunc("GET /terms", staticHTML(termsHTML))
	mux.HandleFunc("GET /terms/", staticHTML(termsHTML))

	mux.HandleFunc("GET /legal.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(legalCSS)
	})

	// RFC 9116 — security.txt по обоим путям (root + .well-known).
	textPlain := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Write(body)
		}
	}
	mux.HandleFunc("GET /.well-known/security.txt", textPlain(securityTxt))
	mux.HandleFunc("GET /security.txt", textPlain(securityTxt))
	mux.HandleFunc("GET /robots.txt", textPlain(robotsTxt))
	mux.HandleFunc("GET /sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(sitemapXML)
	})

	// Release artifacts (.deb, .AppImage, SHA256SUMS, …). Path is configurable
	// so production deploys can mount a volume instead of baking the binaries
	// into the image. Returns 404 silently when the directory is missing.
	downloadsDir := os.Getenv("VEIL_DOWNLOADS_DIR")
	if downloadsDir == "" {
		downloadsDir = "cmd/gateway/downloads"
	}
	if st, err := os.Stat(downloadsDir); err == nil && st.IsDir() {
		// Tight rate-limit for downloads: 5 req/min per IP to prevent
		// bandwidth exhaustion from large files (.AppImage ~113 MB).
		dlRL := authmw.NewRateLimit(5, time.Minute)
		fs := http.FileServer(http.Dir(downloadsDir))
		stripped := http.StripPrefix("/downloads/", fs)
		mux.Handle("GET /downloads/", dlRL.Wrap(func(w http.ResponseWriter, r *http.Request) {
			// Запрещаем directory listing — корневой /downloads/ и любые
			// пути, заканчивающиеся на /, всегда дают 404.
			if strings.HasSuffix(r.URL.Path, "/") {
				http.NotFound(w, r)
				return
			}
			// Не индексируем релизные бинарники в поисковиках и не даём
			// браузерам отображать AppImage как HTML.
			w.Header().Set("X-Robots-Tag", "noindex, nofollow")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Disposition", "attachment")
			stripped.ServeHTTP(w, r)
		}))
		log.Printf("downloads served from %s", downloadsDir)
	} else {
		log.Printf("downloads disabled (no directory at %s)", downloadsDir)
	}

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	// W4 — Prometheus exposition endpoint moves to a separate internal-only
	// listener bound to VEIL_INTERNAL_ADDR (default 127.0.0.1:9090). The
	// previous behaviour exposed full per-route req-rate to the open
	// internet, which is a privacy/operational leak. Set
	// VEIL_INTERNAL_ADDR="" to opt-in to the legacy public /metrics path
	// (e.g. for local dev where there's no Prometheus sidecar).
	internalAddr, exposePublicMetrics := metricsBindAddr()
	if exposePublicMetrics {
		mux.Handle("GET /metrics", metrics.Handler())
	}

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

	// Internal listener for Prometheus + future pprof. Bound to a
	// non-public address by default so the docker-compose `ports:` mapping
	// only exposes /health and /ws to the internet.
	var internalSrv *http.Server
	if internalAddr != "" {
		internalMux := http.NewServeMux()
		internalMux.Handle("GET /metrics", metrics.Handler())
		internalSrv = &http.Server{
			Addr:         internalAddr,
			Handler:      internalMux,
			ReadTimeout:  15 * time.Second,
			WriteTimeout: 15 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
		log.Printf("veil-gateway internal listener (metrics) on %s", internalAddr)
		go func() {
			if err := internalSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("internal server error: %v", err)
			}
		}()
	}

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("shutting down...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	server.Shutdown(shutdownCtx)
	if internalSrv != nil {
		internalSrv.Shutdown(shutdownCtx)
	}
}

// metricsBindAddr resolves the VEIL_INTERNAL_ADDR env var, returning the
// listen address for the internal mux and whether to keep /metrics on the
// public mux as well.
//
//   - unset → "127.0.0.1:9090", public exposure off (production default).
//   - "off" or "disabled" → no internal listener, public /metrics off
//     (use this when an external sidecar scrapes via docker exec).
//   - "public" → no internal listener, /metrics stays on public mux
//     (legacy mode; **not recommended** for internet-facing deploys).
//   - any other value → bind to it, public exposure off.
func metricsBindAddr() (addr string, exposePublic bool) {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("VEIL_INTERNAL_ADDR")))
	switch raw {
	case "":
		return "127.0.0.1:9090", false
	case "off", "disabled", "none":
		return "", false
	case "public":
		log.Printf("WARN: VEIL_INTERNAL_ADDR=public — /metrics is publicly exposed; protect at the edge")
		return "", true
	default:
		return raw, false
	}
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
