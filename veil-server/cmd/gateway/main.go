package main

import (
	"context"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/chat"
	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/gateway"
	"github.com/NaveLIL/veil/veil-server/internal/httpmw"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/metrics"
	"github.com/NaveLIL/veil/veil-server/internal/mls"
	"github.com/NaveLIL/veil/veil-server/internal/profiles"
	"github.com/NaveLIL/veil/veil-server/internal/push"
	"github.com/NaveLIL/veil/veil-server/internal/servers"
	veiltransparency "github.com/NaveLIL/veil/veil-server/internal/transparency"
	"github.com/NaveLIL/veil/veil-server/internal/uploads"
)

//go:embed web/index.html
var landingHTML []byte

//go:embed web/privacy.html
var privacyHTML []byte

//go:embed web/terms.html
var termsHTML []byte

//go:embed web/enroll.html
var enrollHTML []byte

//go:embed web/legal.css
var legalCSS []byte

//go:embed web/security.txt
var securityTxt []byte

//go:embed web/robots.txt
var robotsTxt []byte

//go:embed web/sitemap.xml
var sitemapXML []byte

const projectRepositoryURL = "https://github.com/NaveLIL/veil"

// buildCommit is replaced with the exact source commit by the release image
// workflow. Local development builds deliberately fall back to the repository
// root instead of constructing a misleading source URL.
var buildCommit = "development"

type sourceMetadata struct {
	License    string `json:"license"`
	Copyright  string `json:"copyright"`
	Revision   string `json:"revision,omitempty"`
	ArchiveURL string `json:"archive_url,omitempty"`
	BrowseURL  string `json:"browse_url"`
}

func canonicalCommit(commit string) (string, bool) {
	commit = strings.ToLower(strings.TrimSpace(commit))
	if len(commit) != 40 {
		return "", false
	}
	if _, err := hex.DecodeString(commit); err != nil {
		return "", false
	}
	return commit, true
}

func validatedSourceURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	parsed, err := url.ParseRequestURI(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", errors.New("must be an absolute durable HTTPS URL without credentials, query, or fragment")
	}
	return parsed.String(), nil
}

func sourceMetadataForBuild(commit, overrideRevision, overrideArchive, overrideBrowse string) (sourceMetadata, error) {
	metadata := sourceMetadata{
		License:   "AGPL-3.0-or-later",
		Copyright: "Copyright (C) 2026 NaveLIL",
	}

	overrideRevision = strings.TrimSpace(overrideRevision)
	overrideArchive = strings.TrimSpace(overrideArchive)
	overrideBrowse = strings.TrimSpace(overrideBrowse)
	hasOverride := overrideRevision != "" || overrideArchive != "" || overrideBrowse != ""
	if hasOverride {
		if overrideRevision == "" || overrideArchive == "" || overrideBrowse == "" {
			return sourceMetadata{}, errors.New("VEIL_SOURCE_REVISION, VEIL_SOURCE_ARCHIVE_URL, and VEIL_SOURCE_BROWSE_URL must be set together")
		}
		revision, ok := canonicalCommit(overrideRevision)
		if !ok {
			return sourceMetadata{}, errors.New("VEIL_SOURCE_REVISION must be a full 40-character Git commit")
		}
		archiveURL, err := validatedSourceURL(overrideArchive)
		if err != nil {
			return sourceMetadata{}, fmt.Errorf("VEIL_SOURCE_ARCHIVE_URL %w", err)
		}
		browseURL, err := validatedSourceURL(overrideBrowse)
		if err != nil {
			return sourceMetadata{}, fmt.Errorf("VEIL_SOURCE_BROWSE_URL %w", err)
		}
		metadata.Revision = revision
		metadata.ArchiveURL = archiveURL
		metadata.BrowseURL = browseURL
		return metadata, nil
	}

	revision, ok := canonicalCommit(commit)
	if !ok {
		metadata.BrowseURL = projectRepositoryURL
		return metadata, nil
	}
	metadata.Revision = revision
	metadata.ArchiveURL = projectRepositoryURL + "/archive/" + revision + ".tar.gz"
	metadata.BrowseURL = projectRepositoryURL + "/tree/" + revision
	return metadata, nil
}

func nodeAccessPassHandler(body []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; connect-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Write(body)
	}
}

func main() {
	// Switch to structured JSON logging via slog (consumed by httpmw.AccessLog).
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.LoadGateway()
	if err != nil {
		log.Fatalf("configuration error: %v", err)
	}
	if err := httpmw.ConfigureClientIPFromEnv(); err != nil {
		log.Fatalf("proxy configuration error: %v", err)
	}
	sourceInfo, err := sourceMetadataForBuild(
		buildCommit,
		os.Getenv("VEIL_SOURCE_REVISION"),
		os.Getenv("VEIL_SOURCE_ARCHIVE_URL"),
		os.Getenv("VEIL_SOURCE_BROWSE_URL"),
	)
	if err != nil {
		log.Fatalf("source metadata configuration error: %v", err)
	}
	sourceInfoJSON, err := json.Marshal(sourceInfo)
	if err != nil {
		log.Fatalf("source metadata encoding error: %v", err)
	}
	sourceInfoJSON = append(sourceInfoJSON, '\n')

	// Connect to PostgreSQL
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
	if err := database.AuditMembershipEpochsV1(ctx, cfg.PublicOrigin.String()); err != nil {
		log.Fatalf("membership epoch startup audit failed: %v", err)
	}
	var identityTransparencySigner *auth.IdentityTransparencySigner
	if cfg.IdentityTransparency != nil {
		identityTransparencySigner, err = auth.NewIdentityTransparencySigner(
			cfg.PublicOrigin,
			cfg.IdentityTransparency.SigningSeed,
		)
		clear(cfg.IdentityTransparency.SigningSeed[:])
		if err != nil {
			log.Fatalf("identity transparency signer configuration failed: %v", err)
		}
		if len(cfg.IdentityTransparency.Witnesses) != 0 {
			endpoints := make([]veiltransparency.WitnessEndpoint, len(cfg.IdentityTransparency.Witnesses))
			for index := range cfg.IdentityTransparency.Witnesses {
				endpoints[index] = veiltransparency.WitnessEndpoint{
					URL:        cfg.IdentityTransparency.Witnesses[index].URL,
					SigningKey: cfg.IdentityTransparency.Witnesses[index].SigningKey,
				}
			}
			witnessQuorum, witnessErr := veiltransparency.NewHTTPWitnessQuorum(
				endpoints, cfg.IdentityTransparency.WitnessThreshold, database,
			)
			if witnessErr != nil {
				log.Fatalf("identity transparency witness configuration failed: %v", witnessErr)
			}
			identityTransparencySigner.SetWitnessCosigner(witnessQuorum)
			log.Printf(
				"identity transparency external witnesses enabled: configured=%d quorum=%d",
				len(endpoints), cfg.IdentityTransparency.WitnessThreshold,
			)
		}
		defer identityTransparencySigner.Destroy()
		publicKey := identityTransparencySigner.PublicKey()
		if err := database.EnableIdentityTransparencyLog(
			ctx,
			cfg.PublicOrigin,
			identityTransparencySigner.LogID(),
			publicKey[:],
		); err != nil {
			log.Fatalf("identity transparency activation failed: %v", err)
		}
		log.Println("identity transparency account-registration log enabled")
	}
	log.Println("database connected")

	// Initialize services
	authSvc := auth.NewService(database, cfg)
	chatSvc := chat.NewService(database, cfg)

	// Start hub
	hub := gateway.NewHub(authSvc, chatSvc)
	chatSvc.SetBroadcaster(hub)
	if err := gateway.ConfigureFromEnv(); err != nil {
		log.Fatalf("gateway config: %v", err)
	}
	go hub.Run()

	// HTTP routes
	mux := http.NewServeMux()
	mux.HandleFunc("/v3/events", func(w http.ResponseWriter, r *http.Request) {
		gateway.HandleWebSocketV3(hub, w, r)
	})

	// Servers / Channels / Roles / Invites REST endpoints
	serversSvc := servers.NewService(database, hub)

	// Shared signature middleware + per-user rate limit. The middleware reads
	// signing keys via the servers service (any of the three would do; they
	// all share the same DB). Every authenticated REST route is v2-only and
	// requires the exact version/user/timestamp/nonce/signature proof set.
	signedMw := authmw.New(serversSvc.SigningKeyLookup())
	defer signedMw.Close()
	restV2Verifier, err := authmw.NewRESTAuthV2Verifier(
		cfg.PublicOrigin,
		serversSvc.SigningKeyLookup(),
		database,
	)
	if err != nil {
		log.Fatalf("REST auth v2 verifier configuration: %v", err)
	}
	restV2Boundary, err := authmw.NewRESTAuthV2HTTPBoundary(restV2Verifier, signedMw)
	if err != nil {
		log.Fatalf("REST auth v2 HTTP boundary configuration: %v", err)
	}
	restDispatcher, err := authmw.NewRESTAuthVersionDispatcher(restV2Boundary)
	if err != nil {
		log.Fatalf("REST auth version dispatcher configuration: %v", err)
	}
	replayJanitorCtx, replayJanitorCancel := context.WithCancel(context.Background())
	defer replayJanitorCancel()
	go runRESTAuthV2ReplayJanitor(replayJanitorCtx, database)
	rl := authmw.NewRateLimit(240, time.Minute) // 4 req/sec sustained, burst 240
	defer rl.Close()
	profileMutationRL := authmw.NewRateLimit(12, time.Minute)
	defer profileMutationRL.Close()
	// Bound unauthenticated key lookup + Ed25519 verification before the
	// verified-principal limiter inside each REST route.
	preAuthRL := authmw.NewRateLimit(600, time.Minute)
	defer preAuthRL.Close()

	// Auth REST endpoints (prekeys, devices, user lookup)
	authHandler := auth.NewHandler(authSvc, signedMw, rl)
	authHandler.SetRESTAuthVersionDispatcher(restDispatcher)
	authHandler.SetIdentityTransparencySigner(identityTransparencySigner)
	authHandler.RegisterRoutes(mux)
	profileStore := profiles.NewPostgresStore(database.Pool)
	profilesHandler := profiles.NewHandler(profileStore, signedMw, rl, profileMutationRL, hub)
	profilesHandler.SetRESTAuthVersionDispatcher(restDispatcher)
	profilesHandler.RegisterRoutes(mux)
	avatarJanitorCtx, avatarJanitorCancel := context.WithCancel(context.Background())
	defer avatarJanitorCancel()
	go profiles.RunAvatarJanitor(avatarJanitorCtx, profileStore, slog.Default())

	// Chat REST endpoints (message sync, conversations)
	chatHandler := chat.NewHandler(chatSvc, signedMw, rl)
	chatHandler.SetRESTAuthVersionDispatcher(restDispatcher)
	chatHandler.RegisterRoutes(mux)

	serversHandler := servers.NewHandler(serversSvc, signedMw, rl)
	serversHandler.SetRESTAuthVersionDispatcher(restDispatcher)
	veilPreviewRL := authmw.NewRateLimit(30, time.Minute)
	defer veilPreviewRL.Close()
	veilJoinRL := authmw.NewRateLimit(10, time.Minute)
	defer veilJoinRL.Close()
	serversHandler.SetVeilLinkRateLimits(veilPreviewRL, veilJoinRL)
	serversHandler.RegisterRoutes(mux)

	// Phase 4P — UnifiedPush over RFC 8291 Web Push. The notifier wires into the
	// gateway's offline-fanout path: when sendToUser finds zero live
	// WS sessions, the dispatcher POSTs a fixed-size encrypted wake-up to every
	// validated distributor URL. New registration and delivery fail closed when
	// VAPID is not configured; list/policy/delete remain available.
	vapid, err := push.LoadVAPIDConfig()
	if err != nil {
		log.Fatalf("push: %v", err)
	}
	pushEndpointPolicy, err := push.LoadEndpointPolicy()
	if err != nil {
		log.Fatalf("push endpoint policy: %v", err)
	}
	pushDispatcher := push.New(push.Options{
		Store:          push.NewDBStore(database),
		VAPID:          vapid,
		EndpointPolicy: pushEndpointPolicy,
		MaxJitter:      push.LoadJitter(),
		Logger:         slog.Default(),
	})
	hub.SetPushNotifier(pushDispatcher)
	pushHandler := push.NewHandlerWithEndpointPolicy(database, signedMw, rl, pushEndpointPolicy)
	pushHandler.SetRESTAuthVersionDispatcher(restDispatcher)
	pushHandler.SetDispatcher(pushDispatcher)
	pushHandler.RegisterRoutes(mux)
	if pushDispatcher.Enabled() {
		log.Printf("push dispatcher enabled (jitter=%s)", push.LoadJitter())
	}

	// Phase 6 — OpenMLS REST surface (key_packages / welcomes / commits).
	// The hub satisfies the mls.Fanout interface, so welcomes and commits
	// arrive at online recipients in real time without polling.
	mlsStore := mls.NewStore(database.Pool)
	mlsHandler := mls.NewHandler(mlsStore, signedMw, rl, hub)
	mlsHandler.SetRESTAuthVersionDispatcher(restDispatcher)
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
	uploadSvc.SetRESTAuthVersionDispatcher(restDispatcher)
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
		w.Header().Set("Link", "</source>; rel=\"source\"")
		w.Write(landingHTML)
	})

	// Юридические страницы (RU). noindex для всех вариантов URL.
	staticHTML := func(body []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("X-Robots-Tag", "noindex")
			w.Header().Set("Link", "</source>; rel=\"source\"")
			w.Write(body)
		}
	}
	mux.HandleFunc("GET /privacy", staticHTML(privacyHTML))
	mux.HandleFunc("GET /privacy/", staticHTML(privacyHTML))
	mux.HandleFunc("GET /terms", staticHTML(termsHTML))
	mux.HandleFunc("GET /terms/", staticHTML(termsHTML))
	enrollPage := nodeAccessPassHandler(enrollHTML)
	mux.HandleFunc("GET /enroll", enrollPage)
	mux.HandleFunc("GET /enroll/", enrollPage)
	mux.HandleFunc("GET /source", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		target := sourceInfo.ArchiveURL
		if target == "" {
			target = sourceInfo.BrowseURL
		}
		http.Redirect(w, r, target, http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("GET /source/browse", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Redirect(w, r, sourceInfo.BrowseURL, http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("GET /.well-known/veil-source.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Write(sourceInfoJSON)
	})

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
	mux.HandleFunc("GET /readyz", readinessHandler(database.Pool))

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

	corsOrigins, err := parseCORSOrigins()
	if err != nil {
		log.Fatalf("CORS configuration error: %v", err)
	}
	publicHandler := http.HandlerFunc(preAuthRL.Wrap(mux.ServeHTTP))
	server := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpmw.Chain(httpmw.SecurityHeaders, httpmw.CORS(corsOrigins), httpmw.AccessLog(slog.Default()))(publicHandler),
		ReadHeaderTimeout: 10 * time.Second,
		// Encrypted tus chunks and large signed REST responses must not be cut
		// off by the old 15-second whole-request deadline. HeaderTimeout keeps
		// the slowloris boundary tight while body I/O gets the same bounded
		// window as the production reverse proxy.
		ReadTimeout:  time.Hour,
		WriteTimeout: time.Hour,
		IdleTimeout:  90 * time.Second,
	}

	log.Printf("veil-gateway starting on :%s", cfg.Port)

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Internal listener for Prometheus + future pprof. Bound to a
	// non-public address by default so the docker-compose `ports:` mapping
	// only exposes the public gateway routes to the internet.
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

type pinger interface {
	Ping(context.Context) error
}

type restAuthV2ReplayCleaner interface {
	DeleteExpiredRESTAuthV2ReplayNonces(context.Context, int) (int64, error)
}

func runRESTAuthV2ReplayJanitor(ctx context.Context, cleaner restAuthV2ReplayCleaner) {
	if ctx == nil || cleaner == nil {
		return
	}
	cleanup := func() {
		for range 4 {
			cleanupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			deleted, err := cleaner.DeleteExpiredRESTAuthV2ReplayNonces(
				cleanupCtx,
				db.MaxRESTAuthV2ReplayCleanupBatch,
			)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					log.Printf("REST auth v2 replay cleanup failed: class=%s", logsafe.ErrorClass(err))
				}
				return
			}
			if deleted < db.MaxRESTAuthV2ReplayCleanupBatch {
				return
			}
		}
	}
	cleanup()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cleanup()
		}
	}
}

func readinessHandler(database pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if err := database.Ping(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
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
// allow-list. Empty configuration is fail-closed for browser origins; native
// Tauri/mobile HTTP clients do not send Origin and are unaffected. An explicit
// "*" remains available for isolated development only.
func parseCORSOrigins() ([]string, error) {
	raw := strings.TrimSpace(os.Getenv("VEIL_CORS_ORIGINS"))
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		if v == "*" {
			log.Printf("WARN: VEIL_CORS_ORIGINS=* allows every browser origin; development only")
			out = append(out, v)
			continue
		}
		parsed, err := url.Parse(v)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("invalid browser origin %q", v)
		}
		out = append(out, strings.ToLower(v))
	}
	return out, nil
}
