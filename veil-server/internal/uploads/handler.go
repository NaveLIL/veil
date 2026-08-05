package uploads

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	"github.com/tus/tusd/v2/pkg/filestore"
	tusd "github.com/tus/tusd/v2/pkg/handler"
	expslog "golang.org/x/exp/slog"
)

// headerVeilUser is the hop-by-hop header bearerMiddleware writes onto
// the request so downstream code (tusd hooks + the GET handler) can
// pick the authenticated user without re-parsing the bearer.
const headerVeilUser = "X-Veil-Upload-User"

// Service is the public façade for cmd/gateway: it owns the tusd
// handler, the bearer middleware, the token-mint endpoint and the
// background sweeper.
type Service struct {
	cfg                Config
	tokenKey           []byte
	store              Store
	composer           *tusd.StoreComposer
	tusHandle          *tusd.Handler
	fileStore          filestore.FileStore
	logger             *slog.Logger
	restAuthDispatcher *authmw.RESTAuthVersionDispatcher
}

// New wires a Service. tokenKey is the HMAC secret returned by
// LoadTokenKey; pass nil to keep the subsystem available but disabled
// (every request is rejected with 503).
func New(cfg Config, tokenKey []byte, store Store, logger *slog.Logger) (*Service, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.LocalDir == "" {
		return nil, errors.New("uploads: LocalDir required")
	}
	if err := os.MkdirAll(cfg.LocalDir, 0o750); err != nil {
		return nil, err
	}

	fs := filestore.New(cfg.LocalDir)
	composer := tusd.NewStoreComposer()
	fs.UseIn(composer)

	h := &hooks{store: store, cfg: cfg, logger: logger}

	tusHandle, err := tusd.NewHandler(tusd.Config{
		BasePath:                cfg.BasePath,
		RespectForwardedHeaders: cfg.RespectForwardedHeaders,
		StoreComposer:           composer,
		MaxSize:                 cfg.MaxUploadSize,
		DisableDownload:         true,
		DisableConcatenation:    true,
		// tusd's default logger records the raw request path, upload ID,
		// generated URL and unfiltered storage errors. The gateway access log
		// already provides bounded route-template observability, while the
		// hooks below emit pseudonymous failure references, so disable the
		// third-party request logger at this privacy boundary.
		Logger:                  expslog.New(expslog.NewTextHandler(io.Discard, nil)),
		PreUploadCreateCallback: h.PreCreate,
		PreFinishResponseCallback: func(e tusd.HookEvent) (tusd.HTTPResponse, error) {
			return h.PreFinish(e)
		},
	})
	if err != nil {
		return nil, err
	}

	return &Service{
		cfg:       cfg,
		tokenKey:  tokenKey,
		store:     store,
		composer:  composer,
		tusHandle: tusHandle,
		fileStore: fs,
		logger:    logger,
	}, nil
}

// Enabled returns true iff a token key was configured. When false,
// callers may still mount the routes — every request returns 503.
func (s *Service) Enabled() bool { return len(s.tokenKey) >= MinTokenKeyLen }

// SetRESTAuthVersionDispatcher activates the REST v2 boundary for the signed
// token-mint endpoint. Bearer-authenticated tus routes remain unchanged.
func (s *Service) SetRESTAuthVersionDispatcher(dispatcher *authmw.RESTAuthVersionDispatcher) {
	s.restAuthDispatcher = dispatcher
}

// RegisterRoutes mounts:
//
//	POST   /v1/uploads/token              — signed (X-Veil triplet)
//	GET    /v1/uploads/blob/{id}          — bearer (download)
//	*      /v1/uploads/files/...          — bearer (POST/PATCH/HEAD/DELETE)
//
// The REST v2 dispatcher wraps only the token endpoint; tusd's traffic uses
// bearer authorization so PATCH chunks do not need account signatures.
func (s *Service) RegisterRoutes(mux *http.ServeMux, signedMw *authmw.Middleware, rl *authmw.RateLimit) {
	signed := func(f http.HandlerFunc) http.HandlerFunc {
		if rl != nil {
			f = rl.Wrap(f)
		}
		jsonPolicy, err := authmw.NewRESTAuthV2JSONHTTPPolicy(4 << 10)
		if err != nil {
			panic("invalid uploads REST v2 JSON policy")
		}
		if s.restAuthDispatcher != nil {
			f = s.restAuthDispatcher.RequireSigned(jsonPolicy, f)
		} else if signedMw != nil {
			var unavailable *authmw.RESTAuthVersionDispatcher
			f = unavailable.RequireSigned(jsonPolicy, f)
		}
		return f
	}
	mux.HandleFunc("POST /v1/uploads/token", signed(s.handleIssueToken))

	// tusd handles routing for everything under BasePath, including
	// the trailing-slash root for POST and the /{id} sub-paths for
	// HEAD/PATCH/DELETE. We mount it via http.StripPrefix so paths
	// match what tusd expects.
	tusRoot := strings.TrimSuffix(s.cfg.BasePath, "/")
	safeTus := publicerr.SanitizeServerErrors(http.StripPrefix(tusRoot, s.tusHandle))
	mux.Handle(s.cfg.BasePath,
		s.bearerMiddleware(safeTus))
	mux.Handle(tusRoot,
		s.bearerMiddleware(safeTus))

	// Encrypted-blob download. The stock tusd GET extension would also
	// work, but we want our own auth gate (cross-user reads must be
	// rejected) and a clean cache header story.
	mux.HandleFunc("GET /v1/uploads/blob/{id}", s.bearerMiddleware(http.HandlerFunc(s.handleDownload)))
}

type tokenRequest struct {
	TTLSeconds int `json:"ttl_seconds,omitempty"`
}

type tokenResponse struct {
	Token     string `json:"token"`
	ExpiresAt string `json:"expires_at"`
	BasePath  string `json:"base_path"`
}

func (s *Service) handleIssueToken(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		writeJSON(w, http.StatusServiceUnavailable,
			map[string]string{"error": "uploads disabled"})
		return
	}
	userID, ok := authmw.VerifiedUserID(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized,
			map[string]string{"error": "unauthenticated"})
		return
	}
	ttl := s.cfg.TokenTTL
	// Optional client override, capped at server max.
	var req tokenRequest
	_ = decodeJSONBest(r, &req)
	if req.TTLSeconds > 0 {
		want := time.Duration(req.TTLSeconds) * time.Second
		if want < ttl {
			ttl = want
		}
	}
	tok, exp, err := IssueToken(s.tokenKey, userID, ttl)
	if err != nil {
		publicerr.Write(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, tokenResponse{
		Token:     tok,
		ExpiresAt: exp.Format(time.RFC3339),
		BasePath:  s.cfg.BasePath,
	})
}

// bearerMiddleware verifies the upload bearer token. On success it
// stamps headerVeilUser onto the request so the tusd hook can read it
// and the download handler can authorise the caller.
func (s *Service) bearerMiddleware(next http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Defence-in-depth: strip any caller-supplied value before we
		// authenticate so a forged header can't leak through if the
		// bearer check is short-circuited in future refactors.
		r.Header.Del(headerVeilUser)
		if !s.Enabled() {
			writeJSON(w, http.StatusServiceUnavailable,
				map[string]string{"error": "uploads disabled"})
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized,
				map[string]string{"error": "missing bearer"})
			return
		}
		userID, err := VerifyToken(s.tokenKey, strings.TrimPrefix(auth, prefix))
		if err != nil {
			publicerr.Write(w, http.StatusUnauthorized, publicerr.New(
				http.StatusUnauthorized, "invalid_upload_bearer", "invalid or expired bearer", err,
			))
			return
		}
		if requiresTusOwnerCheck(r.Method) {
			fileID, ok := tusFileIDFromPath(s.cfg.BasePath, r.URL.Path)
			if !ok {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid upload path"})
				return
			}
			row, lookupErr := s.store.GetTusUpload(r.Context(), fileID)
			if lookupErr != nil || row == nil {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload not found"})
				return
			}
			if !row.ExpiresAt.After(time.Now()) {
				writeJSON(w, http.StatusNotFound, map[string]string{"error": "upload not found"})
				return
			}
			if row.UserID != userID {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
				return
			}
		}
		r.Header.Set(headerVeilUser, userID)
		next.ServeHTTP(w, r)
	}
}

func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	if !looksLikeFileID(fileID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	row, err := s.store.GetTusUpload(r.Context(), fileID)
	if err != nil || row == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if !row.ExpiresAt.After(time.Now()) {
		// Treat expired blobs as absent even before the sweeper removes them.
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	if row.FinishedAt == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "upload incomplete"})
		return
	}
	// The uploader and current participants of a live message conversation
	// may fetch the opaque ciphertext. Channel permissions are re-evaluated
	// on every request.
	allowed, err := s.store.CanDownloadTusUpload(
		r.Context(), fileID, r.Header.Get(headerVeilUser),
	)
	if err != nil {
		s.logger.Warn("uploads: download authorization failed", "file_ref", logsafe.Ref("file", fileID), "error_class", logsafe.ErrorClass(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization failed"})
		return
	}
	if !allowed {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	binPath := filepath.Join(s.cfg.LocalDir, fileID)
	f, err := os.Open(binPath)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "blob missing"})
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Cache-Control", "private, no-store")
	http.ServeContent(w, r, fileID, row.CreatedAt, f)
}

func requiresTusOwnerCheck(method string) bool {
	return method == http.MethodHead || method == http.MethodPatch || method == http.MethodDelete
}

func tusFileIDFromPath(basePath, requestPath string) (string, bool) {
	if !strings.HasSuffix(basePath, "/") || !strings.HasPrefix(requestPath, basePath) {
		return "", false
	}
	fileID := strings.TrimPrefix(requestPath, basePath)
	if strings.Contains(fileID, "/") || !looksLikeFileID(fileID) {
		return "", false
	}
	return fileID, true
}

// Sweeper is the long-running goroutine that drops expired uploads.
// Returns when ctx is cancelled.
func (s *Service) Sweeper(ctx context.Context) {
	t := time.NewTicker(s.cfg.SweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.sweepOnce(ctx)
		}
	}
}

func (s *Service) sweepOnce(ctx context.Context) {
	rows, err := s.store.ListExpiredTusUploads(ctx, time.Now(), 100)
	if err != nil {
		s.logger.Warn("uploads: sweep list failed", "error_class", logsafe.ErrorClass(err))
		return
	}
	for _, row := range rows {
		if err := s.terminateBlob(ctx, row); err != nil {
			s.logger.Warn("uploads: terminate failed", "file_ref", logsafe.Ref("file", row.ID), "error_class", logsafe.ErrorClass(err))
			continue
		}
		if err := s.store.DeleteTusUpload(ctx, row.ID); err != nil {
			s.logger.Warn("uploads: delete row failed", "file_ref", logsafe.Ref("file", row.ID), "error_class", logsafe.ErrorClass(err))
		}
	}
}

func (s *Service) terminateBlob(ctx context.Context, row db.TusUpload) error {
	upload, err := s.fileStore.GetUpload(ctx, row.ID)
	if err != nil {
		// File may already be gone — that's fine, we still drop the row.
		return nil
	}
	t := s.fileStore.AsTerminatableUpload(upload)
	return t.Terminate(ctx)
}

func looksLikeFileID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
