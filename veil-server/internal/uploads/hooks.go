package uploads

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	tusd "github.com/tus/tusd/v2/pkg/handler"
)

// userIDFromHook extracts the bearer-authenticated user ID stored on
// the request by bearerMiddleware. tusd hands us http.Header but no
// raw context, so the middleware also stamps a header for the hook.
func userIDFromHook(event tusd.HookEvent) string {
	return event.HTTPRequest.Header.Get(headerVeilUser)
}

// hooks bundles every callback we plug into tusd. It owns the Store
// adapter so quota checks and bookkeeping stay consistent.
type hooks struct {
	store  Store
	cfg    Config
	logger *slog.Logger
}

// PreCreate enforces auth + quota and returns the freshly minted file
// ID. tusd will use this ID as both the upload identifier and the bin
// filename on the filestore backend.
func (h *hooks) PreCreate(event tusd.HookEvent) (tusd.HTTPResponse, tusd.FileInfoChanges, error) {
	userID := userIDFromHook(event)
	if userID == "" {
		// Should be impossible — middleware refuses unauth'd requests
		// before reaching tusd — but defence in depth.
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("unauthenticated", 401)
	}

	size := event.Upload.Size
	if event.Upload.SizeIsDeferred {
		// Refuse deferred-length uploads; we need the size up-front for
		// the quota gate. Clients always know the ciphertext length.
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("upload length must be declared up-front", 400)
	}
	if size <= 0 {
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("upload size must be > 0", 400)
	}
	if h.cfg.MaxUploadSize > 0 && size > h.cfg.MaxUploadSize {
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError(fmt.Sprintf("upload exceeds per-file limit (%d bytes)", h.cfg.MaxUploadSize), 413)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	since := time.Now().Add(-h.cfg.QuotaWindow)
	used, err := h.store.SumTusBytesInWindow(ctx, userID, since)
	if err != nil {
		h.logger.Warn("uploads: quota lookup failed", "err", err, "user", userID)
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("quota check failed", 500)
	}
	if used+size > h.cfg.UserDailyQuota {
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("quota exceeded", 413)
	}

	fileID, err := generateFileID()
	if err != nil {
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("id generation failed", 500)
	}

	// Set the abort TTL up-front; PreFinish will overwrite with the
	// retention TTL once the upload completes.
	abortAt := time.Now().Add(h.cfg.AbortAfterIdle)
	if err := h.store.CreateTusUpload(ctx, fileID, userID, size, "local", abortAt); err != nil {
		h.logger.Warn("uploads: create row failed", "err", err, "user", userID)
		return tusd.HTTPResponse{}, tusd.FileInfoChanges{},
			rejectError("could not create upload", 500)
	}

	return tusd.HTTPResponse{}, tusd.FileInfoChanges{ID: fileID}, nil
}

// PreFinish is called once the last byte has landed but before tusd's
// 204 response. We promote the abort-TTL row to the retention-TTL.
func (h *hooks) PreFinish(event tusd.HookEvent) (tusd.HTTPResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	retainUntil := time.Now().Add(h.cfg.RetentionAfterFinish)
	if err := h.store.FinishTusUpload(ctx, event.Upload.ID, retainUntil); err != nil {
		h.logger.Warn("uploads: finish row failed", "err", err, "id", event.Upload.ID)
		// Don't fail the request — bytes are on disk, the row will be
		// reconciled by the sweeper if it stays orphaned.
	}
	return tusd.HTTPResponse{}, nil
}

// rejectError converts a human reason into a tusd-friendly error that
// surfaces both the HTTP status and the message in the response body.
func rejectError(msg string, status int) error {
	return tusd.Error{
		ErrorCode: "ERR_UPLOAD_REJECTED",
		Message:   msg,
		HTTPResponse: tusd.HTTPResponse{
			StatusCode: status,
			Body:       msg,
		},
	}
}

// generateFileID mints a 128-bit random hex string. Long enough that
// guessing one is computationally infeasible (path traversal &
// enumeration attacks must rely on guessing the ID, since the storage
// dir isn't world-listable).
func generateFileID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", errors.New("rand: " + err.Error())
	}
	return hex.EncodeToString(b), nil
}
