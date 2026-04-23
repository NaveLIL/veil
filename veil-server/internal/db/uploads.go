package db

import (
	"context"
	"fmt"
	"time"
)

// TusUpload mirrors one row in the tus_uploads table. The server is
// E2EE-blind: only opaque size/timing metadata is recorded here, the
// ciphertext bytes themselves live on the upload backend (local FS by
// default, S3 in a future rev).
type TusUpload struct {
	ID            string
	UserID        string
	SizeBytes     int64
	ReceivedBytes int64
	Backend       string
	CreatedAt     time.Time
	FinishedAt    *time.Time
	ExpiresAt     time.Time
}

// CreateTusUpload inserts a new upload row. fileID must be the value
// tusd will use as the upload identifier (we receive it from the
// pre-create hook). Conflicts are surfaced as errors so the dispatcher
// fails fast on a duplicate ID — tusd's default scheme is collision-
// resistant, so this should never happen in practice.
func (db *DB) CreateTusUpload(ctx context.Context, fileID, userID string, sizeBytes int64, backend string, expiresAt time.Time) error {
	_, err := db.Pool.Exec(ctx,
		`INSERT INTO tus_uploads (file_id, user_id, size_bytes, backend, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		fileID, userID, sizeBytes, backend, expiresAt)
	if err != nil {
		return fmt.Errorf("create tus upload: %w", err)
	}
	return nil
}

// BumpTusReceivedBytes is called by the post-receive hook on every
// PATCH so the quota window stays accurate even before completion.
// Best-effort: failures here are logged but do not fail the PATCH.
func (db *DB) BumpTusReceivedBytes(ctx context.Context, fileID string, received int64) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE tus_uploads SET received_bytes = $2 WHERE file_id = $1`,
		fileID, received)
	return err
}

// FinishTusUpload marks an upload completed and schedules the
// content-retention TTL.
func (db *DB) FinishTusUpload(ctx context.Context, fileID string, retainUntil time.Time) error {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE tus_uploads
		 SET finished_at = now(), expires_at = $2, received_bytes = size_bytes
		 WHERE file_id = $1`,
		fileID, retainUntil)
	if err != nil {
		return fmt.Errorf("finish tus upload: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("finish tus upload: no row for %q", fileID)
	}
	return nil
}

// SumTusBytesInWindow returns the total declared size_bytes uploaded
// by user_id in the trailing window. Used by the quota gate in the
// pre-create hook BEFORE we accept the upload, so an attacker cannot
// burn quota by starting then aborting.
func (db *DB) SumTusBytesInWindow(ctx context.Context, userID string, since time.Time) (int64, error) {
	var total *int64
	err := db.Pool.QueryRow(ctx,
		`SELECT SUM(size_bytes)
		 FROM tus_uploads
		 WHERE user_id = $1 AND created_at >= $2`,
		userID, since).Scan(&total)
	if err != nil {
		return 0, fmt.Errorf("sum tus bytes: %w", err)
	}
	if total == nil {
		return 0, nil
	}
	return *total, nil
}

// GetTusUpload returns one row by file_id. Used by the GET handler to
// resolve user_id (download authorization) and by the sweeper.
func (db *DB) GetTusUpload(ctx context.Context, fileID string) (*TusUpload, error) {
	var u TusUpload
	err := db.Pool.QueryRow(ctx,
		`SELECT file_id, user_id, size_bytes, received_bytes, backend, created_at, finished_at, expires_at
		 FROM tus_uploads WHERE file_id = $1`,
		fileID).Scan(&u.ID, &u.UserID, &u.SizeBytes, &u.ReceivedBytes, &u.Backend, &u.CreatedAt, &u.FinishedAt, &u.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ListExpiredTusUploads returns rows whose expires_at has passed. The
// sweeper calls this, deletes the backend blob for each, then calls
// DeleteTusUpload to drop the row. Capped to limit to keep one sweep
// cycle short.
func (db *DB) ListExpiredTusUploads(ctx context.Context, before time.Time, limit int) ([]TusUpload, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT file_id, user_id, size_bytes, received_bytes, backend, created_at, finished_at, expires_at
		 FROM tus_uploads
		 WHERE expires_at <= $1
		 ORDER BY expires_at ASC
		 LIMIT $2`,
		before, limit)
	if err != nil {
		return nil, fmt.Errorf("list expired tus uploads: %w", err)
	}
	defer rows.Close()
	var out []TusUpload
	for rows.Next() {
		var u TusUpload
		if err := rows.Scan(&u.ID, &u.UserID, &u.SizeBytes, &u.ReceivedBytes, &u.Backend, &u.CreatedAt, &u.FinishedAt, &u.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteTusUpload drops one row by file_id.
func (db *DB) DeleteTusUpload(ctx context.Context, fileID string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM tus_uploads WHERE file_id = $1`, fileID)
	return err
}
