// Package mls implements the server-side persistence and REST surface
// for OpenMLS-backed conversations introduced in Phase 6.
//
// The server is intentionally dumb about MLS internals: every blob
// (KeyPackage, Welcome, Commit) is opaque TLS-encoded bytes that we
// store, list, and fan out without parsing. Authentication and rate
// limiting come from the shared signed-request middleware.
//
// TTL: a background sweeper (registered separately) deletes welcomes
// and commits older than 30 days; key-packages older than 90 days are
// considered stale and pruned.
package mls

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps the pgx pool with the MLS-specific queries.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore returns a Store backed by the given pool.
func NewStore(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ─── KeyPackages ───────────────────────────────────────────────────

// InsertKeyPackages publishes a batch of KeyPackages for a single
// (user, device) pair. A device may keep dozens of KeyPackages in the
// pool — clients top up when the count drops below 10.
func (s *Store) InsertKeyPackages(ctx context.Context, userID string, deviceID []byte, blobs [][]byte) error {
	if len(blobs) == 0 {
		return nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	batch := &pgx.Batch{}
	for _, b := range blobs {
		batch.Queue(
			`INSERT INTO mls_key_packages (user_id, device_id, kp_blob)
			 VALUES ($1, $2, $3)`,
			userID, deviceID, b,
		)
	}
	br := tx.SendBatch(ctx, batch)
	for range blobs {
		if _, err := br.Exec(); err != nil {
			br.Close()
			return err
		}
	}
	if err := br.Close(); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeKeyPackage atomically removes and returns one KeyPackage for
// the given (user, device). If the pool is empty, returns
// pgx.ErrNoRows; the caller should fall back to retrieving the
// last-resort KeyPackage (not yet implemented in Phase 6).
func (s *Store) ConsumeKeyPackage(ctx context.Context, userID string, deviceID []byte) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx,
		`DELETE FROM mls_key_packages
		 WHERE id = (
		     SELECT id FROM mls_key_packages
		     WHERE user_id = $1 AND device_id = $2
		     ORDER BY created_at ASC
		     LIMIT 1
		     FOR UPDATE SKIP LOCKED
		 )
		 RETURNING kp_blob`,
		userID, deviceID,
	).Scan(&blob)
	return blob, err
}

// CountKeyPackages reports how many unused KeyPackages remain for the
// given (user, device).
func (s *Store) CountKeyPackages(ctx context.Context, userID string, deviceID []byte) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mls_key_packages WHERE user_id = $1 AND device_id = $2`,
		userID, deviceID,
	).Scan(&n)
	return n, err
}

// ─── Welcomes ──────────────────────────────────────────────────────

// InsertWelcome stores a Welcome destined for one specific device.
// The recipient should DELETE the row (via DeleteWelcome) after
// successfully processing the welcome.
func (s *Store) InsertWelcome(ctx context.Context, recipientUserID string, recipientDeviceID []byte, conversationID string, blob []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO mls_welcomes (recipient_user_id, recipient_device_id, conversation_id, blob)
		 VALUES ($1, $2, $3, $4)`,
		recipientUserID, recipientDeviceID, conversationID, blob,
	)
	return err
}

// PendingWelcome describes one un-consumed welcome.
type PendingWelcome struct {
	ID             string
	ConversationID string
	Blob           []byte
}

// ListWelcomes returns all pending welcomes for the given device.
func (s *Store) ListWelcomes(ctx context.Context, recipientUserID string, recipientDeviceID []byte) ([]PendingWelcome, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, conversation_id, blob
		 FROM mls_welcomes
		 WHERE recipient_user_id = $1 AND recipient_device_id = $2
		 ORDER BY created_at ASC`,
		recipientUserID, recipientDeviceID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingWelcome
	for rows.Next() {
		var w PendingWelcome
		if err := rows.Scan(&w.ID, &w.ConversationID, &w.Blob); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// DeleteWelcome removes one welcome by id, scoped to the recipient so a
// device can't delete welcomes addressed to others.
func (s *Store) DeleteWelcome(ctx context.Context, id string, recipientUserID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mls_welcomes WHERE id = $1 AND recipient_user_id = $2`,
		id, recipientUserID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// ─── Commits ───────────────────────────────────────────────────────

// ErrEpochConflict is returned when two members race to commit the same
// epoch. The loser must process the winning commit and re-propose.
var ErrEpochConflict = errors.New("epoch already committed")

// InsertCommit appends one commit to the log. Returns ErrEpochConflict
// if a commit already exists for that (conversation, epoch) — this is
// the protocol's natural concurrency control.
func (s *Store) InsertCommit(ctx context.Context, conversationID string, epoch uint64, senderUserID string, blob []byte) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO mls_commits (conversation_id, epoch, sender_user_id, blob)
		 VALUES ($1, $2, $3, $4)`,
		conversationID, int64(epoch), senderUserID, blob,
	)
	if err != nil {
		// 23505 = unique_violation.
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23505" {
			return ErrEpochConflict
		}
		return err
	}
	return nil
}

// CommitRecord describes one commit returned to clients catching up.
type CommitRecord struct {
	Epoch        uint64
	SenderUserID string
	Blob         []byte
}

// ListCommits returns all commits with epoch > afterEpoch, ordered by
// epoch ascending, so the client applies them in order.
func (s *Store) ListCommits(ctx context.Context, conversationID string, afterEpoch uint64, limit int) ([]CommitRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	rows, err := s.pool.Query(ctx,
		`SELECT epoch, sender_user_id, blob
		 FROM mls_commits
		 WHERE conversation_id = $1 AND epoch > $2
		 ORDER BY epoch ASC
		 LIMIT $3`,
		conversationID, int64(afterEpoch), limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CommitRecord
	for rows.Next() {
		var r CommitRecord
		var ep int64
		if err := rows.Scan(&ep, &r.SenderUserID, &r.Blob); err != nil {
			return nil, err
		}
		r.Epoch = uint64(ep)
		out = append(out, r)
	}
	return out, rows.Err()
}

// SweepExpired deletes welcomes older than 30 days and key-packages
// older than 90 days. Intended to be invoked by the chat sweeper.
func (s *Store) SweepExpired(ctx context.Context) (welcomes, keyPackages int64, err error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM mls_welcomes WHERE created_at < now() - interval '30 days'`)
	if err != nil {
		return 0, 0, err
	}
	welcomes = tag.RowsAffected()
	tag, err = s.pool.Exec(ctx,
		`DELETE FROM mls_key_packages WHERE created_at < now() - interval '90 days'`)
	if err != nil {
		return welcomes, 0, err
	}
	keyPackages = tag.RowsAffected()
	return
}

// httpStatusForErr maps store errors to HTTP statuses for the handler.
func httpStatusForErr(err error) int {
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return http.StatusNotFound
	case errors.Is(err, ErrEpochConflict):
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}

// parseAfterEpoch parses the optional ?after_epoch=N query param.
func parseAfterEpoch(r *http.Request) (uint64, error) {
	v := r.URL.Query().Get("after_epoch")
	if v == "" {
		return 0, nil
	}
	return strconv.ParseUint(v, 10, 64)
}
