package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

const (
	// RESTAuthV2ReplayRetention is deliberately longer than the complete
	// two-sided 60-second timestamp window. PostgreSQL measures it from the
	// atomic claim, so process clock differences cannot shorten a live marker.
	RESTAuthV2ReplayRetention = 5 * time.Minute

	MaxRESTAuthV2ReplayCleanupBatch = 10_000
)

var (
	ErrRESTAuthV2ReplayInput = errors.New("REST auth v2 replay input is invalid")
	ErrRESTAuthV2ReplayBatch = errors.New("REST auth v2 replay cleanup batch is invalid")
)

// ClaimRESTAuthV2Nonce atomically claims an account-scoped nonce in
// PostgreSQL. It structurally implements authmw.RESTAuthV2ReplayStore without
// introducing a db -> authmw dependency. A false, nil result is a replay.
func (db *DB) ClaimRESTAuthV2Nonce(
	ctx context.Context,
	userID string,
	nonce [32]byte,
) (bool, error) {
	if ctx == nil || db == nil || db.Pool == nil || !canonicalReplayUserID(userID) || allZeroReplayNonce(nonce) {
		return false, ErrRESTAuthV2ReplayInput
	}

	tag, err := db.Pool.Exec(ctx,
		`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
		 VALUES ($1::uuid, $2, clock_timestamp() + ($3::bigint * interval '1 microsecond'))
		 ON CONFLICT (user_id, nonce) DO NOTHING`,
		userID, nonce[:], RESTAuthV2ReplayRetention.Microseconds(),
	)
	if err != nil {
		return false, fmt.Errorf("claim REST auth v2 nonce: %w", err)
	}
	switch tag.RowsAffected() {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errors.New("claim REST auth v2 nonce changed an invalid row count")
	}
}

// DeleteExpiredRESTAuthV2ReplayNonces removes at most batch expired markers.
// SKIP LOCKED permits multiple janitors without blocking a concurrent claim;
// rows whose expiry is still in the future are never selected.
func (db *DB) DeleteExpiredRESTAuthV2ReplayNonces(ctx context.Context, batch int) (int64, error) {
	if ctx == nil || db == nil || db.Pool == nil || batch < 1 || batch > MaxRESTAuthV2ReplayCleanupBatch {
		return 0, ErrRESTAuthV2ReplayBatch
	}
	tag, err := db.Pool.Exec(ctx,
		`WITH expired AS (
		   SELECT user_id, nonce
		   FROM rest_auth_v2_replay_nonces
		   WHERE expires_at <= clock_timestamp()
		   ORDER BY expires_at, user_id, nonce
		   LIMIT $1
		   FOR UPDATE SKIP LOCKED
		 )
		 DELETE FROM rest_auth_v2_replay_nonces AS marker
		 USING expired
		 WHERE marker.user_id = expired.user_id AND marker.nonce = expired.nonce`,
		batch,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired REST auth v2 replay nonces: %w", err)
	}
	return tag.RowsAffected(), nil
}

func canonicalReplayUserID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && len(value) == 36 && parsed.String() == value
}

func allZeroReplayNonce(nonce [32]byte) bool {
	var combined byte
	for _, value := range nonce {
		combined |= value
	}
	return combined == 0
}
