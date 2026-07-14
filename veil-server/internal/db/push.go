package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

const MaxPushSubscriptionsPerUser = 16

var ErrPushSubscriptionLimit = errors.New("push subscription limit reached")

// PushSubscription is one (user, distributor endpoint) binding used by
// the offline delivery worker. EndpointURL is opaque (UnifiedPush spec
// — the distributor app on the device decides the URL); we never parse
// or expose it beyond storing and POSTing to it.
type PushSubscription struct {
	ID          int64
	UserID      string
	EndpointURL string
	DeviceLabel string
	PushKind    string
	CreatedAt   time.Time
	LastUsed    *time.Time
	Enabled     bool
	MutedUntil  *time.Time
}

// CreatePushSubscription upserts a (user_id, endpoint_url) row and
// returns the row ID. Duplicate endpoints for the same user are
// idempotent — re-subscribing only refreshes the device_label/kind.
func (db *DB) CreatePushSubscription(ctx context.Context, userID, endpointURL, deviceLabel, kind string) (int64, error) {
	if kind == "" {
		kind = "unifiedpush"
	}
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("begin push subscription: %w", err)
	}
	defer tx.Rollback(ctx)
	// Serialize subscription changes for this user. An existing endpoint stays
	// idempotent at the cap, while concurrent new endpoints cannot all observe
	// the same below-cap count.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text, 31))`,
		userID,
	); err != nil {
		return 0, fmt.Errorf("lock push subscriptions: %w", err)
	}
	var existingID int64
	err = tx.QueryRow(ctx,
		`SELECT id FROM push_subscriptions
		 WHERE user_id = $1::uuid AND endpoint_url = $2`,
		userID, endpointURL,
	).Scan(&existingID)
	if err == nil {
		if _, err := tx.Exec(ctx,
			`UPDATE push_subscriptions
			 SET device_label = NULLIF($3, ''), push_kind = $4
			 WHERE id = $1 AND user_id = $2::uuid`,
			existingID, userID, deviceLabel, kind,
		); err != nil {
			return 0, fmt.Errorf("update push subscription: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return 0, fmt.Errorf("commit push subscription: %w", err)
		}
		return existingID, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, fmt.Errorf("lookup push subscription: %w", err)
	}
	var count int
	if err := tx.QueryRow(ctx,
		`SELECT COUNT(*) FROM push_subscriptions WHERE user_id = $1::uuid`,
		userID,
	).Scan(&count); err != nil {
		return 0, fmt.Errorf("count push subscriptions: %w", err)
	}
	if count >= MaxPushSubscriptionsPerUser {
		return 0, ErrPushSubscriptionLimit
	}
	var id int64
	err = tx.QueryRow(ctx,
		`INSERT INTO push_subscriptions (user_id, endpoint_url, device_label, push_kind)
		 VALUES ($1, $2, NULLIF($3, ''), $4)
		 ON CONFLICT (user_id, endpoint_url) DO UPDATE
		 SET device_label = EXCLUDED.device_label,
		     push_kind    = EXCLUDED.push_kind
		 RETURNING id`,
		userID, endpointURL, deviceLabel, kind,
	).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("create push subscription: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("commit push subscription: %w", err)
	}
	return id, nil
}

// ListPushSubscriptions returns every subscription registered for the
// given user. Order is creation time (oldest first) — stable for tests.
func (db *DB) ListPushSubscriptions(ctx context.Context, userID string) ([]PushSubscription, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, endpoint_url, COALESCE(device_label, ''), push_kind, created_at, last_used,
		        enabled, muted_until
		 FROM push_subscriptions
		 WHERE user_id = $1
		 ORDER BY created_at ASC
		 LIMIT $2`, userID, MaxPushSubscriptionsPerUser)
	if err != nil {
		return nil, fmt.Errorf("list push subscriptions: %w", err)
	}
	defer rows.Close()

	var out []PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.EndpointURL, &s.DeviceLabel, &s.PushKind, &s.CreatedAt, &s.LastUsed, &s.Enabled, &s.MutedUntil); err != nil {
			return nil, fmt.Errorf("scan push subscription: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ListActivePushSubscriptions is the only dispatcher projection. Applying the
// policy in SQL prevents disabled/muted endpoints from receiving even a
// metadata-only wake-up or its timing signal.
func (db *DB) ListActivePushSubscriptions(ctx context.Context, userID string) ([]PushSubscription, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, endpoint_url, COALESCE(device_label, ''), push_kind, created_at, last_used,
		        enabled, muted_until
		 FROM push_subscriptions
		 WHERE user_id = $1
		   AND enabled = TRUE
		   AND (muted_until IS NULL OR muted_until <= now())
		 ORDER BY created_at ASC
		 LIMIT $2`, userID, MaxPushSubscriptionsPerUser)
	if err != nil {
		return nil, fmt.Errorf("list active push subscriptions: %w", err)
	}
	defer rows.Close()

	var out []PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.EndpointURL, &s.DeviceLabel, &s.PushKind, &s.CreatedAt, &s.LastUsed, &s.Enabled, &s.MutedUntil); err != nil {
			return nil, fmt.Errorf("scan active push subscription: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// UpdatePushSubscriptionPolicy changes only a subscription owned by userID.
// muteSeconds=0 clears DND; positive values are converted using the database
// clock so dispatcher and policy share one time source.
func (db *DB) UpdatePushSubscriptionPolicy(ctx context.Context, userID string, id int64, enabled *bool, muteSeconds *int64) (bool, error) {
	tag, err := db.Pool.Exec(ctx,
		`UPDATE push_subscriptions
		 SET enabled = CASE WHEN $3::boolean IS NULL THEN enabled ELSE $3 END,
		     muted_until = CASE
		       WHEN $4::bigint IS NULL THEN muted_until
		       WHEN $4 = 0 THEN NULL
		       ELSE now() + ($4 * interval '1 second')
		     END
		 WHERE id = $1 AND user_id = $2::uuid`,
		id, userID, enabled, muteSeconds)
	if err != nil {
		return false, fmt.Errorf("update push subscription policy: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeletePushSubscription removes a subscription by ID, scoped to the
// owning user (so other users cannot delete each other's bindings).
// Returns true if a row was actually deleted.
func (db *DB) DeletePushSubscription(ctx context.Context, userID string, id int64) (bool, error) {
	tag, err := db.Pool.Exec(ctx,
		`DELETE FROM push_subscriptions WHERE id = $1 AND user_id = $2`,
		id, userID)
	if err != nil {
		return false, fmt.Errorf("delete push subscription: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// DeletePushSubscriptionByEndpoint removes the row matching (user_id,
// endpoint_url). Used by the dispatcher when a 410 Gone is received.
func (db *DB) DeletePushSubscriptionByEndpoint(ctx context.Context, userID, endpointURL string) error {
	_, err := db.Pool.Exec(ctx,
		`DELETE FROM push_subscriptions WHERE user_id = $1 AND endpoint_url = $2`,
		userID, endpointURL)
	if err != nil {
		return fmt.Errorf("delete push subscription by endpoint: %w", err)
	}
	return nil
}

// TouchPushSubscription bumps last_used to now() after a successful
// dispatch. Best-effort — the dispatcher logs but does not fail on
// errors here.
func (db *DB) TouchPushSubscription(ctx context.Context, id int64) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE push_subscriptions SET last_used = now() WHERE id = $1`, id)
	return err
}
