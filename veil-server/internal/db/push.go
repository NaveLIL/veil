package db

import (
	"context"
	"fmt"
	"time"
)

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
}

// CreatePushSubscription upserts a (user_id, endpoint_url) row and
// returns the row ID. Duplicate endpoints for the same user are
// idempotent — re-subscribing only refreshes the device_label/kind.
func (db *DB) CreatePushSubscription(ctx context.Context, userID, endpointURL, deviceLabel, kind string) (int64, error) {
	if kind == "" {
		kind = "unifiedpush"
	}
	var id int64
	err := db.Pool.QueryRow(ctx,
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
	return id, nil
}

// ListPushSubscriptions returns every subscription registered for the
// given user. Order is creation time (oldest first) — stable for tests.
func (db *DB) ListPushSubscriptions(ctx context.Context, userID string) ([]PushSubscription, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, user_id, endpoint_url, COALESCE(device_label, ''), push_kind, created_at, last_used
		 FROM push_subscriptions
		 WHERE user_id = $1
		 ORDER BY created_at ASC`, userID)
	if err != nil {
		return nil, fmt.Errorf("list push subscriptions: %w", err)
	}
	defer rows.Close()

	var out []PushSubscription
	for rows.Next() {
		var s PushSubscription
		if err := rows.Scan(&s.ID, &s.UserID, &s.EndpointURL, &s.DeviceLabel, &s.PushKind, &s.CreatedAt, &s.LastUsed); err != nil {
			return nil, fmt.Errorf("scan push subscription: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
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
