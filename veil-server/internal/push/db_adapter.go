package push

import (
	"context"

	"github.com/AegisSec/veil-server/internal/db"
)

// dbStore adapts *db.DB to the push.Store interface so the push
// package does not import db transitively. Construction lives here so
// callers do `push.NewDBStore(database)` instead of building a closure
// at every wiring site.
type dbStore struct{ db *db.DB }

// NewDBStore returns a Store backed by the given *db.DB.
func NewDBStore(database *db.DB) Store {
	return &dbStore{db: database}
}

func (s *dbStore) ListPushSubscriptions(ctx context.Context, userID string) ([]Subscription, error) {
	rows, err := s.db.ListPushSubscriptions(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]Subscription, 0, len(rows))
	for _, r := range rows {
		out = append(out, Subscription{
			ID:          r.ID,
			UserID:      r.UserID,
			EndpointURL: r.EndpointURL,
			PushKind:    r.PushKind,
		})
	}
	return out, nil
}

func (s *dbStore) DeletePushSubscriptionByEndpoint(ctx context.Context, userID, endpointURL string) error {
	return s.db.DeletePushSubscriptionByEndpoint(ctx, userID, endpointURL)
}

func (s *dbStore) TouchPushSubscription(ctx context.Context, id int64) error {
	return s.db.TouchPushSubscription(ctx, id)
}
