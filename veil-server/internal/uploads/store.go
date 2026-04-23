package uploads

import (
	"context"
	"time"

	"github.com/AegisSec/veil-server/internal/db"
)

// Store is the narrow DB surface this package needs. Defining it here
// (instead of importing *db.DB directly) keeps tusd's hooks unit
// testable with a fake store.
type Store interface {
	CreateTusUpload(ctx context.Context, fileID, userID string, sizeBytes int64, backend string, expiresAt time.Time) error
	BumpTusReceivedBytes(ctx context.Context, fileID string, received int64) error
	FinishTusUpload(ctx context.Context, fileID string, retainUntil time.Time) error
	SumTusBytesInWindow(ctx context.Context, userID string, since time.Time) (int64, error)
	GetTusUpload(ctx context.Context, fileID string) (*db.TusUpload, error)
	ListExpiredTusUploads(ctx context.Context, now time.Time, limit int) ([]db.TusUpload, error)
	DeleteTusUpload(ctx context.Context, fileID string) error
}

// dbStore is the production adapter.
type dbStore struct{ d *db.DB }

// NewDBStore returns a Store backed by the real DB pool.
func NewDBStore(d *db.DB) Store { return &dbStore{d: d} }

func (s *dbStore) CreateTusUpload(ctx context.Context, fileID, userID string, sizeBytes int64, backend string, expiresAt time.Time) error {
	return s.d.CreateTusUpload(ctx, fileID, userID, sizeBytes, backend, expiresAt)
}
func (s *dbStore) BumpTusReceivedBytes(ctx context.Context, fileID string, received int64) error {
	return s.d.BumpTusReceivedBytes(ctx, fileID, received)
}
func (s *dbStore) FinishTusUpload(ctx context.Context, fileID string, retainUntil time.Time) error {
	return s.d.FinishTusUpload(ctx, fileID, retainUntil)
}
func (s *dbStore) SumTusBytesInWindow(ctx context.Context, userID string, since time.Time) (int64, error) {
	return s.d.SumTusBytesInWindow(ctx, userID, since)
}
func (s *dbStore) GetTusUpload(ctx context.Context, fileID string) (*db.TusUpload, error) {
	return s.d.GetTusUpload(ctx, fileID)
}
func (s *dbStore) ListExpiredTusUploads(ctx context.Context, now time.Time, limit int) ([]db.TusUpload, error) {
	return s.d.ListExpiredTusUploads(ctx, now, limit)
}
func (s *dbStore) DeleteTusUpload(ctx context.Context, fileID string) error {
	return s.d.DeleteTusUpload(ctx, fileID)
}
