package profiles

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrVersionConflict = errors.New("profile version conflict")

type Profile struct {
	UserID           string    `json:"user_id"`
	Username         string    `json:"username"`
	DisplayName      *string   `json:"display_name"`
	About            string    `json:"about"`
	ProfileVersion   int64     `json:"profile_version"`
	ProfileUpdatedAt time.Time `json:"profile_updated_at"`
}

type Store interface {
	GetProfile(ctx context.Context, userID string) (*Profile, error)
	UpdateProfile(ctx context.Context, userID string, expectedVersion int64, displayName *string, about string) (*Profile, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) GetProfile(ctx context.Context, userID string) (*Profile, error) {
	var profile Profile
	err := s.pool.QueryRow(ctx,
		`SELECT id::text, username, display_name, about, profile_version, profile_updated_at
		 FROM users WHERE id = $1::uuid`, userID,
	).Scan(&profile.UserID, &profile.Username, &profile.DisplayName, &profile.About,
		&profile.ProfileVersion, &profile.ProfileUpdatedAt)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (s *PostgresStore) UpdateProfile(
	ctx context.Context,
	userID string,
	expectedVersion int64,
	displayName *string,
	about string,
) (*Profile, error) {
	var profile Profile
	err := s.pool.QueryRow(ctx,
		`UPDATE users
		 SET display_name = $1,
		     about = $2,
		     profile_version = profile_version + 1,
		     profile_updated_at = now()
		 WHERE id = $3::uuid AND profile_version = $4
		 RETURNING id::text, username, display_name, about, profile_version, profile_updated_at`,
		displayName, about, userID, expectedVersion,
	).Scan(&profile.UserID, &profile.Username, &profile.DisplayName, &profile.About,
		&profile.ProfileVersion, &profile.ProfileUpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, err
	}
	return &profile, nil
}
