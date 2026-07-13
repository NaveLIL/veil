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
	ProfileUpdateRecipients(ctx context.Context, userID string) ([]string, error)
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

// ProfileUpdateRecipients returns only accounts which already have a durable
// relationship with the profile owner on this instance. This avoids turning a
// presentation update into instance-wide UUID/activity disclosure.
func (s *PostgresStore) ProfileUpdateRecipients(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		WITH related(user_id) AS (
			SELECT $1::uuid
			UNION
			SELECT CASE WHEN user_id_1 = $1::uuid THEN user_id_2 ELSE user_id_1 END
			FROM friendships
			WHERE user_id_1 = $1::uuid OR user_id_2 = $1::uuid
			UNION
			SELECT peer.user_id
			FROM conversation_members mine
			JOIN conversation_members peer ON peer.conversation_id = mine.conversation_id
			WHERE mine.user_id = $1::uuid
			UNION
			SELECT peer.user_id
			FROM server_members mine
			JOIN server_members peer ON peer.server_id = mine.server_id
			WHERE mine.user_id = $1::uuid
		)
		SELECT user_id::text FROM related ORDER BY user_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	recipients := make([]string, 0)
	for rows.Next() {
		var recipient string
		if err := rows.Scan(&recipient); err != nil {
			return nil, err
		}
		recipients = append(recipients, recipient)
	}
	return recipients, rows.Err()
}
