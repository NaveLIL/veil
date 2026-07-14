package profiles

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrVersionConflict         = errors.New("profile version conflict")
	ErrAvatarUploadQuota       = errors.New("avatar upload quota exceeded")
	ErrProfileAudienceTooLarge = errors.New("profile update audience exceeds fanout budget")
)

const (
	maxAvatarUploadsPerWindow       = 12
	maxProfileUpdateRecipients      = 4096
	maxRetainedOrphanAvatarAssets   = 4096
	avatarOrphanBudgetAdvisoryKeyID = int64(0x5645494c41564154) // "VEILAVAT"
)

type Profile struct {
	UserID            string    `json:"user_id"`
	Username          string    `json:"username"`
	DisplayName       *string   `json:"display_name"`
	About             string    `json:"about"`
	ProfileVersion    int64     `json:"profile_version"`
	ProfileUpdatedAt  time.Time `json:"profile_updated_at"`
	AvatarAssetID     *string   `json:"avatar_asset_id"`
	AvatarDigest      *string   `json:"avatar_digest"`
	AvatarContentType *string   `json:"avatar_content_type"`
}

type AvatarAsset struct {
	ID          string
	OwnerID     string
	ContentType string
	SHA256      []byte
	Width       int
	Height      int
	Data        []byte
}

type Store interface {
	GetProfile(ctx context.Context, userID string) (*Profile, error)
	UpdateProfile(ctx context.Context, userID string, expectedVersion int64, displayName *string, about string) (*Profile, error)
	UpdateAvatar(ctx context.Context, userID string, expectedVersion int64, asset *AvatarAsset) (*Profile, error)
	GetAvatar(ctx context.Context, assetID string) (*AvatarAsset, error)
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
	err := scanProfile(s.pool.QueryRow(ctx, profileSelect+` WHERE u.id = $1::uuid`, userID), &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

const profileSelect = `SELECT u.id::text, u.username, u.display_name, u.about,
	u.profile_version, u.profile_updated_at, u.avatar_asset_id::text,
	encode(a.sha256, 'hex'), a.content_type
	FROM users u LEFT JOIN profile_avatar_assets a ON a.id = u.avatar_asset_id`

type rowScanner interface{ Scan(dest ...any) error }

func scanProfile(row rowScanner, profile *Profile) error {
	return row.Scan(&profile.UserID, &profile.Username, &profile.DisplayName, &profile.About,
		&profile.ProfileVersion, &profile.ProfileUpdatedAt, &profile.AvatarAssetID,
		&profile.AvatarDigest, &profile.AvatarContentType)
}

func (s *PostgresStore) UpdateProfile(
	ctx context.Context,
	userID string,
	expectedVersion int64,
	displayName *string,
	about string,
) (*Profile, error) {
	var profile Profile
	row := s.pool.QueryRow(ctx,
		`WITH updated AS (UPDATE users
		 SET display_name = $1,
		     about = $2,
		     profile_version = profile_version + 1,
		     profile_updated_at = now()
		 WHERE id = $3::uuid AND profile_version = $4
		 RETURNING *)
		 SELECT x.id::text, x.username, x.display_name, x.about,
			x.profile_version, x.profile_updated_at, x.avatar_asset_id::text,
			encode(a.sha256, 'hex'), a.content_type
		 FROM updated x LEFT JOIN profile_avatar_assets a ON a.id = x.avatar_asset_id`,
		displayName, about, userID, expectedVersion)
	err := scanProfile(row, &profile)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrVersionConflict
	}
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func (s *PostgresStore) UpdateAvatar(ctx context.Context, userID string, expectedVersion int64, asset *AvatarAsset) (*Profile, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var oldID *string
	var currentVersion int64
	var resetUploadWindow bool
	var uploadCount int
	if err = tx.QueryRow(ctx, `SELECT avatar_asset_id::text, profile_version,
		COALESCE(avatar_upload_window_started_at <= now() - interval '24 hours', true),
		avatar_upload_count
		FROM users WHERE id=$1::uuid FOR UPDATE`, userID).Scan(
		&oldID, &currentVersion, &resetUploadWindow, &uploadCount,
	); err != nil {
		return nil, err
	}
	if currentVersion != expectedVersion {
		return nil, ErrVersionConflict
	}
	if asset != nil && !resetUploadWindow && uploadCount >= maxAvatarUploadsPerWindow {
		return nil, ErrAvatarUploadQuota
	}
	var nextID *string
	if asset != nil {
		asset.ID = uuid.NewString()
		asset.OwnerID = userID
		if _, err = tx.Exec(ctx, `INSERT INTO profile_avatar_assets
			(id, owner_id, content_type, sha256, width, height, data)
			VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7)`, asset.ID, userID, asset.ContentType, asset.SHA256, asset.Width, asset.Height, asset.Data); err != nil {
			return nil, err
		}
		nextID = &asset.ID
	}
	if asset != nil {
		if _, err = tx.Exec(ctx, `UPDATE users SET avatar_asset_id=$1::uuid,
			profile_version=profile_version+1, profile_updated_at=now(),
			avatar_upload_window_started_at=CASE WHEN $3 THEN now() ELSE avatar_upload_window_started_at END,
			avatar_upload_count=CASE WHEN $3 THEN 1 ELSE avatar_upload_count+1 END
			WHERE id=$2::uuid`, nextID, userID, resetUploadWindow); err != nil {
			return nil, err
		}
	} else if _, err = tx.Exec(ctx, `UPDATE users SET avatar_asset_id=NULL,
		profile_version=profile_version+1, profile_updated_at=now() WHERE id=$1::uuid`, userID); err != nil {
		return nil, err
	}
	if oldID != nil {
		if _, err = tx.Exec(ctx, `UPDATE profile_avatar_assets SET orphaned_at=now() WHERE id=$1::uuid AND owner_id=$2::uuid`, *oldID, userID); err != nil {
			return nil, err
		}
		// Serialize the global orphan budget across gateway replicas. Current
		// avatars are never budget-evicted; only detached presentation bytes may
		// lose part of their *maximum* 24-hour grace under storage pressure.
		if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, avatarOrphanBudgetAdvisoryKeyID); err != nil {
			return nil, err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM profile_avatar_assets doomed
			WHERE doomed.id IN (
				SELECT candidate.id FROM profile_avatar_assets candidate
				WHERE candidate.orphaned_at IS NOT NULL
				  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_asset_id=candidate.id)
				ORDER BY candidate.orphaned_at DESC, candidate.id DESC
				OFFSET $1
				LIMIT 128
			)`, maxRetainedOrphanAvatarAssets); err != nil {
			return nil, err
		}
	}
	var profile Profile
	if err = scanProfile(tx.QueryRow(ctx, profileSelect+` WHERE u.id=$1::uuid`, userID), &profile); err != nil {
		return nil, err
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &profile, nil
}

func (s *PostgresStore) GetAvatar(ctx context.Context, assetID string) (*AvatarAsset, error) {
	var asset AvatarAsset
	err := s.pool.QueryRow(ctx, `SELECT a.id::text, a.owner_id::text, a.content_type,
		a.sha256, a.width, a.height, a.data FROM profile_avatar_assets a
		JOIN users u ON u.id=a.owner_id AND u.avatar_asset_id=a.id
		WHERE a.id=$1::uuid AND a.orphaned_at IS NULL`, assetID).Scan(
		&asset.ID, &asset.OwnerID, &asset.ContentType, &asset.SHA256, &asset.Width, &asset.Height, &asset.Data)
	if err != nil {
		return nil, err
	}
	return &asset, nil
}

// ProfileUpdateRecipients returns only accounts which already have a durable
// relationship with the profile owner on this instance. This avoids turning a
// presentation update into instance-wide UUID/activity disclosure.
func (s *PostgresStore) ProfileUpdateRecipients(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT source, user_id::text FROM (
			SELECT 0 AS source, $1::uuid AS user_id
			UNION ALL
			SELECT * FROM (
				SELECT 1 AS source,
					CASE WHEN user_id_1 = $1::uuid THEN user_id_2 ELSE user_id_1 END AS user_id
				FROM friendships
				WHERE user_id_1 = $1::uuid OR user_id_2 = $1::uuid
				LIMIT $2
			) friends
			UNION ALL
			SELECT * FROM (
				SELECT 2 AS source, peer.user_id
				FROM conversation_members mine
				JOIN conversation_members peer ON peer.conversation_id = mine.conversation_id
				WHERE mine.user_id = $1::uuid
				LIMIT $2
			) conversations
			UNION ALL
			SELECT * FROM (
				SELECT 3 AS source, peer.user_id
				FROM server_members mine
				JOIN server_members peer ON peer.server_id = mine.server_id
				WHERE mine.user_id = $1::uuid
				LIMIT $2
			) servers
		) bounded_related`, userID, maxProfileUpdateRecipients+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	branchCounts := [4]int{}
	unique := make(map[string]struct{}, maxProfileUpdateRecipients)
	for rows.Next() {
		var source int
		var recipient string
		if err := rows.Scan(&source, &recipient); err != nil {
			return nil, err
		}
		if source < 0 || source >= len(branchCounts) {
			return nil, ErrProfileAudienceTooLarge
		}
		branchCounts[source]++
		if source != 0 && branchCounts[source] > maxProfileUpdateRecipients {
			return nil, ErrProfileAudienceTooLarge
		}
		unique[recipient] = struct{}{}
		if len(unique) > maxProfileUpdateRecipients {
			return nil, ErrProfileAudienceTooLarge
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	recipients := make([]string, 0, len(unique))
	for recipient := range unique {
		recipients = append(recipients, recipient)
	}
	sort.Strings(recipients)
	return recipients, nil
}
