package shares

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrShareNotFound     = errors.New("share not found")
	ErrShareExpired      = errors.New("share expired")
	ErrShareBurned       = errors.New("share burned")
	ErrShareRevoked      = errors.New("share revoked")
	ErrRedemptionFailed  = errors.New("redemption authorization failed")
	ErrLeaseInvalid      = errors.New("lease token invalid or expired")
	ErrMaxSharesExceeded = errors.New("creator active share quota exceeded")
)

const (
	MaxActiveSharesPerUser = 100
	MaxCiphertextSize      = 2 * 1024 * 1024 // 2 MiB for Phase 4G.1 (fits within 4 MiB REST body)
	DefaultLeaseDuration   = 10 * time.Minute
)

type SecureShare struct {
	ID                   string     `json:"id"`
	PublicSelector       string     `json:"public_selector"`
	RedemptionHash       []byte     `json:"-"`
	ReportCapabilityHash []byte     `json:"-"`
	CreatorUserID        string     `json:"creator_user_id"`
	Ciphertext           []byte     `json:"-"`
	SizeBytes            int64      `json:"size_bytes"`
	ContentType          string     `json:"content_type"`
	MaxClaims            int        `json:"max_claims"`
	ConsumedClaims       int        `json:"consumed_claims"`
	Status               string     `json:"status"`
	ExpiresAt            time.Time  `json:"expires_at"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
}

type PublicShareMetadata struct {
	PublicSelector string    `json:"public_selector"`
	ContentType    string    `json:"content_type"`
	SizeBytes      int64     `json:"size_bytes"`
	MaxClaims      int       `json:"max_claims"`
	ConsumedClaims int       `json:"consumed_claims"`
	Status         string    `json:"status"`
	ExpiresAt      time.Time `json:"expires_at"`
	CreatedAt      time.Time `json:"created_at"`
}

type ShareLease struct {
	ID             string    `json:"id"`
	ShareID        string    `json:"share_id"`
	LeaseTokenHash []byte    `json:"-"`
	ExpiresAt      time.Time `json:"expires_at"`
	Status         string    `json:"status"`
	CreatedAt      time.Time `json:"created_at"`
}

type Store interface {
	CreateShare(ctx context.Context, share *SecureShare) (*SecureShare, error)
	ListCreatorShares(ctx context.Context, creatorUserID string, limit int) ([]*SecureShare, error)
	RevokeShare(ctx context.Context, creatorUserID string, selector string) error
	GetPublicMetadata(ctx context.Context, selector string) (*PublicShareMetadata, error)
	ClaimShare(ctx context.Context, selector string, redemptionKey []byte, leaseTokenHash []byte, leaseDuration time.Duration) (*ShareLease, error)
	GetCiphertextByLease(ctx context.Context, selector string, leaseTokenHash []byte) ([]byte, string, int64, error)
	JanitorPurge(ctx context.Context) (int64, error)
}

type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

func (s *PostgresStore) CreateShare(ctx context.Context, share *SecureShare) (*SecureShare, error) {
	creatorUUID, err := uuid.Parse(share.CreatorUserID)
	if err != nil {
		return nil, errors.New("invalid creator user ID")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var activeCount int
	err = tx.QueryRow(ctx, `
		SELECT COUNT(*) FROM secure_shares_v1
		WHERE creator_user_id = $1 AND status = 'active' AND expires_at > now()
	`, creatorUUID).Scan(&activeCount)
	if err != nil {
		return nil, err
	}
	if activeCount >= MaxActiveSharesPerUser {
		return nil, ErrMaxSharesExceeded
	}

	var created SecureShare
	err = tx.QueryRow(ctx, `
		INSERT INTO secure_shares_v1 (
			public_selector, redemption_hash, report_capability_hash,
			creator_user_id, ciphertext, size_bytes, content_type,
			max_claims, consumed_claims, status, expires_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, 0, 'active', $9
		) RETURNING id, public_selector, creator_user_id, size_bytes, content_type,
		            max_claims, consumed_claims, status, expires_at, created_at
	`,
		share.PublicSelector,
		share.RedemptionHash,
		share.ReportCapabilityHash,
		creatorUUID,
		share.Ciphertext,
		share.SizeBytes,
		share.ContentType,
		share.MaxClaims,
		share.ExpiresAt,
	).Scan(
		&created.ID,
		&created.PublicSelector,
		&created.CreatorUserID,
		&created.SizeBytes,
		&created.ContentType,
		&created.MaxClaims,
		&created.ConsumedClaims,
		&created.Status,
		&created.ExpiresAt,
		&created.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &created, nil
}

func (s *PostgresStore) ListCreatorShares(ctx context.Context, creatorUserID string, limit int) ([]*SecureShare, error) {
	creatorUUID, err := uuid.Parse(creatorUserID)
	if err != nil {
		return nil, errors.New("invalid creator user ID")
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, public_selector, creator_user_id, size_bytes, content_type,
		       max_claims, consumed_claims,
		       CASE
		         WHEN status = 'active' AND expires_at <= now() THEN 'expired'
		         ELSE status
		       END AS computed_status,
		       expires_at, revoked_at, created_at
		FROM secure_shares_v1
		WHERE creator_user_id = $1
		ORDER BY created_at DESC
		LIMIT $2
	`, creatorUUID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*SecureShare
	for rows.Next() {
		var item SecureShare
		if err := rows.Scan(
			&item.ID,
			&item.PublicSelector,
			&item.CreatorUserID,
			&item.SizeBytes,
			&item.ContentType,
			&item.MaxClaims,
			&item.ConsumedClaims,
			&item.Status,
			&item.ExpiresAt,
			&item.RevokedAt,
			&item.CreatedAt,
		); err != nil {
			return nil, err
		}
		shares = append(shares, &item)
	}
	return shares, rows.Err()
}

func (s *PostgresStore) RevokeShare(ctx context.Context, creatorUserID string, selector string) error {
	creatorUUID, err := uuid.Parse(creatorUserID)
	if err != nil {
		return errors.New("invalid creator user ID")
	}

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var shareID string
	var currentStatus string
	err = tx.QueryRow(ctx, `
		SELECT id, status FROM secure_shares_v1
		WHERE creator_user_id = $1 AND public_selector = $2
		FOR UPDATE
	`, creatorUUID, selector).Scan(&shareID, &currentStatus)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrShareNotFound
		}
		return err
	}

	if currentStatus == "revoked" {
		return nil
	}

	_, err = tx.Exec(ctx, `
		UPDATE secure_shares_v1
		SET status = 'revoked', revoked_at = now()
		WHERE id = $1
	`, shareID)
	if err != nil {
		return err
	}

	_, err = tx.Exec(ctx, `
		UPDATE secure_share_leases_v1
		SET status = 'revoked'
		WHERE share_id = $1 AND status = 'issued'
	`, shareID)
	if err != nil {
		return err
	}

	return tx.Commit(ctx)
}

func (s *PostgresStore) GetPublicMetadata(ctx context.Context, selector string) (*PublicShareMetadata, error) {
	var meta PublicShareMetadata
	var rawStatus string
	err := s.pool.QueryRow(ctx, `
		SELECT public_selector, content_type, size_bytes, max_claims, consumed_claims,
		       status, expires_at, created_at
		FROM secure_shares_v1
		WHERE public_selector = $1
	`, selector).Scan(
		&meta.PublicSelector,
		&meta.ContentType,
		&meta.SizeBytes,
		&meta.MaxClaims,
		&meta.ConsumedClaims,
		&rawStatus,
		&meta.ExpiresAt,
		&meta.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrShareNotFound
		}
		return nil, err
	}

	if rawStatus == "revoked" {
		return nil, ErrShareRevoked
	}
	if time.Now().After(meta.ExpiresAt) || rawStatus == "expired" {
		return nil, ErrShareExpired
	}
	if rawStatus == "burned" || meta.ConsumedClaims >= meta.MaxClaims {
		return nil, ErrShareBurned
	}

	meta.Status = rawStatus
	return &meta, nil
}

func (s *PostgresStore) ClaimShare(
	ctx context.Context,
	selector string,
	redemptionKey []byte,
	leaseTokenHash []byte,
	leaseDuration time.Duration,
) (*ShareLease, error) {
	if len(redemptionKey) != 32 || len(leaseTokenHash) != 32 {
		return nil, errors.New("invalid key or token hash length")
	}
	if leaseDuration <= 0 || leaseDuration > time.Hour {
		leaseDuration = DefaultLeaseDuration
	}

	computedHash := sha256.Sum256(redemptionKey)

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var shareID string
	var storedRedemptionHash []byte
	var maxClaims int
	var consumedClaims int
	var status string
	var expiresAt time.Time

	err = tx.QueryRow(ctx, `
		SELECT id, redemption_hash, max_claims, consumed_claims, status, expires_at
		FROM secure_shares_v1
		WHERE public_selector = $1
		FOR UPDATE
	`, selector).Scan(
		&shareID,
		&storedRedemptionHash,
		&maxClaims,
		&consumedClaims,
		&status,
		&expiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrShareNotFound
		}
		return nil, err
	}

	if status == "revoked" {
		return nil, ErrShareRevoked
	}
	if time.Now().After(expiresAt) || status == "expired" {
		return nil, ErrShareExpired
	}
	if status == "burned" || consumedClaims >= maxClaims {
		return nil, ErrShareBurned
	}

	// Constant time comparison of redemption hash
	if subtle.ConstantTimeCompare(computedHash[:], storedRedemptionHash) != 1 {
		return nil, ErrRedemptionFailed
	}

	newConsumed := consumedClaims + 1
	newStatus := "active"
	if newConsumed >= maxClaims {
		newStatus = "burned"
	}

	_, err = tx.Exec(ctx, `
		UPDATE secure_shares_v1
		SET consumed_claims = $1, status = $2
		WHERE id = $3
	`, newConsumed, newStatus, shareID)
	if err != nil {
		return nil, err
	}

	leaseExpiry := time.Now().Add(leaseDuration)
	if leaseExpiry.After(expiresAt) {
		leaseExpiry = expiresAt
	}

	var lease ShareLease
	err = tx.QueryRow(ctx, `
		INSERT INTO secure_share_leases_v1 (
			share_id, lease_token_hash, expires_at, status
		) VALUES (
			$1, $2, $3, 'issued'
		) RETURNING id, share_id, expires_at, status, created_at
	`, shareID, leaseTokenHash, leaseExpiry).Scan(
		&lease.ID,
		&lease.ShareID,
		&lease.ExpiresAt,
		&lease.Status,
		&lease.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &lease, nil
}

func (s *PostgresStore) GetCiphertextByLease(
	ctx context.Context,
	selector string,
	leaseTokenHash []byte,
) ([]byte, string, int64, error) {
	if len(leaseTokenHash) != 32 {
		return nil, "", 0, errors.New("invalid lease token hash length")
	}

	var ciphertext []byte
	var contentType string
	var sizeBytes int64
	var leaseStatus string
	var leaseExpiresAt time.Time
	var shareStatus string
	var shareExpiresAt time.Time

	err := s.pool.QueryRow(ctx, `
		SELECT s.ciphertext, s.content_type, s.size_bytes, s.status, s.expires_at,
		       l.status, l.expires_at
		FROM secure_shares_v1 s
		JOIN secure_share_leases_v1 l ON l.share_id = s.id
		WHERE s.public_selector = $1 AND l.lease_token_hash = $2
	`, selector, leaseTokenHash).Scan(
		&ciphertext,
		&contentType,
		&sizeBytes,
		&shareStatus,
		&shareExpiresAt,
		&leaseStatus,
		&leaseExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, "", 0, ErrLeaseInvalid
		}
		return nil, "", 0, err
	}

	if shareStatus == "revoked" || leaseStatus == "revoked" {
		return nil, "", 0, ErrShareRevoked
	}
	if time.Now().After(shareExpiresAt) || time.Now().After(leaseExpiresAt) || leaseStatus != "issued" {
		return nil, "", 0, ErrLeaseInvalid
	}

	return ciphertext, contentType, sizeBytes, nil
}

func (s *PostgresStore) JanitorPurge(ctx context.Context) (int64, error) {
	// Mark expired shares
	_, _ = s.pool.Exec(ctx, `
		UPDATE secure_shares_v1
		SET status = 'expired'
		WHERE status = 'active' AND expires_at <= now()
	`)

	// Mark expired leases
	_, _ = s.pool.Exec(ctx, `
		UPDATE secure_share_leases_v1
		SET status = 'expired'
		WHERE status = 'issued' AND expires_at <= now()
	`)

	// Delete shares that are expired or revoked for more than 7 days, or burned with no active leases
	res, err := s.pool.Exec(ctx, `
		DELETE FROM secure_shares_v1
		WHERE (
			status IN ('expired', 'revoked') AND expires_at <= now() - interval '7 days'
		) OR (
			status = 'burned' AND NOT EXISTS (
				SELECT 1 FROM secure_share_leases_v1 l
				WHERE l.share_id = secure_shares_v1.id AND l.status = 'issued' AND l.expires_at > now()
			) AND expires_at <= now() - interval '1 day'
		)
	`)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}
