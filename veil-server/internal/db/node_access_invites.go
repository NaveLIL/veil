package db

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/jackc/pgx/v5"
)

const (
	// NodeAccessInviteTokenSize provides 256 bits of cryptographic entropy.
	NodeAccessInviteTokenSize = 32
	MaxNodeAccessInviteBatch  = 1000
)

var (
	// ErrNodeAccessInviteInvalid deliberately covers malformed, unknown,
	// expired, and already-used tokens. Callers must not expose a finer-grained
	// reason to an untrusted client.
	ErrNodeAccessInviteInvalid = errors.New("node access invite is invalid")
	ErrNodeAccessInviteCount   = errors.New("node access invite count must be between 1 and 1000")
	ErrNodeAccessInviteExpiry  = errors.New("node access invite lifetime must be at least one microsecond")
)

// NodeAccessInvite is returned only at creation time. Token is the one-time
// bearer secret; no plaintext copy is stored by the database.
type NodeAccessInvite struct {
	Token     []byte
	ExpiresAt time.Time
}

// CreateNodeAccessInvites creates an atomic batch of independent 256-bit
// invites. The returned tokens are the only plaintext copies and must be
// delivered to their recipients over a private channel.
func (db *DB) CreateNodeAccessInvites(ctx context.Context, count int, lifetime time.Duration) ([]NodeAccessInvite, error) {
	if count < 1 || count > MaxNodeAccessInviteBatch {
		return nil, ErrNodeAccessInviteCount
	}
	if lifetime < time.Microsecond {
		return nil, ErrNodeAccessInviteExpiry
	}

	invites := make([]NodeAccessInvite, count)
	for i := range invites {
		token := make([]byte, NodeAccessInviteTokenSize)
		if _, err := rand.Read(token); err != nil {
			clearNodeAccessInvites(invites)
			return nil, fmt.Errorf("generate node access invite: %w", err)
		}
		invites[i] = NodeAccessInvite{Token: token}
	}

	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		clearNodeAccessInvites(invites)
		return nil, fmt.Errorf("begin node access invite batch: %w", err)
	}
	defer tx.Rollback(ctx)
	var expiresAt time.Time
	if err := tx.QueryRow(ctx,
		`SELECT clock_timestamp() + ($1::bigint * interval '1 microsecond')`,
		lifetime.Microseconds(),
	).Scan(&expiresAt); err != nil {
		clearNodeAccessInvites(invites)
		return nil, fmt.Errorf("calculate node access invite expiry: %w", err)
	}
	for i := range invites {
		invites[i].ExpiresAt = expiresAt
	}

	for i := range invites {
		tokenHash, err := nodeAccessInviteTokenHash(invites[i].Token)
		if err != nil {
			clearNodeAccessInvites(invites)
			return nil, err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO node_access_invites (token_hash, expires_at) VALUES ($1, $2)`,
			tokenHash[:], expiresAt,
		); err != nil {
			clearNodeAccessInvites(invites)
			return nil, fmt.Errorf("store node access invite: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		clearNodeAccessInvites(invites)
		return nil, fmt.Errorf("commit node access invite batch: %w", err)
	}
	return invites, nil
}

// CreateUserWithNodeAccessInvite atomically creates an account and consumes
// exactly one valid invite. A failed account insert rolls the consumption
// back, while concurrent attempts can produce at most one account.
func (db *DB) CreateUserWithNodeAccessInvite(ctx context.Context, token, identityKey, signingKey []byte, username string) (*User, error) {
	if len(token) != NodeAccessInviteTokenSize {
		return nil, ErrNodeAccessInviteInvalid
	}
	if len(identityKey) != 32 || !cryptokey.ValidEd25519PublicKey(signingKey) {
		return nil, errors.New("invalid account cryptographic public keys")
	}

	tokenHash, err := nodeAccessInviteTokenHash(token)
	if err != nil {
		return nil, err
	}
	tx, err := db.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, fmt.Errorf("begin invited registration: %w", err)
	}
	defer tx.Rollback(ctx)

	var inviteID string
	err = tx.QueryRow(ctx,
		`SELECT id::text
		 FROM node_access_invites
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		 FOR UPDATE`,
		tokenHash[:],
	).Scan(&inviteID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNodeAccessInviteInvalid
	}
	if err != nil {
		return nil, fmt.Errorf("lock node access invite: %w", err)
	}

	var user User
	err = tx.QueryRow(ctx,
		`INSERT INTO users (identity_key, signing_key, username)
		 VALUES ($1, $2, $3)
		 RETURNING id, identity_key, signing_key, username, created_at`,
		identityKey, signingKey, username,
	).Scan(&user.ID, &user.IdentityKey, &user.SigningKey, &user.Username, &user.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("create invited user: %w", err)
	}

	tag, err := tx.Exec(ctx,
		`UPDATE node_access_invites
		 SET used_at = now(), used_by_user_id = $2::uuid
		 WHERE id = $1::uuid AND used_at IS NULL AND expires_at > now()`,
		inviteID, user.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("consume node access invite: %w", err)
	}
	if tag.RowsAffected() != 1 {
		return nil, ErrNodeAccessInviteInvalid
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit invited registration: %w", err)
	}
	return &user, nil
}

func clearNodeAccessInvites(invites []NodeAccessInvite) {
	for i := range invites {
		clear(invites[i].Token)
	}
}

func nodeAccessInviteTokenHash(token []byte) ([sha256.Size]byte, error) {
	if len(token) != NodeAccessInviteTokenSize {
		return [sha256.Size]byte{}, ErrNodeAccessInviteInvalid
	}
	return sha256.Sum256(token), nil
}
