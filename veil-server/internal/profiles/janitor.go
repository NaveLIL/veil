package profiles

import (
	"context"
	"log/slog"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
)

const (
	avatarJanitorInterval  = time.Minute
	avatarJanitorBatch     = 256
	avatarJanitorRunBudget = 20 * time.Second
)

// DeleteExpiredAvatarAssets removes one bounded batch of detached normalized
// assets. It is intentionally independent of request contexts so retention is
// enforced even when no user performs another profile mutation.
func (s *PostgresStore) DeleteExpiredAvatarAssets(ctx context.Context, batch int) (int64, error) {
	if batch < 1 || batch > avatarJanitorBatch {
		batch = avatarJanitorBatch
	}
	command, err := s.pool.Exec(ctx, `
		WITH doomed AS (
			SELECT candidate.id FROM profile_avatar_assets candidate
			WHERE candidate.orphaned_at < now() - interval '24 hours'
			  AND NOT EXISTS (SELECT 1 FROM users u WHERE u.avatar_asset_id=candidate.id)
			ORDER BY candidate.orphaned_at, candidate.id
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		DELETE FROM profile_avatar_assets a
		USING doomed d
		WHERE a.id=d.id`, batch)
	if err != nil {
		return 0, err
	}
	return command.RowsAffected(), nil
}

func sweepExpiredAvatarAssets(ctx context.Context, store *PostgresStore, logger *slog.Logger) {
	runCtx, cancel := context.WithTimeout(ctx, avatarJanitorRunBudget)
	defer cancel()
	for {
		deleted, err := store.DeleteExpiredAvatarAssets(runCtx, avatarJanitorBatch)
		if err != nil {
			if ctx.Err() == nil && runCtx.Err() == nil {
				logger.Error("profile avatar janitor failed", "class", logsafe.ErrorClass(err))
			}
			return
		}
		if deleted < avatarJanitorBatch {
			return
		}
		if runCtx.Err() != nil {
			return
		}
	}
}

// RunAvatarJanitor performs an immediate sweep and then enforces retention on
// a bounded hourly cadence until the gateway shuts down.
func RunAvatarJanitor(ctx context.Context, store *PostgresStore, logger *slog.Logger) {
	if store == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}
	sweepExpiredAvatarAssets(ctx, store, logger)
	ticker := time.NewTicker(avatarJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sweepExpiredAvatarAssets(ctx, store, logger)
		}
	}
}
