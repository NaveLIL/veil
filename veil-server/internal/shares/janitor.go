package shares

import (
	"context"
	"log/slog"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
)

const JanitorInterval = 5 * time.Minute

// RunJanitor executes periodic purge cycles on expired and burned shares.
func RunJanitor(ctx context.Context, store Store, logger *slog.Logger) {
	if store == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	ticker := time.NewTicker(JanitorInterval)
	defer ticker.Stop()

	purge := func() {
		purgeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		deleted, err := store.JanitorPurge(purgeCtx)
		cancel()
		if err != nil {
			if ctx.Err() == nil {
				logger.Warn("secure share janitor purge failed",
					slog.String("class", logsafe.ErrorClass(err)),
				)
			}
			return
		}
		if deleted > 0 {
			logger.Info("secure share janitor purged rows",
				slog.Int64("deleted_shares", deleted),
			)
		}
	}

	// Initial purge upon startup
	purge()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			purge()
		}
	}
}
