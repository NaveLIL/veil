// Package delivery contains the R11 River experiment. It is deliberately not
// wired into production fan-out: device authorization and event contracts are
// required before R12 can use a durable delivery worker.
package delivery

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/riverqueue/river/rivertype"
)

const (
	Schema                    = "veil_delivery_experiment"
	SchemaTargetVersion       = 7 // river/riverpgxv5 v0.47.0, main migration line
	Queue                     = "veil_delivery_experiment"
	MigrationLockID     int64 = 0x5645494c523131 // VEILR11, experiment-only
)

// MessageRef is a bounded reference, never a copy of plaintext, ciphertext,
// identity metadata, keys or a precomputed recipient list.
type MessageRef struct {
	ConversationID string `json:"conversation_id"`
	MessageID      string `json:"message_id"`
}

func (MessageRef) Kind() string { return "veil_message_ref_v1" }

func (ref MessageRef) valid() bool {
	for _, value := range []string{ref.ConversationID, ref.MessageID} {
		parsed, err := uuid.Parse(value)
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return false
		}
	}
	return true
}

type Producer struct{ client *river.Client[pgx.Tx] }

func NewProducer(pool *pgxpool.Pool) (*Producer, error) {
	if pool == nil {
		return nil, errors.New("delivery experiment requires a pool")
	}
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{Schema: Schema})
	if err != nil {
		return nil, err
	}
	return &Producer{client: client}, nil
}

// InsertTx does not begin or commit a transaction. The caller can join it to
// StoreMessageTx; its references are visible to a worker only after commit.
// Uniqueness covers completed jobs while retained. Durable send replay must
// still be governed by Veil's ledger, not queue-retention-based uniqueness.
func (p *Producer) InsertTx(ctx context.Context, tx pgx.Tx, ref MessageRef) (*rivertype.JobInsertResult, error) {
	if tx == nil || !ref.valid() {
		return nil, errors.New("invalid delivery reference")
	}
	var stored bool
	if err := tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM messages WHERE id=$1::uuid AND conversation_id=$2::uuid)", ref.MessageID, ref.ConversationID).Scan(&stored); err != nil {
		return nil, err
	}
	if !stored {
		return nil, errors.New("delivery reference does not match a stored message")
	}
	return p.client.InsertTx(ctx, tx, ref, &river.InsertOpts{
		Queue: Queue, MaxAttempts: 5, UniqueOpts: river.UniqueOpts{ByArgs: true},
	})
}

// ReferenceHandler must be idempotent across attempts and must resolve current
// authorization/bindings before external delivery. Worker owns no SQL lock or
// transaction while the handler executes. There is no production handler yet.
type ReferenceHandler interface {
	Handle(context.Context, MessageRef) error
}

type Worker struct {
	river.WorkerDefaults[MessageRef]
	Handler ReferenceHandler
}

func (w *Worker) Work(ctx context.Context, job *river.Job[MessageRef]) error {
	if w.Handler == nil || job == nil || !job.Args.valid() {
		return errors.New("invalid delivery worker input")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return w.Handler.Handle(ctx, job.Args)
}

// A short bounded experiment policy, not the production provider TTL/retry
// policy. MaxAttempts is separately capped on insertion.
func (*Worker) NextRetry(job *river.Job[MessageRef]) time.Time {
	attempt := min(max(job.Attempt, 1), 5)
	return time.Now().Add(time.Duration(attempt) * 250 * time.Millisecond)
}

// MigrateExperiment applies pinned steps in separate upstream transactions.
// Coordination uses a distinct connection, requiring at least two pool slots.
// Never place the combined upstream --all SQL inside Veil's file transaction.
// Production adoption must join the deployment migrator's shared coordination.
func MigrateExperiment(ctx context.Context, pool *pgxpool.Pool) error {
	if pool == nil || pool.Config().MaxConns < 2 {
		return errors.New("River migration requires at least two pool connections")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	lock, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = lock.Rollback(cleanupCtx)
	}()
	if _, err := lock.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", MigrationLockID); err != nil {
		return err
	}
	// The schema has to be committed before River's separate connection uses it.
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+Schema); err != nil {
		return err
	}
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), &rivermigrate.Config{Schema: Schema})
	if err != nil {
		return err
	}
	if _, err := migrator.Migrate(ctx, rivermigrate.DirectionUp, &rivermigrate.MigrateOpts{TargetVersion: SchemaTargetVersion}); err != nil {
		return err
	}
	validation, err := migrator.Validate(ctx, &rivermigrate.ValidateOpts{TargetVersion: SchemaTargetVersion})
	if err != nil {
		return err
	}
	if !validation.OK {
		return errors.New("River schema validation failed")
	}
	return lock.Commit(ctx)
}
