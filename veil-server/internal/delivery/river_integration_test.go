//go:build integration

package delivery

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	integrationtest "github.com/NaveLIL/veil/veil-server/internal/integration"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

func TestRiverStoreMessageTransactionAndCrashRecovery(t *testing.T) {
	h := integrationtest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := MigrateExperiment(ctx, h.DB.Pool); err != nil {
		t.Fatal(err)
	}
	// Reapplying the exact pinned target is idempotent, including migration 4/6.
	if err := MigrateExperiment(ctx, h.DB.Pool); err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(h.DB.Pool)
	if err != nil {
		t.Fatal(err)
	}
	alice := h.CreateUser("river-alice")
	bob := h.CreateUser("river-bob")
	conversationID, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	newMessage := func() *db.Message {
		return &db.Message{ConversationID: conversationID, SenderID: alice.ID, Ciphertext: []byte("opaque-encrypted-body"), Header: append([]byte{0x02}, make([]byte, 41)...), MsgType: 0}
	}
	counts := func() (int, int) {
		t.Helper()
		var messages, jobs int
		if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM messages WHERE conversation_id=$1::uuid", conversationID).Scan(&messages); err != nil {
			t.Fatal(err)
		}
		if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM "+Schema+".river_job").Scan(&jobs); err != nil {
			t.Fatal(err)
		}
		return messages, jobs
	}
	t.Run("rollback_and_visibility", func(t *testing.T) {
		tx, err := h.DB.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		m := newMessage()
		if err := h.DB.StoreMessageTx(ctx, tx, m); err != nil {
			t.Fatal(err)
		}
		if _, err := producer.InsertTx(ctx, tx, MessageRef{ConversationID: conversationID, MessageID: m.ID}); err != nil {
			t.Fatal(err)
		}
		if messages, jobs := counts(); messages != 0 || jobs != 0 {
			t.Fatalf("uncommitted state visible: %d/%d", messages, jobs)
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if messages, jobs := counts(); messages != 0 || jobs != 0 {
			t.Fatalf("rollback retained state: %d/%d", messages, jobs)
		}
	})
	t.Run("job_insert_failure_rolls_back_message", func(t *testing.T) {
		if _, err := h.DB.Pool.Exec(ctx, "ALTER TABLE "+Schema+".river_job ADD CONSTRAINT r11_fail_job CHECK (kind <> 'veil_message_ref_v1')"); err != nil {
			t.Fatal(err)
		}
		defer h.DB.Pool.Exec(ctx, "ALTER TABLE "+Schema+".river_job DROP CONSTRAINT r11_fail_job")
		tx, err := h.DB.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		m := newMessage()
		if err := h.DB.StoreMessageTx(ctx, tx, m); err != nil {
			t.Fatal(err)
		}
		if _, err := producer.InsertTx(ctx, tx, MessageRef{ConversationID: conversationID, MessageID: m.ID}); err == nil {
			t.Fatal("forced queue constraint accepted insertion")
		}
		if err := tx.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		if messages, jobs := counts(); messages != 0 || jobs != 0 {
			t.Fatalf("partial commit: %d/%d", messages, jobs)
		}
	})
	var ref MessageRef
	var jobID int64
	t.Run("commit_and_duplicate_reference", func(t *testing.T) {
		tx, err := h.DB.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		m := newMessage()
		if err := h.DB.StoreMessageTx(ctx, tx, m); err != nil {
			t.Fatal(err)
		}
		ref = MessageRef{ConversationID: conversationID, MessageID: m.ID}
		inserted, err := producer.InsertTx(ctx, tx, ref)
		if err != nil {
			t.Fatal(err)
		}
		jobID = inserted.Job.ID
		duplicate, err := producer.InsertTx(ctx, tx, ref)
		if err != nil {
			t.Fatal(err)
		}
		if !duplicate.UniqueSkippedAsDuplicate || duplicate.Job.ID != jobID {
			t.Fatal("duplicate reference created another job")
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if messages, jobs := counts(); messages != 1 || jobs != 1 {
			t.Fatalf("commit not atomic: %d/%d", messages, jobs)
		}
		var args []byte
		if err := h.DB.Pool.QueryRow(ctx, "SELECT args FROM "+Schema+".river_job WHERE id=$1", jobID).Scan(&args); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(args, m.Ciphertext) || bytes.Contains(args, []byte("sender")) || bytes.Contains(args, []byte("key")) {
			t.Fatalf("job copied message material: %s", args)
		}
	})
	if t.Failed() {
		return
	}
	if _, err := h.DB.Pool.Exec(ctx, `CREATE TABLE r11_delivery_effects(message_id uuid PRIMARY KEY);
CREATE TABLE r11_delivery_attempts(message_id uuid PRIMARY KEY, calls integer NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	t.Run("process_crash_and_durable_restore", func(t *testing.T) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		childCtx, childCancel := context.WithTimeout(ctx, 30*time.Second)
		defer childCancel()
		child := exec.CommandContext(childCtx, executable, "-test.run=^TestRiverCrashWorkerHelper$")
		child.Env = append(os.Environ(), "VEIL_R11_CRASH_DSN="+h.DB.Pool.Config().ConnConfig.ConnString())
		output, err := child.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 42 {
			t.Fatalf("worker did not crash at committed side effect: %v\n%s", err, output)
		}
		var state string
		if err := h.DB.Pool.QueryRow(ctx, "SELECT state FROM "+Schema+".river_job WHERE id=$1", jobID).Scan(&state); err != nil {
			t.Fatal(err)
		}
		if state != "running" {
			t.Fatalf("crash acknowledged job unexpectedly: %s", state)
		}
		// Accelerate the stale-attempt clock only. The real upstream rescuer and
		// leader election, not a manual state transition, recover the running job.
		if _, err := h.DB.Pool.Exec(ctx, "UPDATE "+Schema+".river_job SET attempted_at=now()-interval '5 minutes' WHERE id=$1", jobID); err != nil {
			t.Fatal(err)
		}
		client := testWorkerClient(t, h.DB.Pool, false)
		defer stopWorker(t, client)
		if err := client.Start(ctx); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(70 * time.Second)
		for state != "completed" {
			if time.Now().After(deadline) {
				t.Fatalf("crashed job not rescued: %s", state)
			}
			time.Sleep(100 * time.Millisecond)
			if err := h.DB.Pool.QueryRow(ctx, "SELECT state FROM "+Schema+".river_job WHERE id=$1", jobID).Scan(&state); err != nil {
				t.Fatal(err)
			}
		}
		var effects, calls int
		if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM r11_delivery_effects WHERE message_id=$1::uuid", ref.MessageID).Scan(&effects); err != nil {
			t.Fatal(err)
		}
		if err := h.DB.Pool.QueryRow(ctx, "SELECT calls FROM r11_delivery_attempts WHERE message_id=$1::uuid", ref.MessageID).Scan(&calls); err != nil {
			t.Fatal(err)
		}
		if effects != 1 || calls < 2 {
			t.Fatalf("side effect not idempotent across rescue: effects=%d attempts=%d", effects, calls)
		}
		// Queue uniqueness includes retained completed state; this is not a
		// substitute for the longer-lived send ledger after job retention expiry.
		tx, err := h.DB.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback(ctx)
		duplicate, err := producer.InsertTx(ctx, tx, ref)
		if err != nil {
			t.Fatal(err)
		}
		if duplicate.Job.ID != jobID || !duplicate.UniqueSkippedAsDuplicate {
			t.Fatal("completed reference recreated job")
		}
	})
}

func TestRiverDuplicateSendReusesLedgerMessageAndIntent(t *testing.T) {
	h := integrationtest.New(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := MigrateExperiment(ctx, h.DB.Pool); err != nil {
		t.Fatal(err)
	}
	producer, err := NewProducer(h.DB.Pool)
	if err != nil {
		t.Fatal(err)
	}
	alice := h.CreateUser("river-replay-alice")
	bob := h.CreateUser("river-replay-bob")
	conversationID, _, err := h.DB.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	msg := &pb.SendMessage{ClientMessageId: "33333333-3333-4333-8333-333333333333", ConversationId: conversationID, Ciphertext: []byte("opaque-replay-body"), Header: append([]byte{0x02}, make([]byte, 41)...), MsgType: pb.MessageType_MESSAGE_TYPE_TEXT}
	var messageID string
	var jobID int64
	for attempt := range 2 {
		result, err := h.Chat.HandleSendMessageResult(ctx, alice.ID, msg)
		if err != nil {
			t.Fatal(err)
		}
		if attempt == 1 && (!result.Replayed || result.MessageID != messageID) {
			t.Fatal("exact replay did not retain ledger outcome")
		}
		messageID = result.MessageID
		tx, err := h.DB.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		inserted, err := producer.InsertTx(ctx, tx, MessageRef{ConversationID: conversationID, MessageID: result.MessageID})
		if err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if attempt == 1 && (!inserted.UniqueSkippedAsDuplicate || inserted.Job.ID != jobID) {
			_ = tx.Rollback(ctx)
			t.Fatal("replayed send created another intent")
		}
		jobID = inserted.Job.ID
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var messages, jobs int
	if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM messages WHERE conversation_id=$1::uuid", conversationID).Scan(&messages); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM "+Schema+".river_job").Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if messages != 1 || jobs != 1 {
		t.Fatalf("replayed send retained %d messages/%d jobs", messages, jobs)
	}
	// This separately tests the real send ledger and queue identity. It does
	// NOT wire InsertTx into the live send's commit: that remains R12 work.
}

// This helper runs in a real child process and exits before River completion.
func TestRiverCrashWorkerHelper(t *testing.T) {
	dsn := os.Getenv("VEIL_R11_CRASH_DSN")
	if dsn == "" {
		t.Skip("child-process crash helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	client := testWorkerClient(t, pool, true)
	if err := client.Start(ctx); err != nil {
		t.Fatal(err)
	}
	<-ctx.Done()
	t.Fatal("child worker did not reach crash boundary")
}

type experimentHandler struct {
	pool  *pgxpool.Pool
	crash bool
}

func (w *experimentHandler) Handle(ctx context.Context, ref MessageRef) error {
	// At-least-once effect is idempotent. No SQL transaction/row lock is held
	// across an external action; the experiment intentionally sends no network.
	if _, err := w.pool.Exec(ctx, "INSERT INTO r11_delivery_effects(message_id) VALUES($1::uuid) ON CONFLICT DO NOTHING", ref.MessageID); err != nil {
		return err
	}
	if _, err := w.pool.Exec(ctx, "INSERT INTO r11_delivery_attempts(message_id,calls) VALUES($1::uuid,1) ON CONFLICT(message_id) DO UPDATE SET calls=r11_delivery_attempts.calls+1", ref.MessageID); err != nil {
		return err
	}
	if w.crash {
		os.Exit(42)
	}
	return nil
}

func testWorkerClient(t *testing.T, pool *pgxpool.Pool, crash bool) *river.Client[pgx.Tx] {
	t.Helper()
	workers := river.NewWorkers()
	river.AddWorker(workers, &Worker{Handler: &experimentHandler{pool: pool, crash: crash}})
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{
		Schema: Schema, PollOnly: true, Workers: workers, Queues: map[string]river.QueueConfig{Queue: {MaxWorkers: 1}},
		FetchCooldown: time.Millisecond, FetchPollInterval: 10 * time.Millisecond,
		JobTimeout: 2 * time.Second, RescueStuckJobsAfter: 3 * time.Second, SoftStopTimeout: time.Second,
		CompletedJobRetentionPeriod: time.Hour, CancelledJobRetentionPeriod: time.Hour, DiscardedJobRetentionPeriod: time.Hour,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func stopWorker(t *testing.T, client *river.Client[pgx.Tx]) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.StopAndCancel(ctx); err != nil {
		t.Errorf("worker shutdown: %v", err)
	}
}
