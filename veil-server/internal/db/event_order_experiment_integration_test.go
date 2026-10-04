//go:build integration

package db_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// This is a characterization of the live legacy cursor plus an isolated SQL
// experiment for proposed ADR-0005. It does not activate a production feed.
func TestTimestampCursorMissesLateCommitAndCounterExperimentPreservesOrder(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	createUser := func(name string) *db.User {
		identity := newAuthIdentity(t)
		user, err := database.CreateUser(ctx, identity.identityPublic, identity.signingPublic, name)
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	alice, bob := createUser("cursor-alice"), createUser("cursor-bob")
	conversation, _, err := database.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("actual_timestamp_uuid_cursor_misses_late_commit", func(t *testing.T) {
		late, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer late.Rollback(ctx)
		var older time.Time
		if err := late.QueryRow(ctx, "SELECT now()").Scan(&older); err != nil {
			t.Fatal(err)
		}
		// Establish a strictly later database transaction timestamp without
		// relying on host wall clock or using artificial message timestamps.
		for {
			var newer bool
			if err := database.Pool.QueryRow(ctx, "SELECT clock_timestamp() > $1", older).Scan(&newer); err != nil {
				t.Fatal(err)
			}
			if newer {
				break
			}
		}
		firstVisible := &db.Message{ConversationID: conversation, SenderID: alice.ID, Ciphertext: []byte("first-visible-opaque")}
		if err := database.StoreMessage(ctx, firstVisible); err != nil {
			t.Fatal(err)
		}
		if !firstVisible.CreatedAt.After(older) {
			t.Fatal("transactions did not establish timestamp order")
		}
		page, err := database.GetConversationHistoryPage(ctx, conversation, bob.ID, time.Time{}, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Messages) != 1 || page.Messages[0].ID != firstVisible.ID {
			t.Fatal("initial snapshot did not see only committed message")
		}
		lateMessage := &db.Message{ConversationID: conversation, SenderID: alice.ID, Ciphertext: []byte("late-committed-opaque")}
		if err := database.StoreMessageTx(ctx, late, lateMessage); err != nil {
			t.Fatal(err)
		}
		if err := late.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if !lateMessage.CreatedAt.Equal(older) {
			t.Fatal("now() was not anchored to transaction start")
		}
		full, err := database.GetConversationHistoryPage(ctx, conversation, bob.ID, time.Time{}, "", 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(full.Messages) != 2 {
			t.Fatal("late commit was not stored")
		}
		for _, cursorID := range []string{"", firstVisible.ID} {
			after, err := database.GetConversationHistoryPage(ctx, conversation, bob.ID, firstVisible.CreatedAt, cursorID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Messages) != 0 {
				t.Fatal("expected characterized timestamp inversion was not reproduced")
			}
		}
		t.Log("late message exists in full history but both since and (created_at, UUID) keyset cursors skip it")
	})
	if _, err := database.Pool.Exec(ctx, `CREATE TABLE r07_bigserial_probe(seq bigserial PRIMARY KEY, label text NOT NULL);
CREATE TABLE r07_heads_probe(conversation_id uuid PRIMARY KEY, last_seq bigint NOT NULL CHECK(last_seq>=0));
CREATE TABLE r07_events_probe(conversation_id uuid NOT NULL, seq bigint NOT NULL CHECK(seq>0), label text NOT NULL, PRIMARY KEY(conversation_id,seq))`); err != nil {
		t.Fatal(err)
	}
	t.Run("bigserial_also_does_not_order_commit", func(t *testing.T) {
		late, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer late.Rollback(ctx)
		var low, visible int64
		if err := late.QueryRow(ctx, "INSERT INTO r07_bigserial_probe(label) VALUES('late') RETURNING seq").Scan(&low); err != nil {
			t.Fatal(err)
		}
		if err := database.Pool.QueryRow(ctx, "INSERT INTO r07_bigserial_probe(label) VALUES('visible') RETURNING seq").Scan(&visible); err != nil {
			t.Fatal(err)
		}
		if visible <= low {
			t.Fatal("sequence not allocated in expected order")
		}
		if err := late.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		var after int
		if err := database.Pool.QueryRow(ctx, "SELECT count(*) FROM r07_bigserial_probe WHERE seq>$1", visible).Scan(&after); err != nil {
			t.Fatal(err)
		}
		if after != 0 {
			t.Fatal("expected sequence commit inversion not reproduced")
		}
	})
	t.Run("shared_conversation_counter_serializes_commit", func(t *testing.T) {
		otherConversation := uuid.NewString()
		if _, err := database.Pool.Exec(ctx, "INSERT INTO r07_heads_probe VALUES($1::uuid,0),($2::uuid,0)", conversation, otherConversation); err != nil {
			t.Fatal(err)
		}
		appendEvent := func(ctx context.Context, tx pgx.Tx, conversationID, label string) (int64, error) {
			var seq int64
			if err := tx.QueryRow(ctx, "UPDATE r07_heads_probe SET last_seq=last_seq+1 WHERE conversation_id=$1::uuid RETURNING last_seq", conversationID).Scan(&seq); err != nil {
				return 0, err
			}
			_, err := tx.Exec(ctx, "INSERT INTO r07_events_probe VALUES($1::uuid,$2,$3)", conversationID, seq, label)
			return seq, err
		}
		committed, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seq, err := appendEvent(ctx, committed, conversation, "first"); err != nil || seq != 1 {
			_ = committed.Rollback(ctx)
			t.Fatalf("first: %d %v", seq, err)
		}
		if err := committed.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		late, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer late.Rollback(ctx)
		if seq, err := appendEvent(ctx, late, conversation, "late"); err != nil || seq != 2 {
			t.Fatalf("late: %d %v", seq, err)
		}
		var watermark int64
		if err := database.Pool.QueryRow(ctx, "SELECT last_seq FROM r07_heads_probe WHERE conversation_id=$1::uuid", conversation).Scan(&watermark); err != nil {
			t.Fatal(err)
		}
		if watermark != 1 {
			t.Fatalf("uncommitted head published: %d", watermark)
		}
		third, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		thirdCtx, thirdCancel := context.WithCancel(ctx)
		var backendPID uint32
		if err := third.QueryRow(ctx, "SELECT pg_backend_pid()").Scan(&backendPID); err != nil {
			thirdCancel()
			_ = third.Rollback(ctx)
			t.Fatal(err)
		}
		result := make(chan error, 1)
		resultConsumed := false
		go func() {
			seq, err := appendEvent(thirdCtx, third, conversation, "third")
			if err == nil && seq != 3 {
				err = fmt.Errorf("third sequence %d, want 3", seq)
			}
			if err == nil {
				err = third.Commit(thirdCtx)
			}
			result <- err
		}()
		defer func() {
			thirdCancel()
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			if !resultConsumed {
				select {
				case <-result:
				case <-cleanupCtx.Done():
					t.Error("append goroutine did not stop after cancellation")
					return // Do not call Rollback concurrently with a live pgx.Tx user.
				}
			}
			_ = third.Rollback(cleanupCtx)
		}()
		// Prove actual PostgreSQL lock wait rather than assuming goroutine
		// scheduling or declaring a short sleep to be evidence of blocking.
		deadline := time.Now().Add(2 * time.Second)
		for {
			var waiting bool
			if err := database.Pool.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock')", backendPID).Scan(&waiting); err != nil {
				t.Fatal(err)
			}
			if waiting {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("same-conversation append never waited on the held counter")
			}
			time.Sleep(time.Millisecond)
		}
		select {
		case err := <-result:
			resultConsumed = true
			t.Fatalf("later append escaped counter lock: %v", err)
		default:
		}
		independent, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seq, err := appendEvent(ctx, independent, otherConversation, "independent"); err != nil || seq != 1 {
			_ = independent.Rollback(ctx)
			t.Fatalf("independent: %d %v", seq, err)
		}
		if err := independent.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		if err := late.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-result:
			resultConsumed = true
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		rows, err := database.Pool.Query(ctx, "SELECT seq,label FROM r07_events_probe WHERE conversation_id=$1::uuid AND seq>$2 ORDER BY seq", conversation, watermark)
		if err != nil {
			t.Fatal(err)
		}
		var labels []string
		for rows.Next() {
			var seq int64
			var label string
			if err := rows.Scan(&seq, &label); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			if seq != int64(len(labels)+2) {
				rows.Close()
				t.Fatalf("sequence gap: %d", seq)
			}
			labels = append(labels, label)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if len(labels) != 2 || labels[0] != "late" || labels[1] != "third" {
			t.Fatalf("catch-up skipped committed events: %v", labels)
		}
		rolled, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seq, err := appendEvent(ctx, rolled, conversation, "rolled-back"); err != nil || seq != 4 {
			_ = rolled.Rollback(ctx)
			t.Fatalf("rollback append: %d %v", seq, err)
		}
		if err := rolled.Rollback(ctx); err != nil {
			t.Fatal(err)
		}
		next, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if seq, err := appendEvent(ctx, next, conversation, "after-rollback"); err != nil || seq != 4 {
			_ = next.Rollback(ctx)
			t.Fatalf("unpublished sequence not safely reusable: %d %v", seq, err)
		}
		if err := next.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	})
}
