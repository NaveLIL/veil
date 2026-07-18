//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestReactionAdmissionCapIsRaceSafe(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	createUser := func(identityByte byte, username string) *db.User {
		t.Helper()
		signingPublic, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		user, err := database.CreateUser(
			ctx,
			bytes.Repeat([]byte{identityByte}, 32),
			signingPublic,
			username,
		)
		if err != nil {
			t.Fatal(err)
		}
		return user
	}
	alice := createUser(0x31, "reaction-cap-alice")
	bob := createUser(0x32, "reaction-cap-bob")
	conversationID, _, err := database.FindOrCreateDM(ctx, alice.ID, bob.ID)
	if err != nil {
		t.Fatal(err)
	}
	message := &db.Message{
		ConversationID: conversationID,
		SenderID:       alice.ID,
		Ciphertext:     []byte("reaction cap ciphertext"),
		Header:         []byte("reaction cap header"),
	}
	if err := database.StoreMessage(ctx, message); err != nil {
		t.Fatal(err)
	}

	countReactions := func() int {
		t.Helper()
		var count int
		if err := database.Pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM reactions WHERE message_id = $1::uuid`,
			message.ID,
		).Scan(&count); err != nil {
			t.Fatal(err)
		}
		return count
	}
	clearReactions := func() {
		t.Helper()
		if _, err := database.Pool.Exec(ctx,
			`DELETE FROM reactions WHERE message_id = $1::uuid`,
			message.ID,
		); err != nil {
			t.Fatal(err)
		}
	}
	type mutationResult struct {
		changed bool
		err     error
	}
	waitForRosterLock := func(t *testing.T, conversationID string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			probe, err := database.Pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var revision int64
			err = probe.QueryRow(ctx,
				`SELECT mutation_revision FROM conversation_roster_revisions
				 WHERE conversation_id=$1::uuid FOR UPDATE NOWAIT`,
				conversationID,
			).Scan(&revision)
			_ = probe.Rollback(ctx)
			if err == nil {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "55P03" {
				return
			}
			t.Fatalf("probe roster lock: %v", err)
		}
		t.Fatal("reaction mutation did not acquire the roster revision lock")
	}

	t.Run("boundary and idempotency", func(t *testing.T) {
		for index := 0; index < db.MaxReactionsPerMessage; index++ {
			if changed, err := database.AddReaction(
				ctx,
				message.ID,
				conversationID,
				bob.ID,
				fmt.Sprintf("boundary-%03d", index),
			); err != nil || !changed {
				t.Fatalf("add boundary reaction %d: %v", index, err)
			}
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("reaction count = %d, want %d", got, db.MaxReactionsPerMessage)
		}

		if changed, err := database.AddReaction(
			ctx, message.ID, conversationID, bob.ID, "boundary-000",
		); err != nil || changed {
			t.Fatalf("exact add at cap must remain idempotent: %v", err)
		}
		if _, err := database.AddReaction(
			ctx, message.ID, conversationID, bob.ID, "boundary-overflow",
		); !errors.Is(err, db.ErrReactionLimitReached) {
			t.Fatalf("257th reaction error = %v, want ErrReactionLimitReached", err)
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("rejected add changed reaction count to %d", got)
		}

		if changed, err := database.RemoveReaction(
			ctx, message.ID, conversationID, bob.ID, "boundary-001",
		); err != nil || !changed {
			t.Fatal(err)
		}
		if changed, err := database.RemoveReaction(
			ctx, message.ID, conversationID, bob.ID, "boundary-001",
		); err != nil || changed {
			t.Fatalf("idempotent remove changed=%v err=%v", changed, err)
		}
		if changed, err := database.AddReaction(
			ctx, message.ID, conversationID, bob.ID, "boundary-after-remove",
		); err != nil || !changed {
			t.Fatalf("add after removal: %v", err)
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("reaction count after replacement = %d", got)
		}
	})

	t.Run("concurrent boundary", func(t *testing.T) {
		clearReactions()
		const available = 8
		for index := 0; index < db.MaxReactionsPerMessage-available; index++ {
			if changed, err := database.AddReaction(
				ctx,
				message.ID,
				conversationID,
				bob.ID,
				fmt.Sprintf("prefill-%03d", index),
			); err != nil || !changed {
				t.Fatalf("prefill reaction %d: %v", index, err)
			}
		}

		const contenders = 32
		start := make(chan struct{})
		results := make(chan mutationResult, contenders)
		var wait sync.WaitGroup
		for index := 0; index < contenders; index++ {
			wait.Add(1)
			go func(index int) {
				defer wait.Done()
				<-start
				changed, err := database.AddReaction(
					ctx,
					message.ID,
					conversationID,
					bob.ID,
					fmt.Sprintf("contender-%03d", index),
				)
				results <- mutationResult{changed: changed, err: err}
			}(index)
		}
		close(start)
		wait.Wait()
		close(results)

		var admitted, limited int
		for result := range results {
			switch {
			case result.err == nil && result.changed:
				admitted++
			case errors.Is(result.err, db.ErrReactionLimitReached):
				limited++
			default:
				t.Fatalf("unexpected concurrent add result: changed=%v err=%v", result.changed, result.err)
			}
		}
		if admitted != available || limited != contenders-available {
			t.Fatalf(
				"concurrent results admitted=%d limited=%d, want %d/%d",
				admitted,
				limited,
				available,
				contenders-available,
			)
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("concurrent reaction count = %d, want %d", got, db.MaxReactionsPerMessage)
		}

		const exactRetries = 16
		retryResults := make(chan mutationResult, exactRetries)
		wait = sync.WaitGroup{}
		for index := 0; index < exactRetries; index++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				changed, err := database.AddReaction(
					ctx, message.ID, conversationID, bob.ID, "prefill-000",
				)
				retryResults <- mutationResult{changed: changed, err: err}
			}()
		}
		wait.Wait()
		close(retryResults)
		for result := range retryResults {
			if result.err != nil || result.changed {
				t.Fatalf("concurrent exact retry at cap: changed=%v err=%v", result.changed, result.err)
			}
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("exact retries changed reaction count to %d", got)
		}
	})

	t.Run("raw and application writers share a deadlock-free lock order", func(t *testing.T) {
		clearReactions()
		rawTx, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer rawTx.Rollback(ctx)
		if _, err := rawTx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text,73))`,
			message.ID,
		); err != nil {
			t.Fatal(err)
		}

		applicationResult := make(chan mutationResult, 1)
		go func() {
			changed, err := database.AddReaction(
				ctx, message.ID, conversationID, bob.ID, "application-lock-order",
			)
			applicationResult <- mutationResult{changed: changed, err: err}
		}()
		waitForRosterLock(t, conversationID)

		if _, err := rawTx.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
			 VALUES ($1::uuid,$2::uuid,$3::uuid,'raw-lock-order')`,
			message.ID, conversationID, bob.ID,
		); err != nil {
			t.Fatalf("raw writer deadlocked behind application message lock: %v", err)
		}
		if err := rawTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-applicationResult
		if result.err != nil || !result.changed {
			t.Fatalf("application writer changed=%v err=%v", result.changed, result.err)
		}
		if got := countReactions(); got != 2 {
			t.Fatalf("mixed writer reaction count=%d, want 2", got)
		}
	})

	t.Run("repeatable-read raw writers fail closed on the physical slot bound", func(t *testing.T) {
		clearReactions()
		for index := 0; index < db.MaxReactionsPerMessage-1; index++ {
			if changed, err := database.AddReaction(
				ctx, message.ID, conversationID, bob.ID,
				fmt.Sprintf("rr-prefill-%03d", index),
			); err != nil || !changed {
				t.Fatalf("RR prefill %d changed=%v err=%v", index, changed, err)
			}
		}

		first, err := database.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer first.Rollback(ctx)
		second, err := database.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		if err != nil {
			t.Fatal(err)
		}
		defer second.Rollback(ctx)
		for name, tx := range map[string]pgx.Tx{"first": first, "second": second} {
			var snapshotCount int
			if err := tx.QueryRow(ctx,
				`SELECT COUNT(*) FROM reactions WHERE message_id=$1::uuid`, message.ID,
			).Scan(&snapshotCount); err != nil || snapshotCount != db.MaxReactionsPerMessage-1 {
				t.Fatalf("%s RR snapshot count=%d err=%v", name, snapshotCount, err)
			}
		}

		if _, err := first.Exec(ctx,
			`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
			 VALUES ($1::uuid,$2::uuid,$3::uuid,'rr-first')`,
			message.ID, conversationID, bob.ID,
		); err != nil {
			t.Fatal(err)
		}
		secondResult := make(chan error, 1)
		go func() {
			_, err := second.Exec(ctx,
				`INSERT INTO reactions(message_id,conversation_id,user_id,emoji)
				 VALUES ($1::uuid,$2::uuid,$3::uuid,'rr-second')`,
				message.ID, conversationID, bob.ID,
			)
			secondResult <- err
		}()
		select {
		case err := <-secondResult:
			t.Fatalf("second RR writer did not wait for admission lock: %v", err)
		case <-time.After(50 * time.Millisecond):
		}
		if err := first.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		err = <-secondResult
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) ||
			!((pgErr.Code == "23505" && pgErr.ConstraintName == "reactions_message_history_slot_unique") ||
				pgErr.Code == "40001") {
			t.Fatalf("stale RR overflow error=%v, want slot conflict or serialization failure", err)
		}
		if err := second.Rollback(ctx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			t.Fatal(err)
		}
		if got := countReactions(); got != db.MaxReactionsPerMessage {
			t.Fatalf("stale RR writers produced %d reactions, want %d", got, db.MaxReactionsPerMessage)
		}
	})

	t.Run("authorization and active message scope are transactional", func(t *testing.T) {
		clearReactions()
		mallory := createUser(0x33, "reaction-cap-mallory")
		if changed, err := database.AddReaction(
			ctx, message.ID, conversationID, mallory.ID, "unauthorized",
		); !errors.Is(err, db.ErrConversationAccessDenied) || changed {
			t.Fatalf("unauthorized mutation changed=%v err=%v", changed, err)
		}

		otherConversationID, _, err := database.FindOrCreateDM(ctx, alice.ID, mallory.ID)
		if err != nil {
			t.Fatal(err)
		}
		otherMessage := &db.Message{
			ConversationID: otherConversationID,
			SenderID:       alice.ID,
			Ciphertext:     []byte("other reaction scope ciphertext"),
			Header:         []byte("other reaction scope header"),
		}
		if err := database.StoreMessage(ctx, otherMessage); err != nil {
			t.Fatal(err)
		}
		if changed, err := database.AddReaction(
			ctx, otherMessage.ID, conversationID, bob.ID, "wrong-scope",
		); !errors.Is(err, db.ErrMessageMutationScope) || changed {
			t.Fatalf("cross-scope mutation changed=%v err=%v", changed, err)
		}

		deletedMessage := &db.Message{
			ConversationID: conversationID,
			SenderID:       alice.ID,
			Ciphertext:     []byte("pending delete ciphertext"),
			Header:         []byte("pending delete header"),
		}
		if err := database.StoreMessage(ctx, deletedMessage); err != nil {
			t.Fatal(err)
		}
		deleteTx, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer deleteTx.Rollback(ctx)
		if _, err := deleteTx.Exec(ctx,
			`UPDATE messages SET is_deleted=true WHERE id=$1::uuid`, deletedMessage.ID,
		); err != nil {
			t.Fatal(err)
		}
		deleteResult := make(chan mutationResult, 1)
		go func() {
			changed, err := database.AddReaction(
				ctx, deletedMessage.ID, conversationID, bob.ID, "delete-race",
			)
			deleteResult <- mutationResult{changed: changed, err: err}
		}()
		waitForRosterLock(t, conversationID)
		select {
		case result := <-deleteResult:
			t.Fatalf("mutation bypassed pending message lock: %+v", result)
		case <-time.After(50 * time.Millisecond):
		}
		if err := deleteTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result := <-deleteResult
		if !errors.Is(result.err, db.ErrMessageMutationScope) || result.changed {
			t.Fatalf("post-delete mutation changed=%v err=%v", result.changed, result.err)
		}

		revokeTx, err := database.Pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer revokeTx.Rollback(ctx)
		if _, err := revokeTx.Exec(ctx,
			`DELETE FROM conversation_members
			 WHERE conversation_id=$1::uuid AND user_id=$2::uuid`,
			conversationID, bob.ID,
		); err != nil {
			t.Fatal(err)
		}
		revokeResult := make(chan mutationResult, 1)
		go func() {
			changed, err := database.AddReaction(
				ctx, message.ID, conversationID, bob.ID, "revoke-race",
			)
			revokeResult <- mutationResult{changed: changed, err: err}
		}()
		select {
		case result := <-revokeResult:
			t.Fatalf("mutation bypassed pending roster lock: %+v", result)
		case <-time.After(50 * time.Millisecond):
		}
		if err := revokeTx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		result = <-revokeResult
		if !errors.Is(result.err, db.ErrConversationAccessDenied) || result.changed {
			t.Fatalf("post-revoke mutation changed=%v err=%v", result.changed, result.err)
		}
	})
}
