//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/db"
)

func TestRESTAuthV2ReplayStoreLifecycleAndCrossProcessClaim(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	publicA, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicB, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	userA, err := database.CreateUser(ctx, bytes.Repeat([]byte{0xa1}, 32), publicA, "rest-replay-a")
	if err != nil {
		t.Fatal(err)
	}
	userB, err := database.CreateUser(ctx, bytes.Repeat([]byte{0xb1}, 32), publicB, "rest-replay-b")
	if err != nil {
		t.Fatal(err)
	}

	second, err := db.Connect(ctx, database.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	secondOpen := true
	t.Cleanup(func() {
		if secondOpen {
			second.Close()
		}
	})

	nonce := [32]byte{1, 2, 3}
	start := make(chan struct{})
	results := make(chan struct {
		claimed bool
		err     error
	}, 2)
	var workers sync.WaitGroup
	for _, store := range []*db.DB{database, second} {
		workers.Add(1)
		go func(candidate *db.DB) {
			defer workers.Done()
			<-start
			claimed, claimErr := candidate.ClaimRESTAuthV2Nonce(ctx, userA.ID, nonce)
			results <- struct {
				claimed bool
				err     error
			}{claimed: claimed, err: claimErr}
		}(store)
	}
	close(start)
	workers.Wait()
	close(results)
	var accepted, replayed int
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.claimed {
			accepted++
		} else {
			replayed++
		}
	}
	if accepted != 1 || replayed != 1 {
		t.Fatalf("concurrent claims accepted=%d replayed=%d", accepted, replayed)
	}

	// An equal nonce belongs to a distinct account scope.
	if claimed, err := second.ClaimRESTAuthV2Nonce(ctx, userB.ID, nonce); err != nil || !claimed {
		t.Fatalf("other-account claim=%v err=%v", claimed, err)
	}

	// A marker written by one pool remains after that pool closes and is seen by
	// a newly connected process-equivalent store.
	persistentNonce := [32]byte{4, 5, 6}
	if claimed, err := second.ClaimRESTAuthV2Nonce(ctx, userA.ID, persistentNonce); err != nil || !claimed {
		t.Fatalf("persistent claim=%v err=%v", claimed, err)
	}
	second.Close()
	secondOpen = false
	reopened, err := db.Connect(ctx, database.Pool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if claimed, err := reopened.ClaimRESTAuthV2Nonce(ctx, userA.ID, persistentNonce); err != nil || claimed {
		t.Fatalf("post-reopen duplicate claim=%v err=%v", claimed, err)
	}

	// Expired rows are fail-safe until bounded cleanup removes them. Cleanup
	// cannot select a live marker.
	if _, err := database.Pool.Exec(ctx,
		`UPDATE rest_auth_v2_replay_nonces
		 SET created_at = clock_timestamp() - interval '6 minutes',
		     expires_at = clock_timestamp() - interval '1 minute'
		 WHERE user_id = $1::uuid AND nonce = $2`,
		userA.ID, nonce[:],
	); err != nil {
		t.Fatal(err)
	}
	if claimed, err := reopened.ClaimRESTAuthV2Nonce(ctx, userA.ID, nonce); err != nil || claimed {
		t.Fatalf("unpurged expired marker claim=%v err=%v", claimed, err)
	}
	deleted, err := reopened.DeleteExpiredRESTAuthV2ReplayNonces(ctx, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("expired cleanup deleted=%d err=%v", deleted, err)
	}
	if claimed, err := reopened.ClaimRESTAuthV2Nonce(ctx, userA.ID, nonce); err != nil || !claimed {
		t.Fatalf("post-cleanup claim=%v err=%v", claimed, err)
	}
	if deleted, err := reopened.DeleteExpiredRESTAuthV2ReplayNonces(ctx, 100); err != nil || deleted != 0 {
		t.Fatalf("live cleanup deleted=%d err=%v", deleted, err)
	}

	// Database constraints protect raw writers too.
	for name, input := range map[string]struct {
		nonce  []byte
		expiry string
	}{
		"short nonce": {nonce: bytes.Repeat([]byte{7}, 31), expiry: "5 minutes"},
		"zero nonce":  {nonce: make([]byte, 32), expiry: "5 minutes"},
		"long expiry": {nonce: bytes.Repeat([]byte{8}, 32), expiry: "11 minutes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := database.Pool.Exec(ctx,
				`INSERT INTO rest_auth_v2_replay_nonces (user_id, nonce, expires_at)
				 VALUES ($1::uuid, $2, clock_timestamp() + $3::interval)`,
				userA.ID, input.nonce, input.expiry,
			); err == nil {
				t.Fatal("invalid raw replay marker was accepted")
			}
		})
	}

	if _, err := database.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1::uuid`, userB.ID); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM rest_auth_v2_replay_nonces WHERE user_id = $1::uuid`, userB.ID,
	).Scan(&retained); err != nil || retained != 0 {
		t.Fatalf("deleted account retained replay markers=%d err=%v", retained, err)
	}
}
