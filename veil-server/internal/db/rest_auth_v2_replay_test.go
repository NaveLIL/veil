package db

import (
	"context"
	"errors"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
)

var _ authmw.RESTAuthV2ReplayStore = (*DB)(nil)

func TestRESTAuthV2ReplayStoreRejectsInvalidClaimBeforeDatabaseUse(t *testing.T) {
	database := &DB{}
	validNonce := [32]byte{1}
	for name, testCase := range map[string]struct {
		ctx    context.Context
		userID string
		nonce  [32]byte
	}{
		"nil context": {
			userID: "00112233-4455-4677-8899-aabbccddeeff",
			nonce:  validNonce,
		},
		"nil pool": {
			ctx:    context.Background(),
			userID: "00112233-4455-4677-8899-aabbccddeeff",
			nonce:  validNonce,
		},
		"noncanonical user": {
			ctx:    context.Background(),
			userID: "00112233-4455-4677-8899-AABBCCDDEEFF",
			nonce:  validNonce,
		},
		"nil user": {
			ctx:    context.Background(),
			userID: "00000000-0000-0000-0000-000000000000",
			nonce:  validNonce,
		},
		"zero nonce": {
			ctx:    context.Background(),
			userID: "00112233-4455-4677-8899-aabbccddeeff",
		},
	} {
		t.Run(name, func(t *testing.T) {
			claimed, err := database.ClaimRESTAuthV2Nonce(testCase.ctx, testCase.userID, testCase.nonce)
			if claimed || !errors.Is(err, ErrRESTAuthV2ReplayInput) {
				t.Fatalf("claimed=%v error=%v", claimed, err)
			}
		})
	}
}

func TestRESTAuthV2ReplayCleanupRejectsInvalidBatchBeforeDatabaseUse(t *testing.T) {
	database := &DB{}
	for _, batch := range []int{-1, 0, MaxRESTAuthV2ReplayCleanupBatch + 1} {
		deleted, err := database.DeleteExpiredRESTAuthV2ReplayNonces(context.Background(), batch)
		if deleted != 0 || !errors.Is(err, ErrRESTAuthV2ReplayBatch) {
			t.Fatalf("batch=%d deleted=%d error=%v", batch, deleted, err)
		}
	}
	//lint:ignore SA1012 This boundary test deliberately verifies fail-closed nil handling.
	if deleted, err := database.DeleteExpiredRESTAuthV2ReplayNonces(nil, 1); deleted != 0 || !errors.Is(err, ErrRESTAuthV2ReplayBatch) {
		t.Fatalf("nil context deleted=%d error=%v", deleted, err)
	}
}

func TestRESTAuthV2ReplayRetentionCoversFullAcceptanceWindow(t *testing.T) {
	if RESTAuthV2ReplayRetention <= 2*authmw.SignatureMaxSkew {
		t.Fatalf("replay retention=%v must exceed complete timestamp window=%v", RESTAuthV2ReplayRetention, 2*authmw.SignatureMaxSkew)
	}
}
