//go:build integration

package db_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
)

func TestPreKeyExactBodyReceiptSurvivesCompaction(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	identityKey := bytes.Repeat([]byte{0x11}, 32)
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	user, err := database.CreateUser(ctx, identityKey, signingPublic, "prekey-receipt")
	if err != nil {
		t.Fatal(err)
	}
	device, err := database.CreateDevice(ctx, user.ID, bytes.Repeat([]byte{0x22}, 16), "prekey-receipt")
	if err != nil {
		t.Fatal(err)
	}
	service := auth.NewService(database, &config.Config{PreKeyLowWarning: 10})
	handler := auth.NewHandler(service, nil, nil)

	signedOne := signedPreKey(t, signingPrivate, 1, 0x31)
	oneTimeTen := db.PreKey{KeyType: 1, ProtocolKeyID: 10, PublicKey: bytes.Repeat([]byte{0x51}, 32)}
	originalBody := uploadBody(t, device.DeviceKey, signedOne, []db.PreKey{oneTimeTen}, false)
	status, response := uploadPreKeys(t, handler, user.ID, originalBody)
	if status != http.StatusOK || int(response["stored"].(float64)) != 2 {
		t.Fatalf("initial upload status=%d body=%v", status, response)
	}

	claimed, err := database.ClaimOneTimePreKey(ctx, device.ID)
	if err != nil || claimed == nil || claimed.ProtocolKeyID != oneTimeTen.ProtocolKeyID || !claimed.Used {
		t.Fatalf("claim=%#v err=%v", claimed, err)
	}
	var claimedRows int
	if err := database.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM prekeys
		 WHERE device_id=$1::uuid AND key_type=1 AND protocol_key_id=$2`,
		device.ID, oneTimeTen.ProtocolKeyID,
	).Scan(&claimedRows); err != nil {
		t.Fatal(err)
	}
	if claimedRows != 0 {
		t.Fatal("receipt-mode claim retained a consumed OPK row")
	}

	// The exact bytes remain replayable even after their OPK row disappeared.
	status, response = uploadPreKeys(t, handler, user.ID, originalBody)
	if status != http.StatusOK || int(response["stored"].(float64)) != 2 {
		t.Fatalf("lost-ACK exact replay status=%d body=%v", status, response)
	}
	remaining, err := database.CountUnusedOPKs(ctx, device.ID)
	if err != nil || remaining != 0 {
		t.Fatalf("exact replay resurrected inventory: remaining=%d err=%v", remaining, err)
	}

	// Semantically identical JSON with different bytes is not the exact outbox
	// retry. With no new protocol id it must conflict and must not replace the
	// previous receipt.
	alternateBody := uploadBody(t, device.DeviceKey, signedOne, []db.PreKey{oneTimeTen}, true)
	if bytes.Equal(alternateBody, originalBody) {
		t.Fatal("pretty JSON fixture unexpectedly equals canonical JSON bytes")
	}
	status, _ = uploadPreKeys(t, handler, user.ID, alternateBody)
	if status != http.StatusConflict {
		t.Fatalf("alternate-body replay status=%d, want 409", status)
	}
	status, response = uploadPreKeys(t, handler, user.ID, originalBody)
	if status != http.StatusOK || int(response["stored"].(float64)) != 2 {
		t.Fatalf("conflict replaced exact receipt: status=%d body=%v", status, response)
	}

	conflictingOPK := oneTimeTen
	conflictingOPK.PublicKey = bytes.Repeat([]byte{0x52}, 32)
	status, _ = uploadPreKeys(t, handler, user.ID,
		uploadBody(t, device.DeviceKey, signedOne, []db.PreKey{conflictingOPK}, false))
	if status != http.StatusConflict {
		t.Fatalf("retired OPK material conflict status=%d, want 409", status)
	}

	// Future replenishment may retain the exact current SPK while advancing
	// only the OPK watermark.
	oneTimeEleven := db.PreKey{KeyType: 1, ProtocolKeyID: 11, PublicKey: bytes.Repeat([]byte{0x61}, 32)}
	status, response = uploadPreKeys(t, handler, user.ID,
		uploadBody(t, device.DeviceKey, signedOne, []db.PreKey{oneTimeEleven}, false))
	if status != http.StatusOK || int(response["stored"].(float64)) != 2 {
		t.Fatalf("current-SPK replenishment status=%d body=%v", status, response)
	}

	conflictingSigned := signedOne
	conflictingSigned.PublicKey = bytes.Repeat([]byte{0x32}, 32)
	conflictingSigned.Signature = bytes.Repeat([]byte{0x41}, ed25519.SignatureSize)
	if err := database.StorePreKeys(ctx, device.ID, []db.PreKey{
		conflictingSigned,
		{KeyType: 1, ProtocolKeyID: 12, PublicKey: bytes.Repeat([]byte{0x62}, 32)},
	}); !errors.Is(err, db.ErrPreKeyMaterialConflict) {
		t.Fatalf("different current SPK material error=%v", err)
	}

	signedTwo := signedPreKey(t, signingPrivate, 2, 0x33)
	emptyRotationBody := uploadBody(t, device.DeviceKey, signedTwo, nil, false)
	status, response = uploadPreKeys(t, handler, user.ID, emptyRotationBody)
	if status != http.StatusOK || int(response["stored"].(float64)) != 1 {
		t.Fatalf("SPK rotation status=%d body=%v", status, response)
	}
	status, _ = uploadPreKeys(t, handler, user.ID,
		uploadBody(t, device.DeviceKey, signedTwo, nil, true))
	if status != http.StatusConflict {
		t.Fatalf("no-new-id alternate body status=%d, want 409", status)
	}
	status, response = uploadPreKeys(t, handler, user.ID, emptyRotationBody)
	if status != http.StatusOK || int(response["stored"].(float64)) != 1 {
		t.Fatalf("no-new-id conflict replaced exact receipt: status=%d body=%v", status, response)
	}
	status, _ = uploadPreKeys(t, handler, user.ID,
		uploadBody(t, device.DeviceKey, signedOne, []db.PreKey{
			{KeyType: 1, ProtocolKeyID: 12, PublicKey: bytes.Repeat([]byte{0x62}, 32)},
		}, false))
	if status != http.StatusConflict {
		t.Fatalf("stale non-current SPK status=%d, want 409", status)
	}

	var signedRows, consumedRows int
	if err := database.Pool.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE key_type=0),
		   COUNT(*) FILTER (WHERE key_type=1 AND used=true)
		 FROM prekeys WHERE device_id=$1::uuid`,
		device.ID,
	).Scan(&signedRows, &consumedRows); err != nil {
		t.Fatal(err)
	}
	if signedRows != 1 || consumedRows != 0 {
		t.Fatalf("bounded device rows signed=%d consumed=%d", signedRows, consumedRows)
	}
}

func TestPreKeySequentialRotationsRemainBounded(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	user, device := createPreKeyTestDevice(t, ctx, database, 0x41, "prekey-rotations")
	_ = user

	var current db.PreKey
	for rotation := uint32(1); rotation <= 1100; rotation++ {
		current = db.PreKey{
			KeyType:       0,
			ProtocolKeyID: rotation,
			PublicKey:     bytes.Repeat([]byte{byte(rotation%251 + 1)}, 32),
			Signature:     bytes.Repeat([]byte{byte(rotation%239 + 1)}, ed25519.SignatureSize),
		}
		if err := database.StorePreKeys(ctx, device.ID, []db.PreKey{current}); err != nil {
			t.Fatalf("empty-OPK rotation %d: %v", rotation, err)
		}
	}

	nextOPKID := uint32(1)
	for replenishment := 0; replenishment < 150; replenishment++ {
		batch := []db.PreKey{current}
		for index := 0; index < 20; index++ {
			batch = append(batch, db.PreKey{
				KeyType:       1,
				ProtocolKeyID: nextOPKID,
				PublicKey:     bytes.Repeat([]byte{byte(nextOPKID%251 + 1)}, 32),
			})
			nextOPKID++
		}
		if err := database.StorePreKeys(ctx, device.ID, batch); err != nil {
			t.Fatalf("OPK replenishment %d: %v", replenishment, err)
		}
		for claim := 0; claim < 5; claim++ {
			if claimed, err := database.ClaimOneTimePreKey(ctx, device.ID); err != nil || claimed == nil {
				t.Fatalf("replenishment %d claim %d: claimed=%#v err=%v", replenishment, claim, claimed, err)
			}
		}
	}

	var signedRows, unusedRows, consumedRows, signedHigh, oneTimeHigh int
	if err := database.Pool.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE p.key_type=0),
		   COUNT(*) FILTER (WHERE p.key_type=1 AND p.used=false),
		   COUNT(*) FILTER (WHERE p.key_type=1 AND p.used=true),
		   s.signed_prekey_high_watermark,
		   s.one_time_prekey_high_watermark
		 FROM prekeys p
		 JOIN prekey_publication_state s ON s.device_id=p.device_id
		 WHERE p.device_id=$1::uuid
		 GROUP BY s.signed_prekey_high_watermark, s.one_time_prekey_high_watermark`,
		device.ID,
	).Scan(&signedRows, &unusedRows, &consumedRows, &signedHigh, &oneTimeHigh); err != nil {
		t.Fatal(err)
	}
	if signedRows != 1 || unusedRows > db.MaxUnusedOneTimePreKeysPerDevice || consumedRows != 0 ||
		signedHigh != 1100 || oneTimeHigh != int(nextOPKID-1) {
		t.Fatalf("bounded rotation state signed=%d unused=%d consumed=%d high=%d/%d",
			signedRows, unusedRows, consumedRows, signedHigh, oneTimeHigh)
	}
}

func TestPreKeyAccountStateBoundIsConcurrent(t *testing.T) {
	database := newInviteIntegrationDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	user, err := database.CreateUser(
		ctx,
		bytes.Repeat([]byte{0x71}, 32),
		mustSigningPublic(t),
		"prekey-account-bound",
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := database.Pool.Exec(ctx,
		`WITH inserted AS (
		   INSERT INTO devices (user_id, device_key, device_name)
		   SELECT $1::uuid,
		          decode(lpad(to_hex(100000 + n), 32, '0'), 'hex'),
		          'prekey-cap-' || n::text
		   FROM generate_series(1, $2::int) n
		   RETURNING id
		 )
		 INSERT INTO prekey_publication_state (device_id)
		 SELECT id FROM inserted`,
		user.ID, db.MaxPreKeyDevicesPerAccount-1,
	); err != nil {
		t.Fatal(err)
	}

	targets := make([]*db.Device, 2)
	for index := range targets {
		targets[index], err = database.CreateDevice(
			ctx,
			user.ID,
			bytes.Repeat([]byte{byte(0xe1 + index)}, 16),
			fmt.Sprintf("prekey-cap-target-%d", index),
		)
		if err != nil {
			t.Fatal(err)
		}
	}
	batches := [][]db.PreKey{
		{{KeyType: 0, ProtocolKeyID: 1, PublicKey: bytes.Repeat([]byte{0xc1}, 32), Signature: bytes.Repeat([]byte{0xd1}, 64)}},
		{{KeyType: 0, ProtocolKeyID: 1, PublicKey: bytes.Repeat([]byte{0xc2}, 32), Signature: bytes.Repeat([]byte{0xd2}, 64)}},
	}
	type result struct {
		index int
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	var publishers sync.WaitGroup
	for index := range targets {
		publishers.Add(1)
		go func(index int) {
			defer publishers.Done()
			<-start
			results <- result{index: index, err: database.StorePreKeys(ctx, targets[index].ID, batches[index])}
		}(index)
	}
	close(start)
	publishers.Wait()
	close(results)

	winner := -1
	capacityFailures := 0
	for outcome := range results {
		switch {
		case outcome.err == nil:
			winner = outcome.index
		case errors.Is(outcome.err, db.ErrPreKeyLiveStateFull):
			capacityFailures++
		default:
			t.Fatalf("unexpected concurrent publication error: %v", outcome.err)
		}
	}
	if winner < 0 || capacityFailures != 1 {
		t.Fatalf("winner=%d capacity failures=%d, want one of each", winner, capacityFailures)
	}
	if err := database.StorePreKeys(ctx, targets[winner].ID, batches[winner]); err != nil {
		t.Fatalf("exact replay at account state bound: %v", err)
	}
	var states int
	if err := database.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM prekey_publication_state s
		 JOIN devices d ON d.id=s.device_id WHERE d.user_id=$1::uuid`,
		user.ID,
	).Scan(&states); err != nil {
		t.Fatal(err)
	}
	if states != db.MaxPreKeyDevicesPerAccount {
		t.Fatalf("account state rows=%d, want %d", states, db.MaxPreKeyDevicesPerAccount)
	}
}

func signedPreKey(t *testing.T, private ed25519.PrivateKey, id uint32, marker byte) db.PreKey {
	t.Helper()
	publicKey := bytes.Repeat([]byte{marker}, 32)
	message, err := auth.SignedPreKeySigningMessage(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	return db.PreKey{
		KeyType:       0,
		ProtocolKeyID: id,
		PublicKey:     publicKey,
		Signature:     ed25519.Sign(private, message),
	}
}

func uploadBody(t *testing.T, deviceKey []byte, signed db.PreKey, oneTime []db.PreKey, pretty bool) []byte {
	t.Helper()
	opks := make([]map[string]any, 0, len(oneTime))
	for _, key := range oneTime {
		opks = append(opks, map[string]any{
			"key_id":     key.ProtocolKeyID,
			"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
			"signature":  "",
		})
	}
	payload := map[string]any{
		"device_id": hex.EncodeToString(deviceKey),
		"signed_prekey": map[string]any{
			"key_id":     signed.ProtocolKeyID,
			"public_key": base64.StdEncoding.EncodeToString(signed.PublicKey),
			"signature":  base64.StdEncoding.EncodeToString(signed.Signature),
		},
		"one_time_prekeys": opks,
	}
	var body []byte
	var err error
	if pretty {
		body, err = json.MarshalIndent(payload, "", "  ")
	} else {
		body, err = json.Marshal(payload)
	}
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func uploadPreKeys(t *testing.T, handler *auth.Handler, userID string, body []byte) (int, map[string]any) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/prekeys", bytes.NewReader(body))
	request.Header.Set("X-User-ID", userID)
	response := httptest.NewRecorder()
	handler.UploadPreKeys(response, request)
	decoded := make(map[string]any)
	if response.Body.Len() > 0 {
		if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
			t.Fatalf("decode upload response status=%d body=%q: %v", response.Code, response.Body.String(), err)
		}
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("upload Cache-Control=%q, want no-store", got)
	}
	return response.Code, decoded
}

func createPreKeyTestDevice(t *testing.T, ctx context.Context, database *db.DB, marker byte, name string) (*db.User, *db.Device) {
	t.Helper()
	user, err := database.CreateUser(
		ctx,
		bytes.Repeat([]byte{marker}, 32),
		mustSigningPublic(t),
		name,
	)
	if err != nil {
		t.Fatal(err)
	}
	device, err := database.CreateDevice(ctx, user.ID, bytes.Repeat([]byte{marker + 1}, 16), name)
	if err != nil {
		t.Fatal(err)
	}
	return user, device
}

func mustSigningPublic(t *testing.T) ed25519.PublicKey {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey
}
