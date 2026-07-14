//go:build integration

package integration

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/profiles"
)

func TestSignedProfileAndAvatarLifecycle(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("profile-api-owner")
	peer := h.CreateUser("profile-api-peer")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	status, _, initial := h.Do(peer, http.MethodGet, "/v1/users/"+owner.ID+"/profile", nil)
	if status != http.StatusOK || initial["user_id"] != owner.ID || initial["profile_version"] != float64(0) {
		t.Fatalf("initial profile status=%d body=%v", status, initial)
	}
	status, _, updated := h.Do(owner, http.MethodPut, "/v1/users/me/profile", map[string]any{
		"expected_version": 0,
		"display_name":     "Alice",
		"about":            "Server-visible profile",
	})
	if status != http.StatusOK || updated["profile_version"] != float64(1) {
		t.Fatalf("profile update status=%d body=%v", status, updated)
	}
	status, _, conflict := h.Do(owner, http.MethodPut, "/v1/users/me/profile", map[string]any{
		"expected_version": 0,
		"display_name":     "rollback",
		"about":            "rollback",
	})
	if status != http.StatusConflict || conflict["code"] != "profile_version_conflict" {
		t.Fatalf("stale update status=%d body=%v", status, conflict)
	}

	pngBody := integrationPNG(t, 37, 19)
	status, _, avatarProfile := h.DoRaw(owner, http.MethodPut,
		"/v1/users/me/profile/avatar?expected_version=1", pngBody, "image/png")
	firstAsset, _ := avatarProfile["avatar_asset_id"].(string)
	if status != http.StatusOK || firstAsset == "" || avatarProfile["avatar_content_type"] != "image/jpeg" || avatarProfile["profile_version"] != float64(2) {
		t.Fatalf("first avatar status=%d body=%v", status, avatarProfile)
	}
	status, avatarBytes, _ := h.Do(peer, http.MethodGet, "/v1/profile-avatars/"+firstAsset, nil)
	if status != http.StatusOK || len(avatarBytes) == 0 || !bytes.HasPrefix(avatarBytes, []byte{0xff, 0xd8}) {
		t.Fatalf("avatar fetch status=%d bytes=%d", status, len(avatarBytes))
	}

	status, _, replacement := h.DoRaw(owner, http.MethodPut,
		"/v1/users/me/profile/avatar?expected_version=2", integrationPNG(t, 19, 37), "image/png")
	secondAsset, _ := replacement["avatar_asset_id"].(string)
	if status != http.StatusOK || secondAsset == "" || secondAsset == firstAsset || replacement["profile_version"] != float64(3) {
		t.Fatalf("replacement status=%d body=%v", status, replacement)
	}
	if status, _, _ = h.Do(peer, http.MethodGet, "/v1/profile-avatars/"+firstAsset, nil); status != http.StatusNotFound {
		t.Fatalf("orphaned avatar remained fetchable: status=%d", status)
	}

	if _, err := h.DB.Pool.Exec(ctx, `UPDATE users SET avatar_asset_id=$1::uuid WHERE id=$2::uuid`, secondAsset, peer.ID); err == nil {
		t.Fatal("database accepted another account's avatar asset")
	}

	status, _, removed := h.Do(owner, http.MethodDelete,
		"/v1/users/me/profile/avatar?expected_version=3", nil)
	if status != http.StatusOK || removed["avatar_asset_id"] != nil || removed["profile_version"] != float64(4) {
		t.Fatalf("avatar removal status=%d body=%v", status, removed)
	}
	if status, _, _ = h.Do(peer, http.MethodGet, "/v1/profile-avatars/"+secondAsset, nil); status != http.StatusNotFound {
		t.Fatalf("removed avatar remained fetchable: status=%d", status)
	}

	if _, err := h.DB.Pool.Exec(ctx, `UPDATE profile_avatar_assets SET orphaned_at=now()-interval '25 hours' WHERE id=$1::uuid`, firstAsset); err != nil {
		t.Fatalf("age orphan: %v", err)
	}
	deleted, err := profiles.NewPostgresStore(h.DB.Pool).DeleteExpiredAvatarAssets(ctx, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("bounded orphan sweep deleted=%d err=%v", deleted, err)
	}
	var remaining int
	if err := h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM profile_avatar_assets WHERE id=$1::uuid`, firstAsset).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired orphan count=%d err=%v", remaining, err)
	}

	version := 4
	for upload := 2; upload < maxProfileAvatarUploadsForTest; upload++ {
		status, _, body := h.DoRaw(owner, http.MethodPut,
			"/v1/users/me/profile/avatar?expected_version="+itoa(version), pngBody, "image/png")
		if status != http.StatusOK {
			t.Fatalf("quota warmup upload=%d status=%d body=%v", upload+1, status, body)
		}
		version++
	}
	status, _, quota := h.DoRaw(owner, http.MethodPut,
		"/v1/users/me/profile/avatar?expected_version="+itoa(version), pngBody, "image/png")
	if status != http.StatusTooManyRequests || quota["code"] != "avatar_upload_quota" {
		t.Fatalf("quota overflow status=%d body=%v", status, quota)
	}
}

func TestAvatarOrphanStorageBudgetIsGlobalAndFailSafe(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("profile-avatar-budget-owner")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	var currentAsset string
	if err := h.DB.Pool.QueryRow(ctx, `INSERT INTO profile_avatar_assets
		(owner_id, id, content_type, sha256, width, height, data)
		VALUES ($1::uuid, gen_random_uuid(), 'image/jpeg', digest('current', 'sha256'), 512, 512, decode('ffd8ffd9','hex'))
		RETURNING id::text`, owner.ID).Scan(&currentAsset); err != nil {
		t.Fatalf("insert current budget asset: %v", err)
	}
	if _, err := h.DB.Pool.Exec(ctx, `UPDATE users SET avatar_asset_id=$1::uuid WHERE id=$2::uuid`, currentAsset, owner.ID); err != nil {
		t.Fatalf("bind current budget asset: %v", err)
	}
	if _, err := h.DB.Pool.Exec(ctx, `INSERT INTO profile_avatar_assets
		(owner_id, id, content_type, sha256, width, height, data, orphaned_at)
		SELECT $1::uuid, gen_random_uuid(), 'image/jpeg', digest(g::text, 'sha256'),
			512, 512, decode('ffd8ffd9','hex'), now()-interval '1 hour'
		FROM generate_series(1, 4096) AS g`, owner.ID); err != nil {
		t.Fatalf("seed bounded avatar orphans: %v", err)
	}
	asset := &profiles.AvatarAsset{
		ContentType: "image/jpeg",
		SHA256:      bytes.Repeat([]byte{0xa5}, 32),
		Width:       512,
		Height:      512,
		Data:        []byte{0xff, 0xd8, 0xff, 0xd9},
	}
	profile, err := profiles.NewPostgresStore(h.DB.Pool).UpdateAvatar(ctx, owner.ID, 0, asset)
	if err != nil || profile.AvatarAssetID == nil {
		t.Fatalf("budgeted avatar replacement profile=%v err=%v", profile, err)
	}
	var orphans int
	if err := h.DB.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM profile_avatar_assets WHERE orphaned_at IS NOT NULL`).Scan(&orphans); err != nil {
		t.Fatalf("count budgeted avatar orphans: %v", err)
	}
	if orphans > 4096 {
		t.Fatalf("global avatar orphan budget escaped: %d", orphans)
	}
}

const maxProfileAvatarUploadsForTest = 12

func integrationPNG(t *testing.T, width, height int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.SetNRGBA(x, y, color.NRGBA{R: uint8(x * 3), G: uint8(y * 5), B: 180, A: 190})
		}
	}
	var output bytes.Buffer
	if err := png.Encode(&output, img); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func itoa(value int) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	position := len(buffer)
	for value > 0 {
		position--
		buffer[position] = digits[value%10]
		value /= 10
	}
	return string(buffer[position:])
}
