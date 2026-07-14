//go:build integration

package integration

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
)

func createVeilLink(t *testing.T, h *Harness, owner *User, spaceID string, maxUses int32) map[string]any {
	t.Helper()
	status, _, body := h.Do(owner, http.MethodPost, "/v1/servers/"+spaceID+"/veil-links", map[string]any{
		"max_uses": maxUses, "expires_in_secs": 24 * 60 * 60,
	})
	if status != http.StatusCreated {
		t.Fatalf("create Veil Link: status=%d body=%v", status, body)
	}
	for _, field := range []string{"id", "public_selector", "secret", "share_url"} {
		if body[field] == "" || body[field] == nil {
			t.Fatalf("create Veil Link missing %s: %v", field, body)
		}
	}
	return body
}

func joinVeilLink(t *testing.T, h *Harness, user *User, link map[string]any) (int, map[string]any) {
	t.Helper()
	selector := link["public_selector"].(string)
	secret := link["secret"].(string)
	status, _, body := h.Do(user, http.MethodPost, "/v1/veil-links/"+selector+"/join", map[string]string{"secret": secret})
	return status, body
}

func TestVeilLinks_CreateListPreviewAndJoin(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("veil-link-owner")
	joiner := h.CreateUser("veil-link-joiner")
	spaceID := mkServer(t, h, owner, "Joinable Space")
	link := createVeilLink(t, h, owner, spaceID, 2)

	selector := link["public_selector"].(string)
	secret := link["secret"].(string)
	if len(selector) != 43 || len(secret) != 43 || selector == secret {
		t.Fatalf("selector/secret entropy contract violated")
	}
	shareURL := link["share_url"].(string)
	if !strings.Contains(shareURL, "/join/v1/"+selector+"#s="+secret) {
		t.Fatalf("unexpected share URL %q", shareURL)
	}

	status, _, listed := h.Do(owner, http.MethodGet, "/v1/servers/"+spaceID+"/veil-links", nil)
	if status != http.StatusOK {
		t.Fatalf("list links status=%d body=%v", status, listed)
	}
	encoded, _ := json.Marshal(listed)
	if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "secret_hash") {
		t.Fatalf("list re-exposed secret material: %s", encoded)
	}

	resp, err := http.Get(h.Server.URL + "/v1/veil-links/" + selector)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" ||
		resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("public preview status/headers=%d %v", resp.StatusCode, resp.Header)
	}
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), spaceID) || strings.Contains(string(raw), owner.ID) || strings.Contains(string(raw), secret) {
		t.Fatalf("public preview disclosed private identifiers: %s", raw)
	}
	var publicPreview struct {
		Space struct {
			MarkSeed string `json:"mark_seed"`
		} `json:"space"`
	}
	if err := json.Unmarshal(raw, &publicPreview); err != nil || len(publicPreview.Space.MarkSeed) != 43 {
		t.Fatalf("public preview mark seed contract failed: err=%v body=%s", err, raw)
	}

	portal, err := http.Get(h.Server.URL + "/join/v1/" + selector)
	if err != nil {
		t.Fatal(err)
	}
	defer portal.Body.Close()
	portalBody, _ := io.ReadAll(portal.Body)
	portalCSP := portal.Header.Get("Content-Security-Policy")
	exactPortalCSP := regexp.MustCompile(`^default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-[A-Za-z0-9+/]{24}'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'none'; img-src 'self'$`)
	if portal.StatusCode != http.StatusOK ||
		!exactPortalCSP.MatchString(portalCSP) ||
		portal.Header.Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(string(portalBody), "A Veil Link for a private Space") ||
		!strings.Contains(string(portalBody), "Review in Veil, then confirm") ||
		!strings.Contains(string(portalBody), "/assets/veil-link-bg-v1-38824a5f41228389.jpg") ||
		!strings.Contains(string(portalBody), "M4 4H8V11.8L4 13ZM4 16L8 14.8V20H4ZM10 2H14V10.5L10 11.7ZM10 14.7L14 13.5V22H10ZM16 5H20V8.2L16 9.4ZM16 12.4L20 11.2V19H16Z") ||
		!strings.Contains(string(portalBody), `data-seed="`+publicPreview.Space.MarkSeed+`"`) ||
		strings.Contains(string(portalBody), secret) || strings.Contains(string(portalBody), owner.ID) {
		t.Fatalf("unsafe Veil Link portal status=%d headers=%v body=%s", portal.StatusCode, portal.Header, portalBody)
	}
	invalidPortal, err := http.Get(h.Server.URL + "/join/v1/not-a-selector")
	if err != nil {
		t.Fatal(err)
	}
	defer invalidPortal.Body.Close()
	if invalidPortal.StatusCode != http.StatusNotFound {
		t.Fatalf("invalid portal status=%d", invalidPortal.StatusCode)
	}

	previewPath := "/v1/veil-links/" + selector + "/preview"
	previewBody := map[string]string{"secret": secret}
	status, _, signedPreview := h.Do(joiner, http.MethodPost, previewPath, previewBody)
	if status != http.StatusOK || signedPreview["already_member"] != false {
		t.Fatalf("pre-join authenticated preview status=%d body=%v", status, signedPreview)
	}

	status, used := joinVeilLink(t, h, joiner, link)
	if status != http.StatusOK || used["id"] != spaceID {
		t.Fatalf("join status=%d body=%v", status, used)
	}
	status, _, signedPreview = h.Do(joiner, http.MethodPost, previewPath, previewBody)
	if status != http.StatusOK || signedPreview["already_member"] != true {
		t.Fatalf("member authenticated preview status=%d body=%v", status, signedPreview)
	}
	var createdEvents, joinedEvents int
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FILTER (WHERE event_type='created'),
		        count(*) FILTER (WHERE event_type='joined')
		 FROM veil_link_events WHERE server_id=$1::uuid`, spaceID,
	).Scan(&createdEvents, &joinedEvents); err != nil {
		t.Fatal(err)
	}
	if createdEvents != 1 || joinedEvents != 1 {
		t.Fatalf("bounded Veil Link lifecycle events = created:%d joined:%d", createdEvents, joinedEvents)
	}
}

func TestVeilLinks_SecretExpiryUseAndRevocationAreFailClosed(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("veil-link-bounds-owner")
	first := h.CreateUser("veil-link-bounds-first")
	second := h.CreateUser("veil-link-bounds-second")
	spaceID := mkServer(t, h, owner, "Bounded Space")
	link := createVeilLink(t, h, owner, spaceID, 1)

	selector := link["public_selector"].(string)
	status, _, _ := h.Do(first, http.MethodPost, "/v1/veil-links/"+selector+"/join", map[string]string{"secret": strings.Repeat("A", 43)})
	if status == http.StatusOK {
		t.Fatal("wrong secret joined Space")
	}
	if status, _ := joinVeilLink(t, h, first, link); status != http.StatusOK {
		t.Fatalf("first join status=%d", status)
	}
	if status, _ := joinVeilLink(t, h, second, link); status == http.StatusOK {
		t.Fatal("exhausted Veil Link admitted second member")
	}

	revocable := createVeilLink(t, h, owner, spaceID, 2)
	path := "/v1/servers/" + spaceID + "/veil-links/" + revocable["id"].(string)
	if status, _, _ := h.Do(owner, http.MethodDelete, path, nil); status != http.StatusOK {
		t.Fatalf("revoke status=%d", status)
	}
	if status, _ := joinVeilLink(t, h, second, revocable); status == http.StatusOK {
		t.Fatal("revoked Veil Link admitted member")
	}
	var revokedEvents int
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM veil_link_events
		 WHERE server_id=$1::uuid AND link_id=$2::uuid AND event_type='revoked'`,
		spaceID, revocable["id"],
	).Scan(&revokedEvents); err != nil {
		t.Fatal(err)
	}
	if revokedEvents != 1 {
		t.Fatalf("revoke lifecycle event count = %d", revokedEvents)
	}

	revokeAll := createVeilLink(t, h, owner, spaceID, 2)
	if status, _, body := h.Do(owner, http.MethodDelete, "/v1/servers/"+spaceID+"/veil-links", nil); status != http.StatusOK {
		t.Fatalf("revoke-all status=%d body=%v", status, body)
	}
	if status, _ := joinVeilLink(t, h, second, revokeAll); status == http.StatusOK {
		t.Fatal("revoke-all left a Veil Link active")
	}
	var revokeAllEvents int
	if err := h.DB.Pool.QueryRow(t.Context(),
		`SELECT count(*) FROM veil_link_events
		 WHERE server_id=$1::uuid AND link_id IS NULL AND event_type='revoked_all'`, spaceID,
	).Scan(&revokeAllEvents); err != nil {
		t.Fatal(err)
	}
	if revokeAllEvents != 1 {
		t.Fatalf("revoke-all lifecycle event count = %d", revokeAllEvents)
	}

	expired := createVeilLink(t, h, owner, spaceID, 2)
	if _, err := h.DB.Pool.Exec(t.Context(), `UPDATE server_invites
		SET created_at=now()-interval '10 minutes', expires_at=now()-interval '1 second'
		WHERE id=$1::uuid`, expired["id"]); err != nil {
		t.Fatal(err)
	}
	if status, _ := joinVeilLink(t, h, second, expired); status == http.StatusOK {
		t.Fatal("expired Veil Link admitted member")
	}
}

func TestVeilLinks_StrictBoundsIdempotenceAndDeletedSpace(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("strict-link-owner")
	joiner := h.CreateUser("strict-link-joiner")
	other := h.CreateUser("strict-link-other")
	spaceID := mkServer(t, h, owner, "Strict Space")
	path := "/v1/servers/" + spaceID + "/veil-links"
	for name, body := range map[string]any{
		"malformed":    "{",
		"trailing":     `{"max_uses":1,"expires_in_secs":300} {}`,
		"unlimited":    map[string]any{"max_uses": 0, "expires_in_secs": 300},
		"too many":     map[string]any{"max_uses": 101, "expires_in_secs": 300},
		"short expiry": map[string]any{"max_uses": 1, "expires_in_secs": 299},
		"long expiry":  map[string]any{"max_uses": 1, "expires_in_secs": 7*24*60*60 + 1},
	} {
		t.Run(name, func(t *testing.T) {
			if status, _, _ := h.Do(owner, http.MethodPost, path, body); status != http.StatusBadRequest {
				t.Fatalf("invalid input status=%d", status)
			}
		})
	}

	link := createVeilLink(t, h, owner, spaceID, 1)
	if status, _ := joinVeilLink(t, h, owner, link); status != http.StatusOK {
		t.Fatalf("existing owner idempotent join status=%d", status)
	}
	if status, _ := joinVeilLink(t, h, joiner, link); status != http.StatusOK {
		t.Fatalf("first membership status=%d", status)
	}
	if status, _ := joinVeilLink(t, h, joiner, link); status != http.StatusOK {
		t.Fatalf("existing member repeat status=%d", status)
	}
	previewPath := "/v1/veil-links/" + link["public_selector"].(string) + "/preview"
	previewBody := map[string]string{"secret": link["secret"].(string)}
	if status, _, preview := h.Do(joiner, http.MethodPost, previewPath, previewBody); status != http.StatusOK || preview["already_member"] != true {
		t.Fatalf("consumed link did not route existing member: status=%d body=%v", status, preview)
	}
	if status, _, _ := h.Do(other, http.MethodPost, previewPath, previewBody); status == http.StatusOK {
		t.Fatal("consumed link preview offered admission to a new member")
	}
	inv, err := h.DB.GetInvite(t.Context(), link["public_selector"].(string))
	if err != nil || inv.Uses != 1 {
		t.Fatalf("idempotence changed use count: inv=%v err=%v", inv, err)
	}
	if status, _ := joinVeilLink(t, h, other, link); status == http.StatusOK {
		t.Fatal("second new member bypassed max uses")
	}

	deletedSpace := mkServer(t, h, owner, "Deleted Space")
	deleted := createVeilLink(t, h, owner, deletedSpace, 2)
	if err := h.DB.DeleteServer(t.Context(), deletedSpace); err != nil {
		t.Fatal(err)
	}
	if status, _ := joinVeilLink(t, h, other, deleted); status == http.StatusOK {
		t.Fatal("link joined a deleted Space")
	}
}

func TestKickMember_StrictOptionalJSONAndReasonBound(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("strict-kick-owner")
	target := h.CreateUser("strict-kick-target")
	spaceID := mkServer(t, h, owner, "Strict kick")
	joinViaInvite(t, h, target, mkInviteCode(t, h, owner, spaceID))
	path := "/v1/servers/" + spaceID + "/members/" + target.ID
	for name, body := range map[string]any{
		"malformed": "{",
		"trailing":  `{"reason":"spam"} {}`,
		"oversize":  map[string]string{"reason": strings.Repeat("x", 513)},
	} {
		t.Run(name, func(t *testing.T) {
			status, _, _ := h.Do(owner, http.MethodDelete, path, body)
			if status != http.StatusBadRequest {
				t.Fatalf("invalid kick body status=%d", status)
			}
			member, err := h.DB.IsServerMember(t.Context(), spaceID, target.ID)
			if err != nil || !member {
				t.Fatalf("invalid kick changed membership: member=%v err=%v", member, err)
			}
		})
	}
	if status, _, _ := h.Do(owner, http.MethodDelete, path, nil); status != http.StatusOK {
		t.Fatalf("empty optional kick body status=%d", status)
	}
}

func TestSpaceBanBlocksVeilLinkWithoutConsumingUseUntilExplicitUnban(t *testing.T) {
	h := New(t)
	owner := h.CreateUser("ban-owner")
	target := h.CreateUser("ban-target")
	spaceID := mkServer(t, h, owner, "Moderated Space")
	firstLink := createVeilLink(t, h, owner, spaceID, 1)
	if status, _ := joinVeilLink(t, h, target, firstLink); status != http.StatusOK {
		t.Fatalf("initial join status=%d", status)
	}

	banPath := "/v1/servers/" + spaceID + "/bans/" + target.ID
	if status, _, body := h.Do(owner, http.MethodPut, banPath, map[string]string{"reason": "raid"}); status != http.StatusOK {
		t.Fatalf("ban status=%d body=%v", status, body)
	}
	if member, err := h.DB.IsServerMember(t.Context(), spaceID, target.ID); err != nil || member {
		t.Fatalf("banned account retained Space membership: member=%v err=%v", member, err)
	}

	rejoinLink := createVeilLink(t, h, owner, spaceID, 1)
	if status, _ := joinVeilLink(t, h, target, rejoinLink); status == http.StatusOK {
		t.Fatal("banned account rejoined through a Veil Link")
	}
	invite, err := h.DB.GetInvite(t.Context(), rejoinLink["public_selector"].(string))
	if err != nil || invite.Uses != 0 {
		t.Fatalf("rejected ban consumed link use: invite=%v err=%v", invite, err)
	}
	if status, _, body := h.Do(owner, http.MethodGet, "/v1/servers/"+spaceID+"/bans", nil); status != http.StatusOK {
		t.Fatalf("list bans status=%d body=%v", status, body)
	} else if bans, ok := body["bans"].([]any); !ok || len(bans) != 1 {
		t.Fatalf("unexpected ban list: %v", body)
	}

	if status, _, body := h.Do(owner, http.MethodDelete, banPath, nil); status != http.StatusOK {
		t.Fatalf("unban status=%d body=%v", status, body)
	}
	if status, _ := joinVeilLink(t, h, target, rejoinLink); status != http.StatusOK {
		t.Fatalf("unbanned account did not rejoin status=%d", status)
	}
}
