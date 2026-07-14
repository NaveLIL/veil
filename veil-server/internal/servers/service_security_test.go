package servers

import (
	"errors"
	"strings"
	"testing"

	"github.com/AegisSec/veil-server/internal/db"
)

func TestRoleManagerCannotGrantPermissionsOutsideOwnSet(t *testing.T) {
	manager := roleManager{permissions: db.PermManageRoles, highest: 1}
	if !manager.canGrant(0) || !manager.canGrant(db.PermManageRoles) {
		t.Fatal("manager could not grant a subset of its effective permissions")
	}
	for _, permissions := range []uint64{
		db.PermKickMembers,
		db.PermManageRoles | db.PermAdministrator,
		uint64(1) << 63,
	} {
		if manager.canGrant(permissions) {
			t.Fatalf("manager was allowed to grant %#x", permissions)
		}
	}
}

func TestServerMetadataBoundsAndRemoteIconHardCut(t *testing.T) {
	empty := "   "
	if err := validateServerName(empty); err == nil {
		t.Fatal("blank server name accepted")
	}
	tooLongName := strings.Repeat("n", 101)
	if err := validateServerName(tooLongName); err == nil {
		t.Fatal("oversize server name accepted")
	}
	validName := "Veil team"
	validDescription := strings.Repeat("d", 2000)
	if err := validateServerMetadata(&validName, &validDescription, nil); err != nil {
		t.Fatalf("valid metadata rejected: %v", err)
	}
	for _, raw := range []string{"", "https://cdn.example/icon.png", "data:image/svg+xml,evil"} {
		t.Run(raw, func(t *testing.T) {
			if err := validateServerMetadata(nil, nil, &raw); err == nil {
				t.Fatalf("remote icon field accepted: %q", raw)
			}
		})
	}
	tooLongDescription := strings.Repeat("d", 2001)
	if err := validateServerMetadata(nil, &tooLongDescription, nil); err == nil {
		t.Fatal("oversize description accepted")
	}
}

func TestChannelMetadataBounds(t *testing.T) {
	validName := "general"
	validTopic := strings.Repeat("t", 2000)
	if err := validateChannelMetadata(&validName, &validTopic); err != nil {
		t.Fatalf("valid channel metadata rejected: %v", err)
	}
	blank := "\t"
	if err := validateChannelMetadata(&blank, nil); err == nil {
		t.Fatal("blank channel name accepted")
	}
	tooLongName := strings.Repeat("n", 101)
	tooLongTopic := strings.Repeat("t", 2001)
	if err := validateChannelMetadata(&tooLongName, nil); err == nil {
		t.Fatal("oversize channel name accepted")
	}
	if err := validateChannelMetadata(nil, &tooLongTopic); err == nil {
		t.Fatal("oversize channel topic accepted")
	}
}

func TestInviteInputBounds(t *testing.T) {
	for _, test := range []struct {
		maxUses int32
		expiry  int64
		valid   bool
	}{
		{minInviteUses, minInviteExpirySecs, true},
		{maxInviteUses, maxInviteExpirySecs, true},
		{0, minInviteExpirySecs, false},
		{maxInviteUses + 1, minInviteExpirySecs, false},
		{minInviteUses, minInviteExpirySecs - 1, false},
		{minInviteUses, maxInviteExpirySecs + 1, false},
	} {
		err := validateInviteInput(test.maxUses, test.expiry)
		if (err == nil) != test.valid {
			t.Fatalf("validateInviteInput(%d,%d) err=%v valid=%v", test.maxUses, test.expiry, err, test.valid)
		}
	}
}

func TestKickReasonNormalizationAndBounds(t *testing.T) {
	if reason, err := normalizeKickReason(nil); err != nil || reason != nil {
		t.Fatalf("nil reason normalized to %v err=%v", reason, err)
	}
	blank := " \t\n "
	if reason, err := normalizeKickReason(&blank); err != nil || reason != nil {
		t.Fatalf("blank reason normalized to %v err=%v", reason, err)
	}
	raw := "  spam  "
	reason, err := normalizeKickReason(&raw)
	if err != nil || reason == nil || *reason != "spam" {
		t.Fatalf("trimmed reason=%v err=%v", reason, err)
	}
	tooLong := strings.Repeat("x", maxKickReasonBytes+1)
	if _, err := normalizeKickReason(&tooLong); err == nil {
		t.Fatal("oversize kick reason accepted")
	}
	invalid := string([]byte{0xff})
	if _, err := normalizeKickReason(&invalid); err == nil {
		t.Fatal("invalid UTF-8 kick reason accepted")
	}
}

func TestAdministratorStillCannotPersistUnknownPermissionBits(t *testing.T) {
	administrator := roleManager{permissions: db.PermAdministrator, highest: 10}
	if !administrator.canGrant(db.AllRolePermissions) {
		t.Fatal("administrator could not grant the known permission set")
	}
	if administrator.canGrant(db.AllRolePermissions | uint64(1)<<63) {
		t.Fatal("administrator was allowed to persist unknown permission bits")
	}
}

func TestChannelOverwriteGrantRequiresAuthorityAndKnownSubset(t *testing.T) {
	managerPermissions := db.PermManageChannels | db.PermViewChannel
	if err := validateChannelOverwriteGrant(managerPermissions, db.PermViewChannel); err != nil {
		t.Fatalf("manager could not grant possessed channel permission: %v", err)
	}
	if err := validateChannelOverwriteGrant(db.PermAdministrator, db.AllChannelPermissions); err != nil {
		t.Fatalf("administrator could not grant known channel permissions: %v", err)
	}

	if err := validateChannelOverwriteGrant(db.PermViewChannel, db.PermViewChannel); err == nil {
		t.Fatal("non-manager was allowed to grant a channel permission")
	}
	if err := validateChannelOverwriteGrant(managerPermissions, db.PermSendMessages); err == nil {
		t.Fatal("manager was allowed to grant a channel permission it does not possess")
	}

	unknown := uint64(1) << 20
	for _, permissions := range []uint64{managerPermissions, db.PermAdministrator} {
		if err := validateChannelOverwriteGrant(permissions, unknown); !errors.Is(err, db.ErrInvalidChannelOverwrite) {
			t.Fatalf("unknown overwrite permission error = %v", err)
		}
	}
}
