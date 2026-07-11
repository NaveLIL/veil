package db

import (
	"context"
	"errors"
	"testing"
)

func TestResolveChannelPermissionsAppliesOverwriteTiersInOrder(t *testing.T) {
	permissions, err := resolveChannelPermissions(
		false,
		PermViewChannel|PermSendMessages,
		1,
		PermManageMessages, PermSendMessages,
		PermSendMessages, PermViewChannel,
		PermReadMessageHistory, PermManageMessages,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := PermSendMessages | PermReadMessageHistory
	if permissions != want {
		t.Fatalf("permissions = %#x, want %#x", permissions, want)
	}
}

func TestResolveChannelPermissionsRoleAllowWinsWithinAggregateTier(t *testing.T) {
	permissions, err := resolveChannelPermissions(
		false,
		PermManageMessages,
		1,
		0, 0,
		PermViewChannel, PermViewChannel|PermManageMessages,
		0, 0,
	)
	if err != nil {
		t.Fatal(err)
	}
	if permissions != PermViewChannel {
		t.Fatalf("permissions = %#x, want role allow %#x", permissions, PermViewChannel)
	}
}

func TestResolveChannelPermissionsOwnerAndAdministratorBypassOverwrites(t *testing.T) {
	for _, test := range []struct {
		name  string
		owner bool
		base  uint64
	}{
		{name: "owner", owner: true, base: PermViewChannel},
		{name: "administrator", base: PermAdministrator | PermViewChannel},
	} {
		t.Run(test.name, func(t *testing.T) {
			permissions, err := resolveChannelPermissions(
				test.owner, test.base, 0,
				0, AllChannelPermissions,
				0, AllChannelPermissions,
				0, AllChannelPermissions,
			)
			if err != nil {
				t.Fatal(err)
			}
			want := test.base | PermAdministrator
			if permissions != want {
				t.Fatalf("permissions = %#x, want %#x", permissions, want)
			}
		})
	}
}

func TestResolveChannelPermissionsRejectsMissingDefaultRole(t *testing.T) {
	for _, count := range []int64{0, 2} {
		if _, err := resolveChannelPermissions(false, PermViewChannel, count, 0, 0, 0, 0, 0, 0); !errors.Is(err, ErrInvalidChannelOverwrite) {
			t.Fatalf("default role count %d error = %v", count, err)
		}
	}
}

func TestKnownSignedPermissionMaskRejectsNegativeAndUnknownBits(t *testing.T) {
	if !isKnownSignedPermissionMask(int64(AllRolePermissions), AllRolePermissions) {
		t.Fatal("known role permission mask rejected")
	}
	for _, value := range []int64{-1, int64(AllRolePermissions | uint64(1)<<20)} {
		if isKnownSignedPermissionMask(value, AllRolePermissions) {
			t.Fatalf("invalid signed permission mask accepted: %d", value)
		}
	}
}

func TestValidateChannelOverwrite(t *testing.T) {
	valid := ChannelOverwrite{TargetType: ChannelOverwriteRole, Allow: PermViewChannel, Deny: PermSendMessages}
	if err := validateChannelOverwrite(valid); err != nil {
		t.Fatalf("valid overwrite rejected: %v", err)
	}

	invalid := []ChannelOverwrite{
		{TargetType: 2},
		{TargetType: ChannelOverwriteRole, Allow: uint64(1) << 20},
		{TargetType: ChannelOverwriteUser, Deny: uint64(1) << 20},
		{TargetType: ChannelOverwriteUser, Allow: PermViewChannel, Deny: PermViewChannel},
	}
	for _, overwrite := range invalid {
		if err := validateChannelOverwrite(overwrite); !errors.Is(err, ErrInvalidChannelOverwrite) {
			t.Fatalf("invalid overwrite %#v error = %v", overwrite, err)
		}
	}
}

func TestHasAllChannelPermissionsRejectsUnknownRequiredBitsBeforeDatabase(t *testing.T) {
	database := &DB{}
	allowed, err := database.HasAllChannelPermissions(
		context.Background(), "unused", "unused", uint64(1)<<20,
	)
	if err != nil || allowed {
		t.Fatalf("unknown required bit allowed=%v err=%v", allowed, err)
	}
}
