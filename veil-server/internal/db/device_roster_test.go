package db

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func rosterTestDevice(id byte, binding *DeviceBinding) ConversationDirectoryDevice {
	deviceKey := bytes.Repeat([]byte{id}, 16)
	if binding != nil {
		binding.DeviceKey = append([]byte(nil), deviceKey...)
	}
	return ConversationDirectoryDevice{DeviceKey: deviceKey, Binding: binding}
}

func rosterTestBinding(status DeviceBindingStatus, version, capabilities uint64, keyByte byte) *DeviceBinding {
	return &DeviceBinding{
		DeviceIdentityKey: bytes.Repeat([]byte{keyByte}, 32),
		DeviceSigningKey:  bytes.Repeat([]byte{keyByte + 1}, 32),
		Version:           version,
		Capabilities:      capabilities,
		Status:            status,
		AccountSignature:  bytes.Repeat([]byte{keyByte + 2}, 64),
	}
}

// This vector fixes the v1 collection ordering and u32 length prefixes:
// members are UUID-byte sorted, devices are 16-byte device-id sorted, and a
// legacy device contributes an explicit status plus zeroed binding fields.
func TestConversationDeviceRosterCommitmentDeterministicVector(t *testing.T) {
	members := []ConversationDirectoryMember{
		{
			UserID: "00000000-0000-0000-0000-000000000002",
			Devices: []ConversationDirectoryDevice{
				rosterTestDevice(0x20, rosterTestBinding(DeviceBindingActive, 2, 3, 0x21)),
				rosterTestDevice(0x10, nil),
			},
		},
		{
			UserID: "00000000-0000-0000-0000-000000000001",
			Devices: []ConversationDirectoryDevice{
				rosterTestDevice(0x30, rosterTestBinding(DeviceBindingExcluded, 7, 3, 0x31)),
			},
		},
	}

	commitment, err := ConversationDeviceRosterCommitment(
		"00112233-4455-6677-8899-aabbccddeeff", 3, members,
	)
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("d2a757a44fb7f4fc28a17d92d6d874b4301bc0a17b71ae929ca1b65684923902")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(commitment[:], want) {
		t.Fatalf("roster commitment = %x, want %x", commitment, want)
	}

	// The caller's slice order is deliberately not canonical above. Reversing
	// both collections must still produce the exact same commitment.
	members[0], members[1] = members[1], members[0]
	members[1].Devices[0], members[1].Devices[1] = members[1].Devices[1], members[1].Devices[0]
	reordered, err := ConversationDeviceRosterCommitment(
		"00112233-4455-6677-8899-aabbccddeeff", 3, members,
	)
	if err != nil {
		t.Fatal(err)
	}
	if commitment != reordered {
		t.Fatalf("input order changed roster commitment: %x != %x", commitment, reordered)
	}
}

func TestConversationDeviceRosterCommitmentRejectsDuplicateAndOversizedFields(t *testing.T) {
	baseBinding := rosterTestBinding(DeviceBindingActive, 1, 3, 0x41)
	base := []ConversationDirectoryMember{{
		UserID: "00000000-0000-0000-0000-000000000001",
		Devices: []ConversationDirectoryDevice{
			rosterTestDevice(0x40, baseBinding),
		},
	}}
	if _, err := ConversationDeviceRosterCommitment("00112233-4455-6677-8899-aabbccddeeff", 3, base); err != nil {
		t.Fatalf("valid roster rejected: %v", err)
	}

	duplicateMember := append([]ConversationDirectoryMember(nil), base...)
	duplicateMember = append(duplicateMember, base[0])
	if _, err := ConversationDeviceRosterCommitment("00112233-4455-6677-8899-aabbccddeeff", 3, duplicateMember); err == nil {
		t.Fatal("duplicate member accepted")
	}

	duplicateDevice := append([]ConversationDirectoryMember(nil), base...)
	duplicateDevice[0].Devices = append(append([]ConversationDirectoryDevice(nil), base[0].Devices...), base[0].Devices[0])
	if _, err := ConversationDeviceRosterCommitment("00112233-4455-6677-8899-aabbccddeeff", 3, duplicateDevice); err == nil {
		t.Fatal("duplicate device accepted")
	}

	oversized := append([]ConversationDirectoryMember(nil), base...)
	badBinding := *oversized[0].Devices[0].Binding
	badBinding.Version = uint64(^uint64(0)>>1) + 1
	oversized[0].Devices = []ConversationDirectoryDevice{rosterTestDevice(0x40, &badBinding)}
	if _, err := ConversationDeviceRosterCommitment("00112233-4455-6677-8899-aabbccddeeff", 3, oversized); err == nil {
		t.Fatal("binding version outside PostgreSQL range accepted")
	}
}
