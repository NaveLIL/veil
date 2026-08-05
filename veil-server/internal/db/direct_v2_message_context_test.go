package db

import (
	"bytes"
	"testing"
)

func validDirectV2MessageContextForTest() *MessageSecurityContext {
	return &MessageSecurityContext{
		CryptoProfile:             MessageCryptoProfileDirectV2,
		CryptoEra:                 MessageCryptoEraDirectV2,
		SenderDeviceID:            bytes.Repeat([]byte{0x21}, 16),
		SenderBindingVersion:      3,
		SenderDeviceDatabaseID:    "550e8400-e29b-41d4-a716-446655440301",
		SenderDeviceIdentityKey:   bytes.Repeat([]byte{0x22}, 32),
		SenderDeviceSigningKey:    bytes.Repeat([]byte{0x23}, 32),
		SenderDeviceCapabilities:  RequiredChannelCapabilities,
		SenderDeviceBindingStatus: DeviceBindingActive,
		SenderAccountSignature:    bytes.Repeat([]byte{0x24}, 64),
		TargetDeviceID:            bytes.Repeat([]byte{0x25}, 16),
		TargetBindingVersion:      4,
		TargetDeviceDatabaseID:    "550e8400-e29b-41d4-a716-446655440302",
		DirectSessionID:           bytes.Repeat([]byte{0x26}, 32),
	}
}

func TestValidateDirectV2MessageSecurityContextRejectsProfileSmuggling(t *testing.T) {
	valid := validDirectV2MessageContextForTest()
	if err := validateMessageSecurityContext(valid); err != nil {
		t.Fatalf("valid Direct v2 context: %v", err)
	}

	mutations := map[string]func(*MessageSecurityContext){
		"era":    func(context *MessageSecurityContext) { context.CryptoEra++ },
		"roster": func(context *MessageSecurityContext) { context.RosterVersion = 1 },
		"sender target collision": func(context *MessageSecurityContext) {
			context.TargetDeviceID = append([]byte(nil), context.SenderDeviceID...)
		},
		"sender identity": func(context *MessageSecurityContext) {
			context.SenderDeviceIdentityKey = context.SenderDeviceIdentityKey[:31]
		},
		"sender signing collision": func(context *MessageSecurityContext) {
			context.SenderDeviceSigningKey = append([]byte(nil), context.SenderDeviceIdentityKey...)
		},
		"capabilities": func(context *MessageSecurityContext) { context.SenderDeviceCapabilities = 0 },
		"status":       func(context *MessageSecurityContext) { context.SenderDeviceBindingStatus = DeviceBindingRevoked },
		"signature": func(context *MessageSecurityContext) {
			context.SenderAccountSignature = context.SenderAccountSignature[:63]
		},
		"target version": func(context *MessageSecurityContext) { context.TargetBindingVersion = 0 },
		"session":        func(context *MessageSecurityContext) { context.DirectSessionID = context.DirectSessionID[:31] },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			context := *valid
			context.SenderDeviceID = append([]byte(nil), valid.SenderDeviceID...)
			context.SenderDeviceIdentityKey = append([]byte(nil), valid.SenderDeviceIdentityKey...)
			context.SenderDeviceSigningKey = append([]byte(nil), valid.SenderDeviceSigningKey...)
			context.SenderAccountSignature = append([]byte(nil), valid.SenderAccountSignature...)
			context.TargetDeviceID = append([]byte(nil), valid.TargetDeviceID...)
			context.DirectSessionID = append([]byte(nil), valid.DirectSessionID...)
			mutate(&context)
			if err := validateMessageSecurityContext(&context); err == nil {
				t.Fatal("mutated Direct v2 context was accepted")
			}
		})
	}
}

func TestValidateSenderKeyV6MessageSecurityContextRequiresExactMembershipCoordinates(t *testing.T) {
	valid := &MessageSecurityContext{
		CryptoProfile:          MessageCryptoProfileSenderKeyV6,
		CryptoEra:              MessageCryptoEraSenderKeyV6,
		RosterVersion:          7,
		RosterCommitment:       bytes.Repeat([]byte{0x31}, 32),
		MembershipEpoch:        9,
		MembershipEpochHash:    bytes.Repeat([]byte{0x32}, 32),
		SenderDeviceID:         bytes.Repeat([]byte{0x33}, 16),
		SenderBindingVersion:   4,
		SenderDeviceDatabaseID: "550e8400-e29b-41d4-a716-446655440303",
	}
	if err := validateMessageSecurityContext(valid); err != nil {
		t.Fatalf("valid Sender-Key v6 context: %v", err)
	}

	mutations := map[string]func(*MessageSecurityContext){
		"legacy profile":      func(context *MessageSecurityContext) { context.CryptoProfile = MessageCryptoProfileSenderKeyV5 },
		"zero roster hash":    func(context *MessageSecurityContext) { context.RosterCommitment = make([]byte, 32) },
		"missing epoch":       func(context *MessageSecurityContext) { context.MembershipEpoch = 0 },
		"partial epoch":       func(context *MessageSecurityContext) { context.MembershipEpochHash = nil },
		"zero epoch hash":     func(context *MessageSecurityContext) { context.MembershipEpochHash = make([]byte, 32) },
		"zero sender device":  func(context *MessageSecurityContext) { context.SenderDeviceID = make([]byte, 16) },
		"direct target field": func(context *MessageSecurityContext) { context.TargetDeviceID = bytes.Repeat([]byte{0x34}, 16) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			candidate.RosterCommitment = append([]byte(nil), valid.RosterCommitment...)
			candidate.MembershipEpochHash = append([]byte(nil), valid.MembershipEpochHash...)
			candidate.SenderDeviceID = append([]byte(nil), valid.SenderDeviceID...)
			mutate(&candidate)
			if err := validateMessageSecurityContext(&candidate); err == nil {
				t.Fatal("mutated Sender-Key v6 context was accepted")
			}
		})
	}
}
