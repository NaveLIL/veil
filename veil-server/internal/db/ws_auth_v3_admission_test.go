package db

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"math"
	"testing"
)

func TestAdmitWSAuthV3RejectsNilContextBeforeValidationOrPoolUse(t *testing.T) {
	database := &DB{}
	result, err := database.AdmitWSAuthV3(nil, validWSAuthV3AdmissionRequestForTest())
	if err == nil || result != nil {
		t.Fatalf("nil-context admission result=%#v err=%v, want nil operational error", result, err)
	}
	if errors.Is(err, ErrWSAuthV3AdmissionRejected) || errors.Is(err, ErrNodeAccessInviteInvalid) {
		t.Fatalf("nil context was misclassified as authenticated rejection: %v", err)
	}
	if _, err := database.AdmitWSAuthV3(context.Background(), validWSAuthV3AdmissionRequestForTest()); err == nil {
		t.Fatal("empty database unexpectedly accepted a non-nil context")
	}
}

func validWSAuthV3AdmissionRequestForTest() WSAuthV3AdmissionRequest {
	accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	devicePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	request := WSAuthV3AdmissionRequest{
		Intent:                WSAuthV3AdmissionPass,
		AccountIdentityKey:    repeatedWSAuthV3DB32(0x31),
		DeviceKey:             repeatedWSAuthV3DB16(0x41),
		DeviceIdentityKey:     repeatedWSAuthV3DB32(0x51),
		BindingVersion:        1,
		BindingCapabilities:   RequiredChannelCapabilities,
		BindingStatus:         DeviceBindingActive,
		BindingSignature:      repeatedWSAuthV3DB64(0x61),
		BindingCommitment:     repeatedWSAuthV3DB32(0x71),
		DeviceName:            "Pixel test",
		NodeAccessPass:        bytes.Repeat([]byte{0x81}, NodeAccessInviteTokenSize),
		AllowOpenRegistration: false,
	}
	copy(request.AccountSigningKey[:], accountPrivate.Public().(ed25519.PublicKey))
	copy(request.DeviceSigningKey[:], devicePrivate.Public().(ed25519.PublicKey))
	return request
}

func repeatedWSAuthV3DB16(value byte) (result [16]byte) {
	for index := range result {
		result[index] = value
	}
	return result
}

func repeatedWSAuthV3DB32(value byte) (result [32]byte) {
	for index := range result {
		result[index] = value
	}
	return result
}

func repeatedWSAuthV3DB64(value byte) (result [64]byte) {
	for index := range result {
		result[index] = value
	}
	return result
}

func TestValidateWSAuthV3AdmissionRequestAcceptsOnlyCoherentFixedInputs(t *testing.T) {
	for _, intent := range []WSAuthV3AdmissionIntent{
		WSAuthV3AdmissionExisting, WSAuthV3AdmissionOpen, WSAuthV3AdmissionPass,
	} {
		request := validWSAuthV3AdmissionRequestForTest()
		request.Intent = intent
		if intent != WSAuthV3AdmissionPass {
			request.NodeAccessPass = nil
		}
		if err := validateWSAuthV3AdmissionRequest(request); err != nil {
			t.Fatalf("valid intent %d rejected: %v", intent, err)
		}
	}

	tests := map[string]func(*WSAuthV3AdmissionRequest){
		"unknown intent":            func(value *WSAuthV3AdmissionRequest) { value.Intent = 4 },
		"zero account identity":     func(value *WSAuthV3AdmissionRequest) { value.AccountIdentityKey = [32]byte{} },
		"weak account signing":      func(value *WSAuthV3AdmissionRequest) { value.AccountSigningKey = [32]byte{} },
		"zero device id":            func(value *WSAuthV3AdmissionRequest) { value.DeviceKey = [16]byte{} },
		"zero device identity":      func(value *WSAuthV3AdmissionRequest) { value.DeviceIdentityKey = [32]byte{} },
		"weak device signing":       func(value *WSAuthV3AdmissionRequest) { value.DeviceSigningKey = [32]byte{} },
		"zero binding version":      func(value *WSAuthV3AdmissionRequest) { value.BindingVersion = 0 },
		"oversized binding version": func(value *WSAuthV3AdmissionRequest) { value.BindingVersion = math.MaxInt64 + 1 },
		"missing capabilities":      func(value *WSAuthV3AdmissionRequest) { value.BindingCapabilities = 0 },
		"oversized capabilities":    func(value *WSAuthV3AdmissionRequest) { value.BindingCapabilities = math.MaxInt64 + 1 },
		"non-active binding":        func(value *WSAuthV3AdmissionRequest) { value.BindingStatus = DeviceBindingExcluded },
		"zero binding signature":    func(value *WSAuthV3AdmissionRequest) { value.BindingSignature = [64]byte{} },
		"zero binding commitment":   func(value *WSAuthV3AdmissionRequest) { value.BindingCommitment = [32]byte{} },
		"empty device name":         func(value *WSAuthV3AdmissionRequest) { value.DeviceName = "" },
		"control device name":       func(value *WSAuthV3AdmissionRequest) { value.DeviceName = "bad\nname" },
		"long device name":          func(value *WSAuthV3AdmissionRequest) { value.DeviceName = string(bytes.Repeat([]byte{'a'}, 129)) },
		"missing Pass":              func(value *WSAuthV3AdmissionRequest) { value.NodeAccessPass = nil },
		"zero Pass":                 func(value *WSAuthV3AdmissionRequest) { value.NodeAccessPass = make([]byte, NodeAccessInviteTokenSize) },
		"short Pass": func(value *WSAuthV3AdmissionRequest) {
			value.NodeAccessPass = bytes.Repeat([]byte{1}, NodeAccessInviteTokenSize-1)
		},
		"bearer on existing": func(value *WSAuthV3AdmissionRequest) { value.Intent = WSAuthV3AdmissionExisting },
		"bearer on open":     func(value *WSAuthV3AdmissionRequest) { value.Intent = WSAuthV3AdmissionOpen },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validWSAuthV3AdmissionRequestForTest()
			mutate(&request)
			if err := validateWSAuthV3AdmissionRequest(request); !errors.Is(err, ErrWSAuthV3AdmissionRejected) {
				t.Fatalf("error = %v, want ErrWSAuthV3AdmissionRejected", err)
			}
		})
	}
}
