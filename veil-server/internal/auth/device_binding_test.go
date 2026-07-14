package auth

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	"golang.org/x/crypto/curve25519"
)

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return decoded
}

// TestDeviceBindingV1DeterministicVector pins the complete cross-language
// encoding used by Go and Rust clients. Integer fields are unsigned big-endian
// and both domains end in one NUL byte (00), not the two bytes "\\0".
func TestDeviceBindingV1DeterministicVector(t *testing.T) {
	accountIdentityKey := bytes.Repeat([]byte{0x11}, 32)
	accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, 32))
	accountSigningKey := accountPrivate.Public().(ed25519.PublicKey)
	devicePrivate := bytes.Repeat([]byte{0x44}, 32)
	deviceIdentityKey, err := curve25519.X25519(devicePrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	deviceSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x55}, 32))
	deviceSigningKey := deviceSigningPrivate.Public().(ed25519.PublicKey)
	binding := &DeviceBindingInput{
		DeviceKey:         bytes.Repeat([]byte{0x33}, 16),
		DeviceIdentityKey: deviceIdentityKey,
		DeviceSigningKey:  deviceSigningKey,
		Version:           1,
		Capabilities:      db.RequiredChannelCapabilities,
		Status:            db.DeviceBindingActive,
	}

	if want := decodeVectorHex(t, "a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0"); !bytes.Equal(accountSigningKey, want) {
		t.Fatalf("account Ed25519 public key = %x, want %x", accountSigningKey, want)
	}
	if want := decodeVectorHex(t, "ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6b"); !bytes.Equal(deviceIdentityKey, want) {
		t.Fatalf("device X25519 public key = %x, want %x", deviceIdentityKey, want)
	}
	if want := decodeVectorHex(t, "c6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242"); !bytes.Equal(deviceSigningKey, want) {
		t.Fatalf("device Ed25519 public key = %x, want %x", deviceSigningKey, want)
	}

	bindingMessage, err := DeviceBindingSigningMessage(accountIdentityKey, accountSigningKey, binding)
	if err != nil {
		t.Fatal(err)
	}
	wantBindingMessage := decodeVectorHex(t, "7665696c2d6465766963652d62696e64696e672d7631001111111111111111111111111111111111111111111111111111111111111111a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0333333333333333333333333333333330000000000000001ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6bc6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f73242000000000000000301")
	if !bytes.Equal(bindingMessage, wantBindingMessage) {
		t.Fatalf("binding preimage = %x, want %x", bindingMessage, wantBindingMessage)
	}
	binding.AccountSignature = ed25519.Sign(accountPrivate, bindingMessage)
	wantBindingSignature := decodeVectorHex(t, "30c502700162d164a178a1fd624b3876c084f327f5e1a822fca2c9be977f7092928ff337559313ae0d11f7cc2447ae33f66f1f369dc9b2f32af3ee6fede29a00")
	if !bytes.Equal(binding.AccountSignature, wantBindingSignature) {
		t.Fatalf("binding signature = %x, want %x", binding.AccountSignature, wantBindingSignature)
	}

	serverPrivate := bytes.Repeat([]byte{0x66}, 32)
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	if want := decodeVectorHex(t, "219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf424"); !bytes.Equal(serverPublic, want) {
		t.Fatalf("server X25519 public key = %x, want %x", serverPublic, want)
	}
	sharedSecret, err := curve25519.X25519(devicePrivate, serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	if want := decodeVectorHex(t, "bef8ae582f817bd7eb1b104a83343a15770c1cf2dbc4b4207b70897b7a532209"); !bytes.Equal(sharedSecret, want) {
		t.Fatalf("device DH secret = %x, want %x", sharedSecret, want)
	}

	authMessage, err := DeviceAuthSigningMessage(
		serverPublic, accountIdentityKey, accountSigningKey, binding, sharedSecret,
	)
	if err != nil {
		t.Fatal(err)
	}
	wantAuthMessage := decodeVectorHex(t, "7665696c2d6465766963652d617574682d763100219e4d800da968d2a5fcb009c784f4746c7138edb9ee4844b739e830b05cf4241111111111111111111111111111111111111111111111111111111111111111a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0333333333333333333333333333333330000000000000001ff2ee45601ec1b67310c7790404585ae697331eee1c1f8cf2419731c1fff3e6bc6822637c7d310ec57627be00ba259d253749f4aaf644470cffbe53a35f7324200000000000000030130c502700162d164a178a1fd624b3876c084f327f5e1a822fca2c9be977f7092928ff337559313ae0d11f7cc2447ae33f66f1f369dc9b2f32af3ee6fede29a00bef8ae582f817bd7eb1b104a83343a15770c1cf2dbc4b4207b70897b7a532209")
	if !bytes.Equal(authMessage, wantAuthMessage) {
		t.Fatalf("device auth preimage = %x, want %x", authMessage, wantAuthMessage)
	}
	wantDeviceSignature := decodeVectorHex(t, "c17d2519f57119fc9415472aef77b212233c586365f10db7b5011dc3f45f7bd883eedbb6bbfcabe0291fedcc83685ec17790901ce252a3683937b3659f448303")
	if signature := ed25519.Sign(deviceSigningPrivate, authMessage); !bytes.Equal(signature, wantDeviceSignature) {
		t.Fatalf("device proof signature = %x, want %x", signature, wantDeviceSignature)
	}
}

func TestDeviceBindingV1RejectsAmbiguousFields(t *testing.T) {
	deviceSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	valid := &DeviceBindingInput{
		DeviceKey:         bytes.Repeat([]byte{1}, 16),
		DeviceIdentityKey: bytes.Repeat([]byte{2}, 32),
		DeviceSigningKey:  deviceSigningPrivate.Public().(ed25519.PublicKey),
		Version:           1,
		Capabilities:      db.RequiredChannelCapabilities,
		Status:            db.DeviceBindingActive,
	}
	accountIdentity := bytes.Repeat([]byte{4}, 32)
	accountSigning := bytes.Repeat([]byte{5}, 32)
	if _, err := DeviceBindingSigningMessage(accountIdentity, accountSigning, valid); err != nil {
		t.Fatalf("valid binding rejected: %v", err)
	}

	for name, mutate := range map[string]func(*DeviceBindingInput){
		"zero version":        func(value *DeviceBindingInput) { value.Version = 0 },
		"legacy signed state": func(value *DeviceBindingInput) { value.Status = db.DeviceLegacyUnbound },
		"short device id":     func(value *DeviceBindingInput) { value.DeviceKey = value.DeviceKey[:15] },
		"short X25519 key":    func(value *DeviceBindingInput) { value.DeviceIdentityKey = value.DeviceIdentityKey[:31] },
		"short Ed25519 key":   func(value *DeviceBindingInput) { value.DeviceSigningKey = value.DeviceSigningKey[:31] },
		"weak Ed25519 key":    func(value *DeviceBindingInput) { value.DeviceSigningKey = make([]byte, 32) },
	} {
		t.Run(name, func(t *testing.T) {
			copyValue := *valid
			mutate(&copyValue)
			if _, err := DeviceBindingSigningMessage(accountIdentity, accountSigning, &copyValue); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
}

func TestDecodeBindingUint63RequiresCanonicalDecimal(t *testing.T) {
	for _, test := range []struct {
		value     string
		allowZero bool
		want      uint64
		valid     bool
	}{
		{value: "1", want: 1, valid: true},
		{value: "9223372036854775807", want: 1<<63 - 1, valid: true},
		{value: "0", allowZero: true, valid: true},
		{value: "", valid: false},
		{value: "0", valid: false},
		{value: "01", valid: false},
		{value: "+1", valid: false},
		{value: "-1", valid: false},
		{value: " 1", valid: false},
		{value: "9223372036854775808", valid: false},
	} {
		got, err := decodeBindingUint63(test.value, "test", test.allowZero)
		if test.valid {
			if err != nil || got != test.want {
				t.Fatalf("decode %q = %d, %v; want %d, nil", test.value, got, err, test.want)
			}
		} else if err == nil {
			t.Fatalf("non-canonical value %q accepted as %d", test.value, got)
		}
	}
}
