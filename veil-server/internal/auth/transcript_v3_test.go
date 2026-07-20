package auth

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
)

const wsAuthV3TestOrigin = "https://chat.example.test:443"

type wsAuthV3TestFixture struct {
	input          WSAuthContextV3Input
	devicePublic   [ed25519.PublicKeySize]byte
	accountShared  []byte
	deviceShared   []byte
	accountProof   []byte
	deviceProof    []byte
	accountMessage []byte
	deviceMessage  []byte
}

func repeated32(value byte) (output [32]byte) {
	for index := range output {
		output[index] = value
	}
	return output
}

func repeated16(value byte) (output [16]byte) {
	for index := range output {
		output[index] = value
	}
	return output
}

func newWSAuthV3TestInput(t *testing.T, intent WSAuthRegistrationIntentV3) WSAuthContextV3Input {
	t.Helper()
	accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	accountPublic := accountPrivate.Public().(ed25519.PublicKey)
	var accountSigningKey [ed25519.PublicKeySize]byte
	copy(accountSigningKey[:], accountPublic)

	input := WSAuthContextV3Input{
		CanonicalOrigin:           wsAuthV3TestOrigin,
		ServerEphemeral:           repeated32(0x11),
		AccountIdentityKey:        repeated32(0x22),
		AccountSigningKey:         accountSigningKey,
		DeviceID:                  repeated16(0x33),
		VerifiedBindingCommitment: repeated32(0x44),
		RegistrationIntent:        intent,
	}
	if intent == WSAuthRegistrationCreateWithPassV3 {
		commitment, err := NodeAccessPassCommitmentV1(
			input.CanonicalOrigin, bytes.Repeat([]byte{0x55}, NodeAccessPassSizeV1),
		)
		if err != nil {
			t.Fatal(err)
		}
		input.PassCommitment = commitment
	}
	return input
}

func signedWSAuthV3TestFixture(t *testing.T, input WSAuthContextV3Input) wsAuthV3TestFixture {
	t.Helper()
	accountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	devicePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	devicePublicSlice := devicePrivate.Public().(ed25519.PublicKey)
	var devicePublic [ed25519.PublicKeySize]byte
	copy(devicePublic[:], devicePublicSlice)

	accountShared := bytes.Repeat([]byte{0x71}, WSAuthV3SharedSecretSize)
	deviceShared := bytes.Repeat([]byte{0x81}, WSAuthV3SharedSecretSize)
	accountMessage, err := WSAuthV3AccountProofMessage(input, accountShared)
	if err != nil {
		t.Fatal(err)
	}
	accountProof := ed25519.Sign(accountPrivate, accountMessage)
	deviceMessage, err := WSAuthV3DeviceProofMessage(input, deviceShared, accountProof)
	if err != nil {
		t.Fatal(err)
	}
	deviceProof := ed25519.Sign(devicePrivate, deviceMessage)

	return wsAuthV3TestFixture{
		input:          input,
		devicePublic:   devicePublic,
		accountShared:  accountShared,
		deviceShared:   deviceShared,
		accountProof:   accountProof,
		deviceProof:    deviceProof,
		accountMessage: accountMessage,
		deviceMessage:  deviceMessage,
	}
}

// verifyWSAuthV3TestProofs deliberately lives in _test.go. Production exposes
// canonical builders only: a runtime verifier must derive the DH values and
// obtain the device key from the same verified binding whose commitment is in
// the context, an invariant this isolated contract cannot enforce by itself.
func verifyWSAuthV3TestProofs(
	input WSAuthContextV3Input,
	verifiedDeviceSigningKey [ed25519.PublicKeySize]byte,
	accountShared, deviceShared, accountProofSignature, deviceProofSignature []byte,
) error {
	if !cryptokey.ValidEd25519PublicKey(verifiedDeviceSigningKey[:]) {
		return wsAuthV3Invalid("test device Ed25519 key", nil)
	}
	if len(accountProofSignature) != ed25519.SignatureSize || allZeroWSAuthV3(accountProofSignature) {
		return wsAuthV3Invalid("test account proof signature", nil)
	}
	if len(deviceProofSignature) != ed25519.SignatureSize || allZeroWSAuthV3(deviceProofSignature) {
		return wsAuthV3Invalid("test device proof signature", nil)
	}

	accountMessage, err := WSAuthV3AccountProofMessage(input, accountShared)
	if err != nil {
		return err
	}
	accountOK := ed25519.Verify(
		ed25519.PublicKey(input.AccountSigningKey[:]), accountMessage, accountProofSignature,
	)
	clear(accountMessage)
	if !accountOK {
		return wsAuthV3Invalid("test account proof", nil)
	}

	deviceMessage, err := WSAuthV3DeviceProofMessage(input, deviceShared, accountProofSignature)
	if err != nil {
		return err
	}
	deviceOK := ed25519.Verify(
		ed25519.PublicKey(verifiedDeviceSigningKey[:]), deviceMessage, deviceProofSignature,
	)
	clear(deviceMessage)
	if !deviceOK {
		return wsAuthV3Invalid("test device proof", nil)
	}
	return nil
}

func TestNodeAccessPassCommitmentV1ExactLayoutAndOriginScope(t *testing.T) {
	pass := bytes.Repeat([]byte{0x55}, NodeAccessPassSizeV1)
	got, err := NodeAccessPassCommitmentV1(wsAuthV3TestOrigin, pass)
	if err != nil {
		t.Fatal(err)
	}

	preimage := []byte("veil-node-access-pass-commitment-v1\x00")
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(wsAuthV3TestOrigin)))
	preimage = append(preimage, length[:]...)
	preimage = append(preimage, wsAuthV3TestOrigin...)
	preimage = append(preimage, pass...)
	want := sha256.Sum256(preimage)
	if got != want {
		t.Fatalf("Pass commitment mismatch:\n got %x\nwant %x", got, want)
	}

	otherOrigin, err := NodeAccessPassCommitmentV1("https://other.example.test:443", pass)
	if err != nil {
		t.Fatal(err)
	}
	if otherOrigin == got {
		t.Fatal("the same Pass produced the same commitment for two origins")
	}
	mutatedPass := append([]byte(nil), pass...)
	mutatedPass[0] ^= 1
	otherPass, err := NodeAccessPassCommitmentV1(wsAuthV3TestOrigin, mutatedPass)
	if err != nil {
		t.Fatal(err)
	}
	if otherPass == got {
		t.Fatal("mutating the Pass did not change its commitment")
	}

	for name, invalidPass := range map[string][]byte{
		"missing": nil,
		"short":   bytes.Repeat([]byte{1}, NodeAccessPassSizeV1-1),
		"long":    bytes.Repeat([]byte{1}, NodeAccessPassSizeV1+1),
		"zero":    make([]byte, NodeAccessPassSizeV1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NodeAccessPassCommitmentV1(wsAuthV3TestOrigin, invalidPass); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
	}
	for _, origin := range []string{
		"", "https://chat.example.test", "HTTPS://chat.example.test:443",
		"https://chat.example.test:443/path", "http://chat.example.test:80",
	} {
		if _, err := NodeAccessPassCommitmentV1(origin, pass); !errors.Is(err, ErrInvalidWSAuthV3) {
			t.Fatalf("origin %q error = %v, want ErrInvalidWSAuthV3", origin, err)
		}
	}
}

func TestWSAuthV3ExactContextAndProofLayouts(t *testing.T) {
	input := newWSAuthV3TestInput(t, WSAuthRegistrationCreateWithPassV3)
	fixture := signedWSAuthV3TestFixture(t, input)

	context, err := WSAuthV3Context(input)
	if err != nil {
		t.Fatal(err)
	}
	wantContext := []byte("veil-ws-auth-v3/context\x00")
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(input.CanonicalOrigin)))
	wantContext = append(wantContext, length[:]...)
	wantContext = append(wantContext, input.CanonicalOrigin...)
	wantContext = append(wantContext, input.ServerEphemeral[:]...)
	wantContext = append(wantContext, input.AccountIdentityKey[:]...)
	wantContext = append(wantContext, input.AccountSigningKey[:]...)
	wantContext = append(wantContext, input.DeviceID[:]...)
	wantContext = append(wantContext, input.VerifiedBindingCommitment[:]...)
	wantContext = append(wantContext, byte(input.RegistrationIntent))
	wantContext = append(wantContext, input.PassCommitment[:]...)
	if !bytes.Equal(context, wantContext) {
		t.Fatalf("context mismatch:\n got %x\nwant %x", context, wantContext)
	}

	wantAccount := []byte("veil-ws-auth-v3/account-proof\x00")
	binary.BigEndian.PutUint32(length[:], uint32(len(context)))
	wantAccount = append(wantAccount, length[:]...)
	wantAccount = append(wantAccount, context...)
	wantAccount = append(wantAccount, fixture.accountShared...)
	if !bytes.Equal(fixture.accountMessage, wantAccount) {
		t.Fatalf("account proof message mismatch:\n got %x\nwant %x", fixture.accountMessage, wantAccount)
	}

	wantDevice := []byte("veil-ws-auth-v3/device-proof\x00")
	wantDevice = append(wantDevice, length[:]...)
	wantDevice = append(wantDevice, context...)
	wantDevice = append(wantDevice, fixture.deviceShared...)
	wantDevice = append(wantDevice, fixture.accountProof...)
	if !bytes.Equal(fixture.deviceMessage, wantDevice) {
		t.Fatalf("device proof message mismatch:\n got %x\nwant %x", fixture.deviceMessage, wantDevice)
	}

	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		fixture.accountProof, fixture.deviceProof,
	); err != nil {
		t.Fatalf("valid chained proofs rejected: %v", err)
	}
}

func TestWSAuthV3IntentAndFixedFieldValidation(t *testing.T) {
	for _, intent := range []WSAuthRegistrationIntentV3{
		WSAuthRegistrationExistingOnlyV3,
		WSAuthRegistrationCreateOpenV3,
		WSAuthRegistrationCreateWithPassV3,
	} {
		if _, err := WSAuthV3Context(newWSAuthV3TestInput(t, intent)); err != nil {
			t.Fatalf("valid intent %d rejected: %v", intent, err)
		}
	}

	base := newWSAuthV3TestInput(t, WSAuthRegistrationCreateOpenV3)
	passCommitment := newWSAuthV3TestInput(t, WSAuthRegistrationCreateWithPassV3).PassCommitment
	invalid := map[string]WSAuthContextV3Input{}
	value := base
	value.RegistrationIntent = 0
	invalid["missing intent"] = value
	value = base
	value.RegistrationIntent = 4
	invalid["future intent"] = value
	value = base
	value.PassCommitment = passCommitment
	invalid["open with Pass commitment"] = value
	value = base
	value.RegistrationIntent = WSAuthRegistrationExistingOnlyV3
	value.PassCommitment = passCommitment
	invalid["existing with Pass commitment"] = value
	value = base
	value.RegistrationIntent = WSAuthRegistrationCreateWithPassV3
	invalid["Pass intent without commitment"] = value
	value = base
	value.ServerEphemeral = [32]byte{}
	invalid["zero server key"] = value
	value = base
	value.AccountIdentityKey = [32]byte{}
	invalid["zero account X25519 key"] = value
	value = base
	value.AccountSigningKey = [32]byte{}
	invalid["zero account Ed25519 key"] = value
	value = base
	value.AccountSigningKey = repeated32(0xff)
	invalid["non-canonical account Ed25519 key"] = value
	value = base
	value.DeviceID = [16]byte{}
	invalid["zero device id"] = value
	value = base
	value.VerifiedBindingCommitment = [32]byte{}
	invalid["zero verified binding commitment"] = value

	for name, input := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := WSAuthV3Context(input); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
	}
}

func TestWSAuthV3RejectsProofBoundsAndZeroValues(t *testing.T) {
	input := newWSAuthV3TestInput(t, WSAuthRegistrationCreateOpenV3)
	fixture := signedWSAuthV3TestFixture(t, input)

	for name, shared := range map[string][]byte{
		"missing": nil,
		"short":   bytes.Repeat([]byte{1}, WSAuthV3SharedSecretSize-1),
		"long":    bytes.Repeat([]byte{1}, WSAuthV3SharedSecretSize+1),
		"zero":    make([]byte, WSAuthV3SharedSecretSize),
	} {
		t.Run("account shared "+name, func(t *testing.T) {
			if _, err := WSAuthV3AccountProofMessage(input, shared); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
		t.Run("device shared "+name, func(t *testing.T) {
			if _, err := WSAuthV3DeviceProofMessage(input, shared, fixture.accountProof); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
	}
	for name, signature := range map[string][]byte{
		"missing": nil,
		"short":   bytes.Repeat([]byte{1}, ed25519.SignatureSize-1),
		"long":    bytes.Repeat([]byte{1}, ed25519.SignatureSize+1),
		"zero":    make([]byte, ed25519.SignatureSize),
	} {
		t.Run("account chain "+name, func(t *testing.T) {
			if _, err := WSAuthV3DeviceProofMessage(input, fixture.deviceShared, signature); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
	}

	zeroDeviceKey := [ed25519.PublicKeySize]byte{}
	if err := verifyWSAuthV3TestProofs(
		input, zeroDeviceKey, fixture.accountShared, fixture.deviceShared,
		fixture.accountProof, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("zero device key error = %v, want ErrInvalidWSAuthV3", err)
	}
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		make([]byte, ed25519.SignatureSize), fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("zero account proof error = %v, want ErrInvalidWSAuthV3", err)
	}
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		fixture.accountProof, make([]byte, ed25519.SignatureSize),
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("zero device proof error = %v, want ErrInvalidWSAuthV3", err)
	}
}

func TestWSAuthV3MutationsAndDomainsFailClosed(t *testing.T) {
	input := newWSAuthV3TestInput(t, WSAuthRegistrationCreateOpenV3)
	fixture := signedWSAuthV3TestFixture(t, input)

	otherAccountPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x91}, ed25519.SeedSize))
	otherAccountPublic := otherAccountPrivate.Public().(ed25519.PublicKey)
	var otherAccountKey [ed25519.PublicKeySize]byte
	copy(otherAccountKey[:], otherAccountPublic)

	mutations := map[string]func(*WSAuthContextV3Input){
		"origin": func(value *WSAuthContextV3Input) {
			value.CanonicalOrigin = "https://other.example.test:443"
		},
		"server ephemeral": func(value *WSAuthContextV3Input) {
			value.ServerEphemeral[0] ^= 1
		},
		"account X25519": func(value *WSAuthContextV3Input) {
			value.AccountIdentityKey[0] ^= 1
		},
		"account Ed25519": func(value *WSAuthContextV3Input) {
			value.AccountSigningKey = otherAccountKey
		},
		"device id": func(value *WSAuthContextV3Input) {
			value.DeviceID[0] ^= 1
		},
		"binding commitment": func(value *WSAuthContextV3Input) {
			value.VerifiedBindingCommitment[0] ^= 1
		},
		"intent": func(value *WSAuthContextV3Input) {
			value.RegistrationIntent = WSAuthRegistrationExistingOnlyV3
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := input
			mutate(&changed)
			if err := verifyWSAuthV3TestProofs(
				changed, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
				fixture.accountProof, fixture.deviceProof,
			); !errors.Is(err, ErrInvalidWSAuthV3) {
				t.Fatalf("mutated proof error = %v, want ErrInvalidWSAuthV3", err)
			}
		})
	}

	passInput := newWSAuthV3TestInput(t, WSAuthRegistrationCreateWithPassV3)
	passFixture := signedWSAuthV3TestFixture(t, passInput)
	passInput.PassCommitment[0] ^= 1
	if err := verifyWSAuthV3TestProofs(
		passInput, passFixture.devicePublic, passFixture.accountShared, passFixture.deviceShared,
		passFixture.accountProof, passFixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("mutated Pass commitment error = %v, want ErrInvalidWSAuthV3", err)
	}

	mutated := append([]byte(nil), fixture.accountShared...)
	mutated[0] ^= 1
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, mutated, fixture.deviceShared,
		fixture.accountProof, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("mutated account DH error = %v, want ErrInvalidWSAuthV3", err)
	}
	mutated = append([]byte(nil), fixture.deviceShared...)
	mutated[0] ^= 1
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, mutated,
		fixture.accountProof, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("mutated device DH error = %v, want ErrInvalidWSAuthV3", err)
	}

	mutatedAccountProof := append([]byte(nil), fixture.accountProof...)
	mutatedAccountProof[0] ^= 1
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		mutatedAccountProof, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("mutated account proof error = %v, want ErrInvalidWSAuthV3", err)
	}
	mutatedDeviceProof := append([]byte(nil), fixture.deviceProof...)
	mutatedDeviceProof[0] ^= 1
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		fixture.accountProof, mutatedDeviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("mutated device proof error = %v, want ErrInvalidWSAuthV3", err)
	}

	if ed25519.Verify(ed25519.PublicKey(input.AccountSigningKey[:]), fixture.deviceMessage, fixture.accountProof) {
		t.Fatal("account proof verified in the device proof domain")
	}
	if ed25519.Verify(ed25519.PublicKey(fixture.devicePublic[:]), fixture.accountMessage, fixture.deviceProof) {
		t.Fatal("device proof verified in the account proof domain")
	}
	mutatedDomain := append([]byte(nil), fixture.accountMessage...)
	mutatedDomain[0] ^= 1
	if ed25519.Verify(ed25519.PublicKey(input.AccountSigningKey[:]), mutatedDomain, fixture.accountProof) {
		t.Fatal("account proof accepted a mutated domain")
	}

	wrongDevicePrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, ed25519.SeedSize))
	wrongDevicePublicSlice := wrongDevicePrivate.Public().(ed25519.PublicKey)
	var wrongDevicePublic [ed25519.PublicKeySize]byte
	copy(wrongDevicePublic[:], wrongDevicePublicSlice)
	if err := verifyWSAuthV3TestProofs(
		input, wrongDevicePublic, fixture.accountShared, fixture.deviceShared,
		fixture.accountProof, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("wrong device key error = %v, want ErrInvalidWSAuthV3", err)
	}

	v2Message, err := WSAuthSigningMessage(input.ServerEphemeral[:], fixture.accountShared)
	if err != nil {
		t.Fatal(err)
	}
	v2Signature := ed25519.Sign(
		ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize)), v2Message,
	)
	if err := verifyWSAuthV3TestProofs(
		input, fixture.devicePublic, fixture.accountShared, fixture.deviceShared,
		v2Signature, fixture.deviceProof,
	); !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("v2 downgrade error = %v, want ErrInvalidWSAuthV3", err)
	}
}
