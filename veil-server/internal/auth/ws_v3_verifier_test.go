package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
	"golang.org/x/crypto/curve25519"
)

const wsAuthV3VerifierOrigin = "https://chat.example.test:443"

type wsAuthV3VerifierFixture struct {
	accountIdentityPrivate [32]byte
	accountIdentityPublic  [32]byte
	accountSigningPrivate  ed25519.PrivateKey
	accountSigningPublic   [32]byte
	deviceIdentityPrivate  [32]byte
	deviceIdentityPublic   [32]byte
	deviceSigningPrivate   ed25519.PrivateKey
	deviceSigningPublic    [32]byte
	deviceID               [16]byte
	binding                *DeviceBindingInput
	pass                   [32]byte
}

func newWSAuthV3VerifierFixture(t *testing.T) wsAuthV3VerifierFixture {
	t.Helper()
	var fixture wsAuthV3VerifierFixture
	copy(fixture.accountIdentityPrivate[:], bytes.Repeat([]byte{0x11}, 32))
	accountIdentityPublic, err := curve25519.X25519(fixture.accountIdentityPrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(fixture.accountIdentityPublic[:], accountIdentityPublic)
	accountSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x21}, ed25519.SeedSize))
	fixture.accountSigningPrivate = accountSigningPrivate
	copy(fixture.accountSigningPublic[:], accountSigningPrivate.Public().(ed25519.PublicKey))

	copy(fixture.deviceIdentityPrivate[:], bytes.Repeat([]byte{0x31}, 32))
	deviceIdentityPublic, err := curve25519.X25519(fixture.deviceIdentityPrivate[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(fixture.deviceIdentityPublic[:], deviceIdentityPublic)
	deviceSigningPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	fixture.deviceSigningPrivate = deviceSigningPrivate
	copy(fixture.deviceSigningPublic[:], deviceSigningPrivate.Public().(ed25519.PublicKey))
	copy(fixture.deviceID[:], bytes.Repeat([]byte{0x51}, 16))
	copy(fixture.pass[:], bytes.Repeat([]byte{0x61}, 32))

	fixture.binding = &DeviceBindingInput{
		DeviceKey:         fixture.deviceID[:],
		DeviceIdentityKey: fixture.deviceIdentityPublic[:],
		DeviceSigningKey:  fixture.deviceSigningPublic[:],
		Version:           1,
		Capabilities:      db.RequiredChannelCapabilities,
		Status:            db.DeviceBindingActive,
	}
	bindingMessage, err := DeviceBindingSigningMessage(
		fixture.accountIdentityPublic[:], fixture.accountSigningPublic[:], fixture.binding,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.binding.AccountSignature = ed25519.Sign(fixture.accountSigningPrivate, bindingMessage)
	return fixture
}

func (fixture wsAuthV3VerifierFixture) response(
	t *testing.T,
	challenge ChallengeV3,
	intent WSAuthRegistrationIntentV3,
	proofOrigin string,
) WSAuthV3ResponseInput {
	t.Helper()
	if proofOrigin == "" {
		proofOrigin = challenge.CanonicalOrigin
	}
	binding := cloneWSAuthV3TestBinding(fixture.binding)
	bindingCommitment, err := verifyAccountSignedDeviceBinding(&db.User{
		IdentityKey: fixture.accountIdentityPublic[:],
		SigningKey:  fixture.accountSigningPublic[:],
	}, binding)
	if err != nil {
		t.Fatal(err)
	}
	var passCommitment [32]byte
	var pass []byte
	if intent == WSAuthRegistrationCreateWithPassV3 {
		pass = append([]byte(nil), fixture.pass[:]...)
		passCommitment, err = NodeAccessPassCommitmentV1(proofOrigin, pass)
		if err != nil {
			t.Fatal(err)
		}
	}
	contractInput := WSAuthContextV3Input{
		CanonicalOrigin:           proofOrigin,
		ServerEphemeral:           challenge.ServerEphemeral,
		AccountIdentityKey:        fixture.accountIdentityPublic,
		AccountSigningKey:         fixture.accountSigningPublic,
		DeviceID:                  fixture.deviceID,
		VerifiedBindingCommitment: bindingCommitment,
		RegistrationIntent:        intent,
		PassCommitment:            passCommitment,
	}
	accountShared, err := curve25519.X25519(
		fixture.accountIdentityPrivate[:], challenge.ServerEphemeral[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	accountMessage, err := WSAuthV3AccountProofMessage(contractInput, accountShared)
	clear(accountShared)
	if err != nil {
		t.Fatal(err)
	}
	accountProof := ed25519.Sign(fixture.accountSigningPrivate, accountMessage)
	clear(accountMessage)

	deviceShared, err := curve25519.X25519(
		fixture.deviceIdentityPrivate[:], challenge.ServerEphemeral[:],
	)
	if err != nil {
		t.Fatal(err)
	}
	deviceMessage, err := WSAuthV3DeviceProofMessage(contractInput, deviceShared, accountProof)
	clear(deviceShared)
	if err != nil {
		t.Fatal(err)
	}
	deviceProof := ed25519.Sign(fixture.deviceSigningPrivate, deviceMessage)
	clear(deviceMessage)

	return WSAuthV3ResponseInput{
		ProtocolVersion:       WSAuthProtocolVersionV3,
		IdentityKey:           fixture.accountIdentityPublic[:],
		SigningKey:            fixture.accountSigningPublic[:],
		AccountProofSignature: accountProof,
		DeviceID:              fixture.deviceID[:],
		DeviceName:            "Pixel test",
		ClientVersion:         "veil-test/3",
		DeviceBinding:         binding,
		DeviceProofSignature:  deviceProof,
		RegistrationIntent:    intent,
		NodeAccessPass:        pass,
	}
}

type recordingWSAuthV3Store struct {
	mu        sync.Mutex
	requests  []db.WSAuthV3AdmissionRequest
	err       error
	before    func(db.WSAuthV3AdmissionRequest)
	mutate    func(*db.WSAuthV3AdmissionResult)
	nilResult bool
	passSeen  [32]byte
}

func (store *recordingWSAuthV3Store) AdmitWSAuthV3(
	_ context.Context,
	request db.WSAuthV3AdmissionRequest,
) (*db.WSAuthV3AdmissionResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.before != nil {
		store.before(request)
	}
	if len(request.NodeAccessPass) == len(store.passSeen) {
		copy(store.passSeen[:], request.NodeAccessPass)
	}
	captured := request
	captured.NodeAccessPass = append([]byte(nil), request.NodeAccessPass...)
	store.requests = append(store.requests, captured)
	if store.err != nil {
		return nil, store.err
	}
	if store.nilResult {
		return nil, nil
	}
	result := successfulWSAuthV3Admission(request)
	if store.mutate != nil {
		store.mutate(result)
	}
	return result, nil
}

func (store *recordingWSAuthV3Store) callCount() int {
	store.mu.Lock()
	defer store.mu.Unlock()
	return len(store.requests)
}

func (store *recordingWSAuthV3Store) lastRequest() db.WSAuthV3AdmissionRequest {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.requests[len(store.requests)-1]
}

func successfulWSAuthV3Admission(request db.WSAuthV3AdmissionRequest) *db.WSAuthV3AdmissionResult {
	const userID = "550e8400-e29b-41d4-a716-446655440000"
	const deviceID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	return &db.WSAuthV3AdmissionResult{
		User: &db.User{
			ID:          userID,
			IdentityKey: append([]byte(nil), request.AccountIdentityKey[:]...),
			SigningKey:  append([]byte(nil), request.AccountSigningKey[:]...),
			Username:    "user_test",
		},
		Device: &db.Device{
			ID:        deviceID,
			UserID:    userID,
			DeviceKey: append([]byte(nil), request.DeviceKey[:]...),
		},
		Binding: &db.DeviceBinding{
			DeviceID:          deviceID,
			UserID:            userID,
			DeviceKey:         append([]byte(nil), request.DeviceKey[:]...),
			DeviceIdentityKey: append([]byte(nil), request.DeviceIdentityKey[:]...),
			DeviceSigningKey:  append([]byte(nil), request.DeviceSigningKey[:]...),
			Version:           request.BindingVersion,
			Capabilities:      request.BindingCapabilities,
			Status:            request.BindingStatus,
			AccountSignature:  append([]byte(nil), request.BindingSignature[:]...),
			Commitment:        append([]byte(nil), request.BindingCommitment[:]...),
		},
		IsNew: request.Intent != db.WSAuthV3AdmissionExisting,
	}
}

func newWSAuthV3VerifierService(t *testing.T, store wsAuthV3AdmissionStore) *Service {
	t.Helper()
	origin, err := nodeorigin.ParseCanonical(wsAuthV3VerifierOrigin)
	if err != nil {
		t.Fatal(err)
	}
	service := NewService(nil, &config.Config{
		PublicOrigin:      origin,
		AuthChallengeTTL:  5 * time.Second,
		AllowRegistration: false,
	})
	service.wsAuthV3Store = store
	return service
}

func newWSAuthV3Attempt(
	t *testing.T,
	store wsAuthV3AdmissionStore,
	intent WSAuthRegistrationIntentV3,
) (*Service, WSAuthV3ResponseInput) {
	t.Helper()
	service := newWSAuthV3VerifierService(t, store)
	challenge, err := service.CreateChallengeV3(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	return service, newWSAuthV3VerifierFixture(t).response(t, challenge, intent, "")
}

func requireWSAuthV3Failure(t *testing.T, err error, reason WSAuthV3FailureReason) {
	t.Helper()
	var failure *WSAuthV3Failure
	if !errors.As(err, &failure) || failure.Reason() != reason {
		t.Fatalf("error = %#v, want WSAuthV3Failure reason %d", err, reason)
	}
}

func cloneWSAuthV3TestBinding(binding *DeviceBindingInput) *DeviceBindingInput {
	if binding == nil {
		return nil
	}
	clone := *binding
	clone.DeviceKey = append([]byte(nil), binding.DeviceKey...)
	clone.DeviceIdentityKey = append([]byte(nil), binding.DeviceIdentityKey...)
	clone.DeviceSigningKey = append([]byte(nil), binding.DeviceSigningKey...)
	clone.AccountSignature = append([]byte(nil), binding.AccountSignature...)
	return &clone
}

func cloneWSAuthV3TestResponse(response WSAuthV3ResponseInput) WSAuthV3ResponseInput {
	clone := response
	clone.IdentityKey = append([]byte(nil), response.IdentityKey...)
	clone.SigningKey = append([]byte(nil), response.SigningKey...)
	clone.AccountProofSignature = append([]byte(nil), response.AccountProofSignature...)
	clone.DeviceID = append([]byte(nil), response.DeviceID...)
	clone.DeviceBinding = cloneWSAuthV3TestBinding(response.DeviceBinding)
	clone.DeviceProofSignature = append([]byte(nil), response.DeviceProofSignature...)
	clone.NodeAccessPass = append([]byte(nil), response.NodeAccessPass...)
	return clone
}

func TestVerifyResponseV3AcceptsExactChainedProofsForEveryIntent(t *testing.T) {
	for _, intent := range []WSAuthRegistrationIntentV3{
		WSAuthRegistrationExistingOnlyV3,
		WSAuthRegistrationCreateOpenV3,
		WSAuthRegistrationCreateWithPassV3,
	} {
		t.Run(string(rune('0'+intent)), func(t *testing.T) {
			store := &recordingWSAuthV3Store{}
			service, response := newWSAuthV3Attempt(t, store, intent)
			var expectedPass [32]byte
			if len(response.NodeAccessPass) == len(expectedPass) {
				copy(expectedPass[:], response.NodeAccessPass)
			}
			result, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			if err != nil {
				t.Fatal(err)
			}
			principal := result.Principal()
			if principal.UserID != "550e8400-e29b-41d4-a716-446655440000" ||
				!principal.PerDeviceSecure || principal.DeviceBindingVersion != 1 ||
				principal.DeviceBindingStatus != db.DeviceBindingActive ||
				result.ProtocolVersion() != WSAuthProtocolVersionV3 ||
				result.CanonicalOrigin() != wsAuthV3VerifierOrigin ||
				result.RegistrationIntent() != intent {
				t.Fatalf("unexpected v3 result: %#v", result)
			}
			principal.UserID = "caller mutation"
			if result.Principal().UserID != "550e8400-e29b-41d4-a716-446655440000" {
				t.Fatal("principal getter exposed mutable verified-result state")
			}
			if store.callCount() != 1 {
				t.Fatalf("store calls = %d, want 1", store.callCount())
			}
			request := store.lastRequest()
			if request.Intent != db.WSAuthV3AdmissionIntent(intent) ||
				request.AllowOpenRegistration || request.BindingStatus != db.DeviceBindingActive {
				t.Fatalf("unexpected admission request: %#v", request)
			}
			if intent == WSAuthRegistrationCreateWithPassV3 {
				if store.passSeen != expectedPass || !bytes.Equal(request.NodeAccessPass, expectedPass[:]) {
					t.Fatal("Pass admission did not consume the verifier-owned exact Pass")
				}
			} else if len(request.NodeAccessPass) != 0 {
				t.Fatal("non-Pass admission carried a Pass")
			}
			if !bytes.Equal(response.NodeAccessPass, make([]byte, len(response.NodeAccessPass))) {
				t.Fatal("decoded Pass was not cleared after successful verification")
			}

			_, err = service.VerifyResponseV3(context.Background(), t.Name(), response)
			requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
			if store.callCount() != 1 {
				t.Fatalf("replayed response reached store: calls=%d", store.callCount())
			}
		})
	}
}

func TestVerifyResponseV3RejectsEveryMalformedOrMutatedSecurityFieldBeforeStore(t *testing.T) {
	tests := map[string]func(*WSAuthV3ResponseInput){
		"protocol version":     func(value *WSAuthV3ResponseInput) { value.ProtocolVersion = 2 },
		"account identity":     func(value *WSAuthV3ResponseInput) { value.IdentityKey[0] ^= 1 },
		"account signing key":  func(value *WSAuthV3ResponseInput) { clear(value.SigningKey) },
		"account proof":        func(value *WSAuthV3ResponseInput) { value.AccountProofSignature[0] ^= 1 },
		"device id":            func(value *WSAuthV3ResponseInput) { value.DeviceID[0] ^= 1 },
		"binding device id":    func(value *WSAuthV3ResponseInput) { value.DeviceBinding.DeviceKey[0] ^= 1 },
		"binding identity key": func(value *WSAuthV3ResponseInput) { value.DeviceBinding.DeviceIdentityKey[0] ^= 1 },
		"binding signing key":  func(value *WSAuthV3ResponseInput) { value.DeviceBinding.DeviceSigningKey[0] ^= 1 },
		"binding version":      func(value *WSAuthV3ResponseInput) { value.DeviceBinding.Version++ },
		"binding capabilities": func(value *WSAuthV3ResponseInput) {
			value.DeviceBinding.Capabilities = 0
		},
		"binding status": func(value *WSAuthV3ResponseInput) {
			value.DeviceBinding.Status = db.DeviceBindingExcluded
		},
		"binding signature":   func(value *WSAuthV3ResponseInput) { value.DeviceBinding.AccountSignature[0] ^= 1 },
		"device proof":        func(value *WSAuthV3ResponseInput) { value.DeviceProofSignature[0] ^= 1 },
		"registration intent": func(value *WSAuthV3ResponseInput) { value.RegistrationIntent = 4 },
		"Pass after signing":  func(value *WSAuthV3ResponseInput) { value.NodeAccessPass[0] ^= 1 },
		"device name":         func(value *WSAuthV3ResponseInput) { value.DeviceName = "bad\nname" },
		"client version":      func(value *WSAuthV3ResponseInput) { value.ClientVersion = "veil/\u0080" },
		"short account proof": func(value *WSAuthV3ResponseInput) {
			value.AccountProofSignature = value.AccountProofSignature[:63]
		},
		"non-Pass bearer": func(value *WSAuthV3ResponseInput) {
			value.RegistrationIntent = WSAuthRegistrationExistingOnlyV3
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := &recordingWSAuthV3Store{}
			service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationCreateWithPassV3)
			mutate(&response)
			_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
			if store.callCount() != 0 {
				t.Fatalf("invalid proof reached admission store: calls=%d", store.callCount())
			}
		})
	}
}

func TestVerifyResponseV3RejectsOtherOriginAndLegacyProofBytes(t *testing.T) {
	fixture := newWSAuthV3VerifierFixture(t)
	for name, mutate := range map[string]func(t *testing.T, challenge ChallengeV3, response *WSAuthV3ResponseInput){
		"other origin": func(_ *testing.T, _ ChallengeV3, _ *WSAuthV3ResponseInput) {},
		"legacy v2 account signature": func(t *testing.T, challenge ChallengeV3, response *WSAuthV3ResponseInput) {
			shared, err := curve25519.X25519(fixture.accountIdentityPrivate[:], challenge.ServerEphemeral[:])
			if err != nil {
				t.Fatal(err)
			}
			legacy, err := WSAuthSigningMessage(challenge.ServerEphemeral[:], shared)
			clear(shared)
			if err != nil {
				t.Fatal(err)
			}
			response.AccountProofSignature = ed25519.Sign(fixture.accountSigningPrivate, legacy)
			clear(legacy)
		},
	} {
		t.Run(name, func(t *testing.T) {
			store := &recordingWSAuthV3Store{}
			service := newWSAuthV3VerifierService(t, store)
			challenge, err := service.CreateChallengeV3(t.Name())
			if err != nil {
				t.Fatal(err)
			}
			proofOrigin := ""
			if name == "other origin" {
				proofOrigin = "https://other.example.test:443"
			}
			response := fixture.response(t, challenge, WSAuthRegistrationCreateWithPassV3, proofOrigin)
			mutate(t, challenge, &response)
			_, err = service.VerifyResponseV3(context.Background(), t.Name(), response)
			requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
			if store.callCount() != 0 {
				t.Fatal("cross-origin or legacy proof reached admission store")
			}
		})
	}
}

func TestVerifyResponseV3MapsOnlyCoherentPostProofAdmissionFailures(t *testing.T) {
	tests := []struct {
		name       string
		intent     WSAuthRegistrationIntentV3
		storeError error
		wantPublic WSAuthV3FailureReason
	}{
		{name: "identity absent", intent: WSAuthRegistrationExistingOnlyV3, storeError: db.ErrWSAuthV3IdentityAbsent, wantPublic: WSAuthV3AuthenticationFailed},
		{name: "admission conflict", intent: WSAuthRegistrationCreateWithPassV3, storeError: db.ErrWSAuthV3AdmissionRejected, wantPublic: WSAuthV3AuthenticationFailed},
		{name: "open registration closed", intent: WSAuthRegistrationCreateOpenV3, storeError: db.ErrWSAuthV3RegistrationClosed, wantPublic: WSAuthV3RegistrationClosed},
		{name: "Pass invalid", intent: WSAuthRegistrationCreateWithPassV3, storeError: db.ErrNodeAccessInviteInvalid, wantPublic: WSAuthV3NodeAccessPassInvalid},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			store := &recordingWSAuthV3Store{err: testCase.storeError}
			service, response := newWSAuthV3Attempt(t, store, testCase.intent)
			_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			requireWSAuthV3Failure(t, err, testCase.wantPublic)
			if store.callCount() != 1 {
				t.Fatalf("post-proof store calls = %d, want 1", store.callCount())
			}
		})
	}

	for name, testCase := range map[string]struct {
		intent WSAuthRegistrationIntentV3
		err    error
	}{
		"storage outage":                 {intent: WSAuthRegistrationExistingOnlyV3, err: errors.New("storage unavailable")},
		"incoherent registration closed": {intent: WSAuthRegistrationCreateWithPassV3, err: db.ErrWSAuthV3RegistrationClosed},
		"incoherent Pass invalid":        {intent: WSAuthRegistrationCreateOpenV3, err: db.ErrNodeAccessInviteInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			store := &recordingWSAuthV3Store{err: testCase.err}
			service, response := newWSAuthV3Attempt(t, store, testCase.intent)
			_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			var failure *WSAuthV3Failure
			if err == nil || errors.As(err, &failure) {
				t.Fatalf("operational error became a public auth classification: %#v", err)
			}
		})
	}
}

func TestVerifyResponseV3ConcurrentConsumersGetOneStoreAdmission(t *testing.T) {
	store := &recordingWSAuthV3Store{}
	service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationCreateWithPassV3)
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		attempt := cloneWSAuthV3TestResponse(response)
		go func() {
			<-start
			_, err := service.VerifyResponseV3(context.Background(), t.Name(), attempt)
			results <- err
		}()
	}
	close(start)
	var successes, failures int
	for range 2 {
		err := <-results
		if err == nil {
			successes++
		} else {
			requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
			failures++
		}
	}
	if successes != 1 || failures != 1 || store.callCount() != 1 {
		t.Fatalf("concurrent v3 results: success=%d failure=%d store=%d", successes, failures, store.callCount())
	}
}

func TestVerifyResponseV3OwnsParsedSecurityFieldsBeforeAdmission(t *testing.T) {
	fixture := newWSAuthV3VerifierFixture(t)
	var response WSAuthV3ResponseInput
	store := &recordingWSAuthV3Store{}
	store.before = func(request db.WSAuthV3AdmissionRequest) {
		// Mutate every caller-owned alias after proof verification but while the
		// synchronous admission call is in progress. The request must already be
		// built entirely from verifier-owned fixed arrays.
		clear(response.AccountProofSignature)
		clear(response.DeviceProofSignature)
		clear(response.DeviceBinding.DeviceKey)
		clear(response.DeviceBinding.DeviceIdentityKey)
		clear(response.DeviceBinding.DeviceSigningKey)
		clear(response.DeviceBinding.AccountSignature)
		clear(response.NodeAccessPass)
		if request.AccountIdentityKey != fixture.accountIdentityPublic ||
			request.DeviceKey != fixture.deviceID ||
			request.DeviceIdentityKey != fixture.deviceIdentityPublic ||
			request.DeviceSigningKey != fixture.deviceSigningPublic {
			t.Fatal("admission request retained caller-owned key aliases")
		}
	}
	service := newWSAuthV3VerifierService(t, store)
	challenge, err := service.CreateChallengeV3(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	response = fixture.response(t, challenge, WSAuthRegistrationCreateWithPassV3, "")
	result, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
	if err != nil || result == nil {
		t.Fatalf("owned parsed proof rejected: result=%#v err=%v", result, err)
	}
	if store.passSeen != fixture.pass {
		t.Fatalf("admission observed Pass %x, want original %x", store.passSeen, fixture.pass)
	}
	if !bytes.Equal(response.NodeAccessPass, make([]byte, len(response.NodeAccessPass))) {
		t.Fatal("caller-owned Pass was not cleared on verifier return")
	}
}

func TestVerifyResponseV3FailsClosedOnTypedNilStoreAndInconsistentResult(t *testing.T) {
	var nilStore *recordingWSAuthV3Store
	service, response := newWSAuthV3Attempt(t, nilStore, WSAuthRegistrationExistingOnlyV3)
	_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
	var failure *WSAuthV3Failure
	if err == nil || errors.As(err, &failure) {
		t.Fatalf("typed-nil store error = %#v, want non-public operational failure", err)
	}

	store := &recordingWSAuthV3Store{mutate: func(result *db.WSAuthV3AdmissionResult) {
		result.IsNew = true
	}}
	service, response = newWSAuthV3Attempt(t, store, WSAuthRegistrationExistingOnlyV3)
	_, err = service.VerifyResponseV3(context.Background(), t.Name(), response)
	if err == nil || errors.As(err, &failure) {
		t.Fatalf("EXISTING/new store result error = %#v, want non-public operational failure", err)
	}
}

func TestVerifyResponseV3RejectsCompleteInconsistentStoreResultMatrix(t *testing.T) {
	mutations := map[string]func(*db.WSAuthV3AdmissionResult){
		"nil user": func(result *db.WSAuthV3AdmissionResult) { result.User = nil },
		"nil device": func(result *db.WSAuthV3AdmissionResult) {
			result.Device = nil
		},
		"nil binding": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding = nil
		},
		"invalid user UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.User.ID = "not-a-uuid"
		},
		"nil user UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.User.ID = "00000000-0000-0000-0000-000000000000"
		},
		"noncanonical user UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.User.ID = "550E8400-E29B-41D4-A716-446655440000"
		},
		"invalid device UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.Device.ID = "not-a-uuid"
		},
		"nil device UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.Device.ID = "00000000-0000-0000-0000-000000000000"
		},
		"noncanonical device UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.Device.ID = "6BA7B810-9DAD-11D1-80B4-00C04FD430C8"
		},
		"empty username": func(result *db.WSAuthV3AdmissionResult) {
			result.User.Username = ""
		},
		"account identity key": func(result *db.WSAuthV3AdmissionResult) {
			result.User.IdentityKey[0] ^= 1
		},
		"account signing key": func(result *db.WSAuthV3AdmissionResult) {
			result.User.SigningKey[0] ^= 1
		},
		"device owner": func(result *db.WSAuthV3AdmissionResult) {
			result.Device.UserID = "550e8400-e29b-41d4-a716-446655440001"
		},
		"device key": func(result *db.WSAuthV3AdmissionResult) {
			result.Device.DeviceKey[0] ^= 1
		},
		"binding owner": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.UserID = "550e8400-e29b-41d4-a716-446655440001"
		},
		"binding device UUID": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.DeviceID = "6ba7b810-9dad-11d1-80b4-00c04fd430c9"
		},
		"binding device key": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.DeviceKey[0] ^= 1
		},
		"binding identity key": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.DeviceIdentityKey[0] ^= 1
		},
		"binding signing key": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.DeviceSigningKey[0] ^= 1
		},
		"binding version": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.Version++
		},
		"binding capabilities": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.Capabilities = 0
		},
		"binding status": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.Status = db.DeviceBindingExcluded
		},
		"binding account signature": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.AccountSignature[0] ^= 1
		},
		"binding commitment": func(result *db.WSAuthV3AdmissionResult) {
			result.Binding.Commitment[0] ^= 1
		},
	}
	tests := map[string]*recordingWSAuthV3Store{
		"nil admission": {nilResult: true},
	}
	for name, mutate := range mutations {
		tests[name] = &recordingWSAuthV3Store{mutate: mutate}
	}
	for name, store := range tests {
		t.Run(name, func(t *testing.T) {
			service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationExistingOnlyV3)
			result, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			var failure *WSAuthV3Failure
			if err == nil || result != nil || errors.As(err, &failure) {
				t.Fatalf("inconsistent store result=%#v err=%#v, want nil non-public operational failure", result, err)
			}
			if store.callCount() != 1 {
				t.Fatalf("store calls = %d, want 1", store.callCount())
			}
		})
	}
}

func TestVerifyResponseV3AllowsExistingResolutionForCreationIntents(t *testing.T) {
	for _, intent := range []WSAuthRegistrationIntentV3{
		WSAuthRegistrationCreateOpenV3,
		WSAuthRegistrationCreateWithPassV3,
	} {
		t.Run(string(rune('0'+intent)), func(t *testing.T) {
			store := &recordingWSAuthV3Store{mutate: func(result *db.WSAuthV3AdmissionResult) {
				result.IsNew = false
			}}
			service, response := newWSAuthV3Attempt(t, store, intent)
			result, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
			if err != nil || result.Principal().IsNew {
				t.Fatalf("existing resolution result=%#v err=%v", result, err)
			}
		})
	}
}

func TestVerifyResponseV3ClearsDecodedPassWhenChallengeIsAlreadyGone(t *testing.T) {
	store := &recordingWSAuthV3Store{}
	service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationCreateWithPassV3)
	service.RemoveChallenge(t.Name())
	_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
	requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
	if !bytes.Equal(response.NodeAccessPass, make([]byte, len(response.NodeAccessPass))) {
		t.Fatal("decoded Pass survived the early missing-challenge failure")
	}
	if store.callCount() != 0 {
		t.Fatal("missing challenge reached admission store")
	}
}

func TestVerifyResponseV3RejectsNilContextBeforeProofOrStore(t *testing.T) {
	store := &recordingWSAuthV3Store{}
	service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationCreateWithPassV3)
	//lint:ignore SA1012 This boundary test deliberately verifies fail-closed nil handling.
	_, err := service.VerifyResponseV3(nil, t.Name(), response)
	var failure *WSAuthV3Failure
	if err == nil || errors.As(err, &failure) {
		t.Fatalf("nil context error = %#v, want non-public operational failure", err)
	}
	if store.callCount() != 0 {
		t.Fatal("nil context reached admission store")
	}
	if !bytes.Equal(response.NodeAccessPass, make([]byte, len(response.NodeAccessPass))) {
		t.Fatal("decoded Pass survived the nil-context failure")
	}
}

func TestVerifyResponseV3ConsumesChallengeAndFailsClosedIfConfigDisappears(t *testing.T) {
	store := &recordingWSAuthV3Store{}
	service, response := newWSAuthV3Attempt(t, store, WSAuthRegistrationCreateWithPassV3)
	service.cfg = nil
	_, err := service.VerifyResponseV3(context.Background(), t.Name(), response)
	requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
	if store.callCount() != 0 {
		t.Fatal("missing config reached admission store")
	}
	if !bytes.Equal(response.NodeAccessPass, make([]byte, len(response.NodeAccessPass))) {
		t.Fatal("decoded Pass survived the missing-config failure")
	}
	_, err = service.VerifyResponseV3(context.Background(), t.Name(), response)
	requireWSAuthV3Failure(t, err, WSAuthV3AuthenticationFailed)
}

func TestWSAuthV3AdmissionIntentMappingIsExplicit(t *testing.T) {
	tests := map[string]struct {
		input WSAuthRegistrationIntentV3
		want  db.WSAuthV3AdmissionIntent
	}{
		"existing": {input: WSAuthRegistrationExistingOnlyV3, want: db.WSAuthV3AdmissionExisting},
		"open":     {input: WSAuthRegistrationCreateOpenV3, want: db.WSAuthV3AdmissionOpen},
		"Pass":     {input: WSAuthRegistrationCreateWithPassV3, want: db.WSAuthV3AdmissionPass},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := wsAuthV3AdmissionIntent(test.input)
			if err != nil || got != test.want {
				t.Fatalf("mapping = %d, %v; want %d, nil", got, err, test.want)
			}
		})
	}
	if got, err := wsAuthV3AdmissionIntent(0xff); got != 0 || !errors.Is(err, ErrInvalidWSAuthV3) {
		t.Fatalf("unknown mapping = %d, %v; want zero, ErrInvalidWSAuthV3", got, err)
	}
}
