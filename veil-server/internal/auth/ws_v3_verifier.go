package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"golang.org/x/crypto/curve25519"

	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/NaveLIL/veil/veil-server/internal/db"
)

// WSAuthV3FailureReason is the complete public-safe rejection vocabulary for
// the isolated v3 verifier. It intentionally does not contain database,
// constraint, key-shape or proof-detail reasons.
type WSAuthV3FailureReason uint8

const (
	WSAuthV3AuthenticationFailed  WSAuthV3FailureReason = 1
	WSAuthV3RegistrationClosed    WSAuthV3FailureReason = 2
	WSAuthV3NodeAccessPassInvalid WSAuthV3FailureReason = 3
)

// WSAuthV3Failure is safe to classify across a future transport boundary. Its
// Error string is fixed and non-secret; Cause remains private diagnostic state
// and must never be rendered to a peer.
type WSAuthV3Failure struct {
	reason WSAuthV3FailureReason
	cause  error
}

func (failure *WSAuthV3Failure) Error() string {
	if failure == nil {
		return "WebSocket authentication failed"
	}
	switch failure.reason {
	case WSAuthV3RegistrationClosed:
		return "Node registration is closed"
	case WSAuthV3NodeAccessPassInvalid:
		return "Node Access Pass is invalid"
	default:
		return "WebSocket authentication failed"
	}
}

func (failure *WSAuthV3Failure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *WSAuthV3Failure) Reason() WSAuthV3FailureReason {
	if failure == nil {
		return 0
	}
	return failure.reason
}

// WSAuthV3ResponseInput is the transport-neutral representation of a
// canonically decoded AuthResponseV3. A future protobuf adapter must enforce
// raw-wire canonicality before constructing this value.
type WSAuthV3ResponseInput struct {
	ProtocolVersion       uint32
	IdentityKey           []byte
	SigningKey            []byte
	AccountProofSignature []byte
	DeviceID              []byte
	DeviceName            string
	ClientVersion         string
	DeviceBinding         *DeviceBindingInput
	DeviceProofSignature  []byte
	RegistrationIntent    WSAuthRegistrationIntentV3
	NodeAccessPass        []byte
}

// WSAuthV3VerifiedResult is the opaque success product of one consumed v3
// proof attempt. Its principal and result expectation are copied from that
// exact attempt; callers cannot replace the protocol, origin or signed intent
// with independently reconstructed values. It deliberately retains no raw
// Pass, proof signature, DH secret, or account-signed binding bytes.
type WSAuthV3VerifiedResult struct {
	principal          AuthResult
	protocolVersion    uint32
	canonicalOrigin    string
	registrationIntent WSAuthRegistrationIntentV3
}

// Principal returns a copy of the authenticated durable principal.
func (result *WSAuthV3VerifiedResult) Principal() AuthResult {
	if result == nil {
		return AuthResult{}
	}
	return result.principal
}

func (result *WSAuthV3VerifiedResult) ProtocolVersion() uint32 {
	if result == nil {
		return 0
	}
	return result.protocolVersion
}

func (result *WSAuthV3VerifiedResult) CanonicalOrigin() string {
	if result == nil {
		return ""
	}
	return result.canonicalOrigin
}

func (result *WSAuthV3VerifiedResult) RegistrationIntent() WSAuthRegistrationIntentV3 {
	if result == nil {
		return 0
	}
	return result.registrationIntent
}

type wsAuthV3AdmissionStore interface {
	AdmitWSAuthV3(context.Context, db.WSAuthV3AdmissionRequest) (*db.WSAuthV3AdmissionResult, error)
}

// VerifyResponseV3 consumes one origin-bound v3 challenge, verifies the
// account-signed binding and chained account/device possession proofs in that
// order, then asks the durable store for one atomic admission outcome.
//
// This method has no protobuf or gateway call site. In particular, its
// existence does not activate WebSocket v3 on /ws.
func (s *Service) VerifyResponseV3(ctx context.Context, connID string, response WSAuthV3ResponseInput) (*WSAuthV3VerifiedResult, error) {
	// The transport owns this decoded bearer buffer, but the verifier is its
	// last consumer. Clear it even when the challenge is missing or malformed.
	defer clear(response.NodeAccessPass)
	if s == nil {
		return nil, errors.New("WebSocket auth v3 service is unavailable")
	}
	if ctx == nil {
		return nil, errors.New("WebSocket auth v3 context is unavailable")
	}

	// A selected v3 response gets exactly one use of the challenge, including
	// malformed or wrong-version responses. A retry starts a fresh connection
	// and receives a fresh server ephemeral.
	challenge, err := s.takeChallenge(connID)
	if err != nil {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	}
	defer clear(challenge.private[:])

	if s.cfg == nil || s.cfg.PublicOrigin.IsZero() ||
		challenge.canonicalOrigin != s.cfg.PublicOrigin.String() {
		return nil, fmt.Errorf("WebSocket auth v3 configured origin mismatch: %w", ErrPublicOriginRequired)
	}
	if response.ProtocolVersion != WSAuthProtocolVersionV3 ||
		allZeroWSAuthV3(challenge.public[:]) {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrInvalidWSAuthV3)
	}

	parsed, err := parseWSAuthV3Response(response, challenge)
	if err != nil {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	}
	defer parsed.clear()

	// The binding signature must be accepted before its commitment is allowed
	// into either v3 proof context.
	verifiedBinding := parsed.bindingInput()
	bindingCommitment, err := verifyAccountSignedDeviceBinding(&db.User{
		IdentityKey: parsed.accountIdentityKey[:],
		SigningKey:  parsed.accountSigningKey[:],
	}, verifiedBinding)
	if err != nil || allZeroWSAuthV3(bindingCommitment[:]) {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrBadDeviceBindingSig)
	}
	parsed.bindingCommitment = bindingCommitment

	contractInput := WSAuthContextV3Input{
		CanonicalOrigin:           challenge.canonicalOrigin,
		ServerEphemeral:           challenge.public,
		AccountIdentityKey:        parsed.accountIdentityKey,
		AccountSigningKey:         parsed.accountSigningKey,
		DeviceID:                  parsed.deviceID,
		VerifiedBindingCommitment: parsed.bindingCommitment,
		RegistrationIntent:        parsed.registrationIntent,
		PassCommitment:            parsed.passCommitment,
	}

	accountShared, err := curve25519.X25519(challenge.private[:], parsed.accountIdentityKey[:])
	if err != nil || len(accountShared) != WSAuthV3SharedSecretSize || allZeroWSAuthV3(accountShared) {
		clear(accountShared)
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrBadIdentityProof)
	}
	accountMessage, err := WSAuthV3AccountProofMessage(contractInput, accountShared)
	clear(accountShared)
	if err != nil {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	}
	accountProofOK := ed25519.Verify(
		ed25519.PublicKey(parsed.accountSigningKey[:]), accountMessage, parsed.accountProofSignature[:],
	)
	clear(accountMessage)
	if !accountProofOK {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrBadSignature)
	}

	// Only an already-verified account proof may be chained into the device
	// proof. No store or registration-policy operation occurs before both pass.
	deviceShared, err := curve25519.X25519(challenge.private[:], parsed.deviceIdentityKey[:])
	if err != nil || len(deviceShared) != WSAuthV3SharedSecretSize || allZeroWSAuthV3(deviceShared) {
		clear(deviceShared)
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrBadDeviceProof)
	}
	deviceMessage, err := WSAuthV3DeviceProofMessage(
		contractInput, deviceShared, parsed.accountProofSignature[:],
	)
	clear(deviceShared)
	if err != nil {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	}
	deviceProofOK := ed25519.Verify(
		ed25519.PublicKey(parsed.deviceSigningKey[:]), deviceMessage, parsed.deviceProofSignature[:],
	)
	clear(deviceMessage)
	if !deviceProofOK {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, ErrBadDeviceProof)
	}

	if nilWSAuthV3AdmissionStore(s.wsAuthV3Store) {
		return nil, errors.New("WebSocket auth v3 admission store is unavailable")
	}
	admissionIntent, err := wsAuthV3AdmissionIntent(parsed.registrationIntent)
	if err != nil {
		return nil, rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	}
	admission, err := s.wsAuthV3Store.AdmitWSAuthV3(ctx, db.WSAuthV3AdmissionRequest{
		Intent:                admissionIntent,
		AllowOpenRegistration: s.cfg.AllowRegistration,
		AccountIdentityKey:    parsed.accountIdentityKey,
		AccountSigningKey:     parsed.accountSigningKey,
		DeviceKey:             parsed.deviceID,
		DeviceName:            parsed.deviceName,
		DeviceIdentityKey:     parsed.deviceIdentityKey,
		DeviceSigningKey:      parsed.deviceSigningKey,
		BindingVersion:        parsed.bindingVersion,
		BindingCapabilities:   parsed.bindingCapabilities,
		BindingStatus:         parsed.bindingStatus,
		BindingSignature:      parsed.bindingSignature,
		BindingCommitment:     parsed.bindingCommitment,
		NodeAccessPass:        parsed.passBytes(),
	})
	if err != nil {
		return nil, classifyWSAuthV3AdmissionError(parsed.registrationIntent, err)
	}

	principal, err := wsAuthV3AuthResult(admission, &parsed)
	if err != nil {
		return nil, fmt.Errorf("validate WebSocket auth v3 admission result: %w", err)
	}
	return &WSAuthV3VerifiedResult{
		principal:          *principal,
		protocolVersion:    WSAuthProtocolVersionV3,
		canonicalOrigin:    strings.Clone(challenge.canonicalOrigin),
		registrationIntent: parsed.registrationIntent,
	}, nil
}

type parsedWSAuthV3Response struct {
	accountIdentityKey    [32]byte
	accountSigningKey     [32]byte
	accountProofSignature [64]byte
	deviceID              [16]byte
	bindingDeviceKey      [16]byte
	deviceIdentityKey     [32]byte
	deviceSigningKey      [32]byte
	deviceProofSignature  [64]byte
	deviceName            string
	clientVersion         string
	registrationIntent    WSAuthRegistrationIntentV3
	bindingVersion        uint64
	bindingCapabilities   uint64
	bindingStatus         db.DeviceBindingStatus
	bindingSignature      [64]byte
	bindingCommitment     [32]byte
	pass                  [32]byte
	hasPass               bool
	passCommitment        [32]byte
}

func parseWSAuthV3Response(response WSAuthV3ResponseInput, challenge *pendingChallenge) (parsed parsedWSAuthV3Response, err error) {
	defer func() {
		if err != nil {
			parsed.clear()
		}
	}()
	if challenge == nil || challenge.canonicalOrigin == "" || allZeroWSAuthV3(challenge.public[:]) {
		return parsed, ErrInvalidWSAuthV3
	}
	if len(response.IdentityKey) != 32 || len(response.SigningKey) != ed25519.PublicKeySize ||
		len(response.AccountProofSignature) != ed25519.SignatureSize ||
		len(response.DeviceID) != 16 || len(response.DeviceProofSignature) != ed25519.SignatureSize ||
		response.DeviceBinding == nil {
		return parsed, ErrInvalidWSAuthV3
	}
	copy(parsed.accountIdentityKey[:], response.IdentityKey)
	copy(parsed.accountSigningKey[:], response.SigningKey)
	copy(parsed.accountProofSignature[:], response.AccountProofSignature)
	copy(parsed.deviceID[:], response.DeviceID)
	copy(parsed.deviceProofSignature[:], response.DeviceProofSignature)
	parsed.deviceName = strings.Clone(response.DeviceName)
	parsed.clientVersion = strings.Clone(response.ClientVersion)
	parsed.registrationIntent = response.RegistrationIntent
	if allZeroWSAuthV3(parsed.accountIdentityKey[:]) ||
		!cryptokey.ValidEd25519PublicKey(parsed.accountSigningKey[:]) ||
		allZeroWSAuthV3(parsed.deviceID[:]) ||
		allZeroWSAuthV3(parsed.accountProofSignature[:]) ||
		allZeroWSAuthV3(parsed.deviceProofSignature[:]) ||
		!validWSAuthV3ClientMetadata(parsed.deviceName, parsed.clientVersion) {
		return parsed, ErrInvalidWSAuthV3
	}

	binding := response.DeviceBinding
	if len(binding.DeviceKey) != 16 || len(binding.DeviceIdentityKey) != 32 ||
		len(binding.DeviceSigningKey) != 32 || len(binding.AccountSignature) != ed25519.SignatureSize {
		return parsed, ErrInvalidWSAuthV3
	}
	copy(parsed.bindingDeviceKey[:], binding.DeviceKey)
	copy(parsed.deviceIdentityKey[:], binding.DeviceIdentityKey)
	copy(parsed.deviceSigningKey[:], binding.DeviceSigningKey)
	parsed.bindingVersion = binding.Version
	parsed.bindingCapabilities = binding.Capabilities
	parsed.bindingStatus = binding.Status
	copy(parsed.bindingSignature[:], binding.AccountSignature)
	parsedBinding := parsed.bindingInput()
	if err := validateDeviceBindingInput(parsedBinding, true); err != nil ||
		!bytes.Equal(parsed.bindingDeviceKey[:], parsed.deviceID[:]) ||
		parsed.bindingStatus != db.DeviceBindingActive ||
		parsed.bindingCapabilities&db.RequiredChannelCapabilities != db.RequiredChannelCapabilities ||
		allZeroWSAuthV3(parsed.deviceIdentityKey[:]) {
		return parsed, ErrInvalidWSAuthV3
	}

	switch parsed.registrationIntent {
	case WSAuthRegistrationExistingOnlyV3, WSAuthRegistrationCreateOpenV3:
		if len(response.NodeAccessPass) != 0 {
			return parsed, ErrInvalidWSAuthV3
		}
	case WSAuthRegistrationCreateWithPassV3:
		if len(response.NodeAccessPass) != len(parsed.pass) {
			return parsed, ErrInvalidWSAuthV3
		}
		copy(parsed.pass[:], response.NodeAccessPass)
		parsed.hasPass = true
		commitment, err := NodeAccessPassCommitmentV1(challenge.canonicalOrigin, parsed.pass[:])
		if err != nil {
			return parsed, err
		}
		parsed.passCommitment = commitment
	default:
		return parsed, ErrInvalidWSAuthV3
	}
	return parsed, nil
}

func (parsed *parsedWSAuthV3Response) bindingInput() *DeviceBindingInput {
	if parsed == nil {
		return nil
	}
	return &DeviceBindingInput{
		DeviceKey:         parsed.bindingDeviceKey[:],
		DeviceIdentityKey: parsed.deviceIdentityKey[:],
		DeviceSigningKey:  parsed.deviceSigningKey[:],
		Version:           parsed.bindingVersion,
		Capabilities:      parsed.bindingCapabilities,
		Status:            parsed.bindingStatus,
		AccountSignature:  parsed.bindingSignature[:],
	}
}

func (parsed *parsedWSAuthV3Response) passBytes() []byte {
	if parsed == nil || !parsed.hasPass {
		return nil
	}
	return parsed.pass[:]
}

func (parsed *parsedWSAuthV3Response) clear() {
	if parsed == nil {
		return
	}
	clear(parsed.accountProofSignature[:])
	clear(parsed.deviceProofSignature[:])
	clear(parsed.bindingSignature[:])
	clear(parsed.pass[:])
	parsed.hasPass = false
}

func validWSAuthV3ClientMetadata(deviceName, clientVersion string) bool {
	if !utf8.ValidString(deviceName) || deviceName == "" || len(deviceName) > 128 {
		return false
	}
	for _, character := range deviceName {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	if clientVersion == "" || len(clientVersion) > 128 {
		return false
	}
	for index := 0; index < len(clientVersion); index++ {
		if clientVersion[index] < 0x20 || clientVersion[index] > 0x7e {
			return false
		}
	}
	return true
}

func classifyWSAuthV3AdmissionError(intent WSAuthRegistrationIntentV3, err error) error {
	switch {
	case errors.Is(err, db.ErrWSAuthV3IdentityAbsent):
		return rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	case errors.Is(err, db.ErrWSAuthV3AdmissionRejected):
		return rejectWSAuthV3(WSAuthV3AuthenticationFailed, err)
	case errors.Is(err, db.ErrWSAuthV3RegistrationClosed) && intent == WSAuthRegistrationCreateOpenV3:
		return rejectWSAuthV3(WSAuthV3RegistrationClosed, err)
	case errors.Is(err, db.ErrNodeAccessInviteInvalid) && intent == WSAuthRegistrationCreateWithPassV3:
		return rejectWSAuthV3(WSAuthV3NodeAccessPassInvalid, err)
	case errors.Is(err, db.ErrWSAuthV3RegistrationClosed) || errors.Is(err, db.ErrNodeAccessInviteInvalid):
		return fmt.Errorf("incoherent WebSocket auth v3 admission classification: %w", err)
	default:
		return fmt.Errorf("WebSocket auth v3 admission failed: %w", err)
	}
}

func wsAuthV3AdmissionIntent(intent WSAuthRegistrationIntentV3) (db.WSAuthV3AdmissionIntent, error) {
	switch intent {
	case WSAuthRegistrationExistingOnlyV3:
		return db.WSAuthV3AdmissionExisting, nil
	case WSAuthRegistrationCreateOpenV3:
		return db.WSAuthV3AdmissionOpen, nil
	case WSAuthRegistrationCreateWithPassV3:
		return db.WSAuthV3AdmissionPass, nil
	default:
		return 0, ErrInvalidWSAuthV3
	}
}

func wsAuthV3AuthResult(admission *db.WSAuthV3AdmissionResult, parsed *parsedWSAuthV3Response) (*AuthResult, error) {
	if parsed == nil || admission == nil || admission.User == nil || admission.Device == nil || admission.Binding == nil {
		return nil, errors.New("incomplete admission result")
	}
	userID, err := uuid.Parse(admission.User.ID)
	if err != nil || userID == uuid.Nil || userID.String() != admission.User.ID {
		return nil, errors.New("non-canonical admission user id")
	}
	deviceID, err := uuid.Parse(admission.Device.ID)
	if err != nil || deviceID == uuid.Nil || deviceID.String() != admission.Device.ID {
		return nil, errors.New("non-canonical admission device id")
	}
	binding := admission.Binding
	if (admission.IsNew && parsed.registrationIntent == WSAuthRegistrationExistingOnlyV3) ||
		admission.User.Username == "" ||
		subtle.ConstantTimeCompare(admission.User.IdentityKey, parsed.accountIdentityKey[:]) != 1 ||
		subtle.ConstantTimeCompare(admission.User.SigningKey, parsed.accountSigningKey[:]) != 1 ||
		admission.Device.UserID != admission.User.ID ||
		!bytes.Equal(admission.Device.DeviceKey, parsed.deviceID[:]) ||
		binding.UserID != admission.User.ID || binding.DeviceID != admission.Device.ID ||
		!bytes.Equal(binding.DeviceKey, parsed.deviceID[:]) ||
		!bytes.Equal(binding.DeviceIdentityKey, parsed.deviceIdentityKey[:]) ||
		!bytes.Equal(binding.DeviceSigningKey, parsed.deviceSigningKey[:]) ||
		binding.Version != parsed.bindingVersion ||
		binding.Capabilities != parsed.bindingCapabilities ||
		binding.Status != parsed.bindingStatus ||
		!bytes.Equal(binding.AccountSignature, parsed.bindingSignature[:]) ||
		!bytes.Equal(binding.Commitment, parsed.bindingCommitment[:]) ||
		!bindingIsPerDeviceSecure(binding) {
		return nil, errors.New("admission result does not match verified proof")
	}
	return &AuthResult{
		UserID:               admission.User.ID,
		DeviceID:             admission.Device.ID,
		Username:             admission.User.Username,
		IsNew:                admission.IsNew,
		PerDeviceSecure:      true,
		DeviceBindingVersion: binding.Version,
		DeviceBindingStatus:  binding.Status,
	}, nil
}

func rejectWSAuthV3(reason WSAuthV3FailureReason, cause error) *WSAuthV3Failure {
	return &WSAuthV3Failure{reason: reason, cause: cause}
}

func nilWSAuthV3AdmissionStore(store wsAuthV3AdmissionStore) bool {
	if store == nil {
		return true
	}
	value := reflect.ValueOf(store)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
