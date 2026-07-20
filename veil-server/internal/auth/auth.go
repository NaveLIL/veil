package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/curve25519"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/cryptokey"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
)

var (
	ErrChallengeTooOld      = errors.New("challenge expired")
	ErrChallengeUnknown     = errors.New("unknown challenge")
	ErrBadSignature         = errors.New("invalid signature")
	ErrSigningKeyMismatch   = errors.New("signing key does not match registered identity")
	ErrBadIdentityProof     = errors.New("invalid X25519 identity proof")
	ErrBadKeyLength         = errors.New("key must be exactly 32 bytes")
	ErrBadSigningKey        = errors.New("invalid Ed25519 signing public key")
	ErrBadDeviceID          = errors.New("device_id must be exactly 16 bytes")
	ErrBadDeviceName        = errors.New("device_name must be 1..128 UTF-8 bytes without control characters")
	ErrTooManyAttempts      = errors.New("too many auth attempts")
	ErrRegistrationClosed   = errors.New("registration is closed")
	ErrInviteInvalid        = errors.New("node access invite is invalid")
	ErrPublicOriginRequired = errors.New("canonical public origin is required")
	ErrAuthProtocolMismatch = errors.New("authentication protocol mismatch")
)

const (
	wsAuthDomainV2 = "veil-ws-auth-v2\x00"

	// WSAuthProtocolVersionV3 is the frozen version marker returned by the
	// transport-neutral v3 challenge foundation. It is not live negotiation.
	WSAuthProtocolVersionV3 uint32 = 3
)

type challengeProtocol uint32

const (
	challengeProtocolV2 challengeProtocol = 2
	challengeProtocolV3 challengeProtocol = challengeProtocol(WSAuthProtocolVersionV3)
)

// ChallengeV3 is the transport-neutral server challenge material for the
// non-activated WS auth v3 contract.
type ChallengeV3 struct {
	ProtocolVersion uint32
	ServerEphemeral [32]byte
	CanonicalOrigin string
}

// pendingChallenge stores a single-use ephemeral X25519 key awaiting proof
// from a client. The public key is sent as the 32-byte AuthChallenge.
type pendingChallenge struct {
	protocol        challengeProtocol
	private         [32]byte
	public          [32]byte
	canonicalOrigin string
	createdAt       time.Time
}

// Service handles Ed25519 challenge-response authentication.
type Service struct {
	db  *db.DB
	cfg *config.Config

	mu         sync.Mutex
	challenges map[string]*pendingChallenge // connID -> challenge
}

func NewService(database *db.DB, cfg *config.Config) *Service {
	s := &Service{
		db:         database,
		cfg:        cfg,
		challenges: make(map[string]*pendingChallenge),
	}
	// Periodically clean up expired challenges
	go s.cleanupLoop()
	return s
}

// CreateChallenge generates a fresh ephemeral X25519 key for a connection and
// returns its 32-byte public key. The client must prove possession of its
// X25519 identity private key by signing WSAuthSigningMessage(serverPublic,
// DH(clientIdentityPrivate, serverPublic)).
func (s *Service) CreateChallenge(connID string) ([32]byte, error) {
	var private, public [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		return public, fmt.Errorf("generate ephemeral X25519 key: %w", err)
	}
	publicBytes, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		clear(private[:])
		return public, fmt.Errorf("derive ephemeral X25519 public key: %w", err)
	}
	copy(public[:], publicBytes)

	s.mu.Lock()
	if previous := s.challenges[connID]; previous != nil {
		clear(previous.private[:])
	}
	s.challenges[connID] = &pendingChallenge{
		protocol:  challengeProtocolV2,
		private:   private,
		public:    public,
		createdAt: time.Now(),
	}
	s.mu.Unlock()
	clear(private[:])

	return public, nil
}

// CreateChallengeV3 generates and stores one origin-bound, one-shot v3
// challenge without activating any wire protocol. The canonical origin must
// already have passed gateway configuration validation.
func (s *Service) CreateChallengeV3(connID string) (ChallengeV3, error) {
	var result ChallengeV3
	if s.cfg.PublicOrigin.IsZero() {
		return result, ErrPublicOriginRequired
	}

	var private, public [32]byte
	if _, err := rand.Read(private[:]); err != nil {
		clear(private[:])
		return result, fmt.Errorf("generate ephemeral X25519 key: %w", err)
	}
	publicBytes, err := curve25519.X25519(private[:], curve25519.Basepoint)
	if err != nil {
		clear(private[:])
		return result, fmt.Errorf("derive ephemeral X25519 public key: %w", err)
	}
	copy(public[:], publicBytes)

	canonicalOrigin := s.cfg.PublicOrigin.String()
	s.mu.Lock()
	if previous := s.challenges[connID]; previous != nil {
		clear(previous.private[:])
	}
	s.challenges[connID] = &pendingChallenge{
		protocol:        challengeProtocolV3,
		private:         private,
		public:          public,
		canonicalOrigin: canonicalOrigin,
		createdAt:       time.Now(),
	}
	s.mu.Unlock()
	clear(private[:])

	return ChallengeV3{
		ProtocolVersion: WSAuthProtocolVersionV3,
		ServerEphemeral: public,
		CanonicalOrigin: canonicalOrigin,
	}, nil
}

// AuthResult contains the result of a successful authentication.
type AuthResult struct {
	UserID               string
	DeviceID             string
	Username             string
	IsNew                bool // true if user was just registered
	PerDeviceSecure      bool
	DeviceBindingVersion uint64
	DeviceBindingStatus  db.DeviceBindingStatus
}

// VerifyResponse validates the client's auth response:
// 1. Checks the challenge exists and isn't expired
// 2. Derives an ephemeral X25519 shared secret to prove identity-key possession
// 3. Verifies the domain-separated Ed25519 signature over public key + DH proof
// 4. Finds or creates the user + device in the database
func (s *Service) VerifyResponse(ctx context.Context, connID string, identityKey, signingKey, signature, deviceID []byte, deviceName string) (*AuthResult, error) {
	return s.VerifyResponseV1(
		ctx, connID, identityKey, signingKey, signature, deviceID, deviceName, nil, nil,
	)
}

// VerifyResponseV1 extends account authentication with an optional
// cryptographic per-device binding and proof of possession. A legacy device
// may omit the extension only while it has never been cryptographically bound.
func (s *Service) VerifyResponseV1(ctx context.Context, connID string, identityKey, signingKey, signature, deviceID []byte, deviceName string, binding *DeviceBindingInput, deviceSignature []byte) (*AuthResult, error) {
	return s.VerifyResponseV2(
		ctx, connID, identityKey, signingKey, signature, deviceID, deviceName,
		binding, deviceSignature, nil,
	)
}

// VerifyResponseV2 adds an optional closed-Preview Node Access invite. Invite
// state is intentionally consulted only after X25519 and Ed25519
// proof-of-possession succeeds. Existing accounts do not need an invite.
func (s *Service) VerifyResponseV2(ctx context.Context, connID string, identityKey, signingKey, signature, deviceID []byte, deviceName string, binding *DeviceBindingInput, deviceSignature, nodeAccessInvite []byte) (*AuthResult, error) {
	// --- Input validation ---
	if len(identityKey) != 32 {
		return nil, ErrBadKeyLength
	}
	if len(signingKey) != ed25519.PublicKeySize {
		return nil, ErrBadKeyLength
	}
	if !cryptokey.ValidEd25519PublicKey(signingKey) {
		return nil, ErrBadSigningKey
	}
	if len(deviceID) != 16 {
		return nil, ErrBadDeviceID
	}
	deviceName, err := normalizeDeviceName(deviceName)
	if err != nil {
		return nil, err
	}
	if binding == nil {
		if len(deviceSignature) != 0 {
			return nil, ErrBadDeviceProof
		}
	} else if !bytes.Equal(binding.DeviceKey, deviceID) ||
		len(deviceSignature) != ed25519.SignatureSize {
		return nil, ErrBadDeviceProof
	}

	// --- Challenge lookup + expiry check ---
	challenge, err := s.takeChallenge(connID, challengeProtocolV2)
	if err != nil {
		return nil, err
	}
	defer clear(challenge.private[:])

	// --- X25519 proof-of-possession + domain-separated signature ---
	sharedSecret, err := curve25519.X25519(challenge.private[:], identityKey)
	var zeroSharedSecret [32]byte
	if err != nil || len(sharedSecret) != 32 || subtle.ConstantTimeCompare(sharedSecret, zeroSharedSecret[:]) == 1 {
		return nil, ErrBadIdentityProof
	}
	signingMessage, err := WSAuthSigningMessage(challenge.public[:], sharedSecret)
	clear(sharedSecret)
	if err != nil {
		return nil, ErrBadIdentityProof
	}
	pubKey := ed25519.PublicKey(signingKey)
	if !ed25519.Verify(pubKey, signingMessage, signature) {
		return nil, ErrBadSignature
	}

	// --- Database: find or create user ---
	user, err := s.db.FindUserByIdentityKey(ctx, identityKey)
	isNew := false
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("find user: %w", err)
		}
		// User doesn't exist — register
		username := fmt.Sprintf("user_%x", identityKey[:4])
		if s.cfg.AllowRegistration {
			user, err = s.db.CreateUser(ctx, identityKey, signingKey, username)
		} else {
			if len(nodeAccessInvite) == 0 {
				return nil, ErrRegistrationClosed
			}
			user, err = s.db.CreateUserWithNodeAccessInvite(
				ctx, nodeAccessInvite, identityKey, signingKey, username,
			)
			if errors.Is(err, db.ErrNodeAccessInviteInvalid) {
				return nil, ErrInviteInvalid
			}
		}
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		isNew = true
		log.Printf("new user registered: user_ref=%s", logsafe.Ref("user", user.ID))
	} else if err := verifyRegisteredSigningKey(user, signingKey, signingMessage, signature); err != nil {
		// The identity key is public and therefore is not authentication by
		// itself.  An existing account must always authenticate with the
		// Ed25519 key that was pinned when that identity was registered.  In
		// particular, never accept a client-supplied replacement key here: that
		// would let anybody register a new device for a victim whose X25519
		// identity key they know.
		return nil, err
	}

	var bindingCommitment [32]byte
	if binding != nil {
		bindingCommitment, err = verifyAccountSignedDeviceBinding(user, binding)
		if err != nil {
			return nil, err
		}
		deviceSharedSecret, dhErr := curve25519.X25519(challenge.private[:], binding.DeviceIdentityKey)
		if dhErr != nil || len(deviceSharedSecret) != 32 ||
			subtle.ConstantTimeCompare(deviceSharedSecret, zeroSharedSecret[:]) == 1 {
			clear(deviceSharedSecret)
			return nil, ErrBadDeviceProof
		}
		deviceMessage, messageErr := DeviceAuthSigningMessage(
			challenge.public[:], user.IdentityKey, user.SigningKey, binding, deviceSharedSecret,
		)
		clear(deviceSharedSecret)
		if messageErr != nil || !ed25519.Verify(
			ed25519.PublicKey(binding.DeviceSigningKey), deviceMessage, deviceSignature,
		) {
			return nil, ErrBadDeviceProof
		}
	}

	// --- Database: find or create device ---
	device, err := s.db.FindDevice(ctx, deviceID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("find device: %w", err)
		}
		// Device doesn't exist — register
		device, err = s.db.CreateDevice(ctx, user.ID, deviceID, deviceName)
		if err != nil {
			return nil, fmt.Errorf("create device: %w", err)
		}
		log.Printf("new device registered: device_ref=%s user_ref=%s", logsafe.Ref("device", device.ID), logsafe.Ref("user", user.ID))
	} else {
		// Device exists — verify it belongs to this user
		if device.UserID != user.ID {
			return nil, errors.New("device belongs to another user")
		}
		// Update last seen
		_ = s.db.TouchDevice(ctx, device.ID)
	}

	resultStatus := db.DeviceLegacyUnbound
	var resultVersion uint64
	perDeviceSecure := false
	if binding == nil {
		if _, bindingErr := s.db.GetLatestDeviceBinding(ctx, device.ID); bindingErr == nil {
			return nil, ErrDeviceBindingRequired
		} else if !errors.Is(bindingErr, db.ErrDeviceBindingUnavailable) {
			return nil, fmt.Errorf("lookup device binding: %w", bindingErr)
		}
	} else {
		stored, storeErr := s.db.StoreDeviceBinding(ctx, &db.DeviceBinding{
			DeviceID:          device.ID,
			UserID:            user.ID,
			DeviceKey:         append([]byte(nil), binding.DeviceKey...),
			DeviceIdentityKey: append([]byte(nil), binding.DeviceIdentityKey...),
			DeviceSigningKey:  append([]byte(nil), binding.DeviceSigningKey...),
			Version:           binding.Version,
			Capabilities:      binding.Capabilities,
			Status:            binding.Status,
			AccountSignature:  append([]byte(nil), binding.AccountSignature...),
			Commitment:        bindingCommitment[:],
		})
		if storeErr != nil {
			return nil, storeErr
		}
		if stored.Status == db.DeviceBindingRevoked {
			return nil, db.ErrDeviceBindingRevoked
		}
		resultStatus = stored.Status
		resultVersion = stored.Version
		perDeviceSecure = bindingIsPerDeviceSecure(stored)
	}

	return &AuthResult{
		UserID:               user.ID,
		DeviceID:             device.ID,
		Username:             user.Username,
		IsNew:                isNew,
		PerDeviceSecure:      perDeviceSecure,
		DeviceBindingVersion: resultVersion,
		DeviceBindingStatus:  resultStatus,
	}, nil
}

// takeChallenge atomically removes one pending challenge without copying its
// private key. Failure paths clear the removed object immediately; a
// successful caller must clear that same object after proof verification.
func (s *Service) takeChallenge(connID string, expectedProtocol challengeProtocol) (*pendingChallenge, error) {
	s.mu.Lock()
	challenge, ok := s.challenges[connID]
	if ok {
		delete(s.challenges, connID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, ErrChallengeUnknown
	}
	if challenge.protocol != expectedProtocol {
		clear(challenge.private[:])
		return nil, ErrAuthProtocolMismatch
	}
	if time.Since(challenge.createdAt) > s.cfg.AuthChallengeTTL {
		clear(challenge.private[:])
		return nil, ErrChallengeTooOld
	}
	return challenge, nil
}

func normalizeDeviceName(name string) (string, error) {
	if !utf8.ValidString(name) {
		return "", ErrBadDeviceName
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 128 {
		return "", ErrBadDeviceName
	}
	for _, character := range name {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return "", ErrBadDeviceName
		}
	}
	return name, nil
}

// WSAuthSigningMessage returns the exact domain-separated bytes signed during
// WebSocket authentication:
//
//	"veil-ws-auth-v2\0" || server_ephemeral_public_32 || x25519_shared_secret_32
func WSAuthSigningMessage(serverPublic, sharedSecret []byte) ([]byte, error) {
	if len(serverPublic) != 32 || len(sharedSecret) != 32 {
		return nil, ErrBadIdentityProof
	}
	message := make([]byte, 0, len(wsAuthDomainV2)+64)
	message = append(message, wsAuthDomainV2...)
	message = append(message, serverPublic...)
	message = append(message, sharedSecret...)
	return message, nil
}

// verifyRegisteredSigningKey binds a challenge response to an existing
// account.  The caller has already verified the signature with the presented
// key (which cheaply rejects malformed responses before a database lookup),
// but an existing user must be checked against the server-pinned key as well.
func verifyRegisteredSigningKey(user *db.User, presentedKey, message, signature []byte) error {
	if user == nil || len(user.SigningKey) != ed25519.PublicKeySize ||
		len(presentedKey) != ed25519.PublicKeySize ||
		subtle.ConstantTimeCompare(user.SigningKey, presentedKey) != 1 {
		return ErrSigningKeyMismatch
	}
	if !ed25519.Verify(ed25519.PublicKey(user.SigningKey), message, signature) {
		return ErrBadSignature
	}
	return nil
}

// RemoveChallenge cleans up a challenge when a connection drops.
func (s *Service) RemoveChallenge(connID string) {
	s.mu.Lock()
	if challenge := s.challenges[connID]; challenge != nil {
		clear(challenge.private[:])
	}
	delete(s.challenges, connID)
	s.mu.Unlock()
}

// cleanupLoop removes expired challenges every 30 seconds.
func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, ch := range s.challenges {
			if now.Sub(ch.createdAt) > s.cfg.AuthChallengeTTL*2 {
				clear(ch.private[:])
				delete(s.challenges, id)
			}
		}
		s.mu.Unlock()
	}
}
