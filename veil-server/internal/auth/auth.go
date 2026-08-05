package auth

import (
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/db"
)

var (
	ErrChallengeTooOld      = errors.New("challenge expired")
	ErrChallengeUnknown     = errors.New("unknown challenge")
	ErrBadSignature         = errors.New("invalid signature")
	ErrBadIdentityProof     = errors.New("invalid X25519 identity proof")
	ErrPublicOriginRequired = errors.New("canonical public origin is required")
)

const (
	// Kept only for downgrade-regression vectors. No v2 verifier or transport
	// path exists in the runtime.
	wsAuthDomainV2 = "veil-ws-auth-v2\x00"

	// WSAuthProtocolVersionV3 is the frozen live protocol marker. It is not
	// negotiation and unknown versions fail closed.
	WSAuthProtocolVersionV3 uint32 = 3
)

// ChallengeV3 is the transport-neutral server challenge material for the
// mandatory WS auth v3 contract.
type ChallengeV3 struct {
	ProtocolVersion uint32
	ServerEphemeral [32]byte
	CanonicalOrigin string
}

// pendingChallenge stores a single-use v3 ephemeral X25519 key awaiting proof
// from a client.
type pendingChallenge struct {
	private         [32]byte
	public          [32]byte
	canonicalOrigin string
	createdAt       time.Time
}

// Service handles origin-bound WebSocket v3 authentication.
type Service struct {
	db            *db.DB
	cfg           *config.Config
	wsAuthV3Store wsAuthV3AdmissionStore

	mu         sync.Mutex
	challenges map[string]*pendingChallenge
}

func NewService(database *db.DB, cfg *config.Config) *Service {
	s := &Service{
		db:         database,
		cfg:        cfg,
		challenges: make(map[string]*pendingChallenge),
	}
	if database != nil {
		s.wsAuthV3Store = database
	}
	go s.cleanupLoop()
	return s
}

// CreateChallengeV3 generates and stores one origin-bound, one-shot challenge.
// The canonical origin must already have passed gateway configuration.
func (s *Service) CreateChallengeV3(connID string) (ChallengeV3, error) {
	var result ChallengeV3
	if s == nil || s.cfg == nil || s.cfg.PublicOrigin.IsZero() {
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

// AuthResult contains the principal established by successful v3 admission.
type AuthResult struct {
	UserID               string
	DeviceID             string
	Username             string
	IsNew                bool
	PerDeviceSecure      bool
	DeviceBindingVersion uint64
	DeviceBindingStatus  db.DeviceBindingStatus
}

// takeChallenge atomically removes one pending challenge without copying its
// private key. Failure paths clear the removed object immediately; a successful
// caller must clear that same object after proof verification.
func (s *Service) takeChallenge(connID string) (*pendingChallenge, error) {
	if s == nil {
		return nil, ErrChallengeUnknown
	}
	s.mu.Lock()
	challenge, ok := s.challenges[connID]
	if ok {
		delete(s.challenges, connID)
	}
	s.mu.Unlock()

	if !ok {
		return nil, ErrChallengeUnknown
	}
	if s.cfg == nil {
		clear(challenge.private[:])
		return nil, ErrPublicOriginRequired
	}
	if time.Since(challenge.createdAt) > s.cfg.AuthChallengeTTL {
		clear(challenge.private[:])
		return nil, ErrChallengeTooOld
	}
	return challenge, nil
}

// WSAuthSigningMessage builds legacy v2 proof bytes solely for downgrade
// regression tests. Runtime authentication never verifies this transcript.
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

// RemoveChallenge clears pending secret material when a connection drops.
func (s *Service) RemoveChallenge(connID string) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if challenge := s.challenges[connID]; challenge != nil {
		clear(challenge.private[:])
	}
	delete(s.challenges, connID)
	s.mu.Unlock()
}

func (s *Service) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		if s.cfg == nil {
			for id, challenge := range s.challenges {
				clear(challenge.private[:])
				delete(s.challenges, id)
			}
			s.mu.Unlock()
			continue
		}
		now := time.Now()
		for id, challenge := range s.challenges {
			if now.Sub(challenge.createdAt) > s.cfg.AuthChallengeTTL*2 {
				clear(challenge.private[:])
				delete(s.challenges, id)
			}
		}
		s.mu.Unlock()
	}
}
