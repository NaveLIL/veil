package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/jackc/pgx/v5"
	"time"

	"github.com/AegisSec/veil-server/internal/config"
	"github.com/AegisSec/veil-server/internal/db"
)

var (
	ErrChallengeTooOld  = errors.New("challenge expired")
	ErrChallengeUnknown = errors.New("unknown challenge")
	ErrBadSignature     = errors.New("invalid signature")
	ErrBadKeyLength     = errors.New("key must be exactly 32 bytes")
	ErrBadDeviceID      = errors.New("device_id must be exactly 16 bytes")
	ErrTooManyAttempts  = errors.New("too many auth attempts")
)

// pendingChallenge stores a nonce awaiting signature.
type pendingChallenge struct {
	nonce     [32]byte
	createdAt time.Time
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

// CreateChallenge generates a fresh 32-byte random nonce for a connection.
// Returns the nonce bytes to send to the client.
func (s *Service) CreateChallenge(connID string) ([32]byte, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nonce, fmt.Errorf("generate nonce: %w", err)
	}

	s.mu.Lock()
	s.challenges[connID] = &pendingChallenge{
		nonce:     nonce,
		createdAt: time.Now(),
	}
	s.mu.Unlock()

	return nonce, nil
}

// AuthResult contains the result of a successful authentication.
type AuthResult struct {
	UserID   string
	DeviceID string
	Username string
	IsNew    bool // true if user was just registered
}

// VerifyResponse validates the client's auth response:
// 1. Checks the challenge exists and isn't expired
// 2. Verifies the Ed25519 signature over the challenge nonce
// 3. Finds or creates the user + device in the database
func (s *Service) VerifyResponse(ctx context.Context, connID string, identityKey, signingKey, signature, deviceID []byte, deviceName string) (*AuthResult, error) {
	// --- Input validation ---
	if len(identityKey) != 32 {
		return nil, ErrBadKeyLength
	}
	if len(signingKey) != ed25519.PublicKeySize {
		return nil, ErrBadKeyLength
	}
	if len(deviceID) != 16 {
		return nil, ErrBadDeviceID
	}

	// --- Challenge lookup + expiry check ---
	s.mu.Lock()
	challenge, ok := s.challenges[connID]
	if ok {
		delete(s.challenges, connID) // One-shot: challenge consumed regardless of outcome
	}
	s.mu.Unlock()

	if !ok {
		return nil, ErrChallengeUnknown
	}
	if time.Since(challenge.createdAt) > s.cfg.AuthChallengeTTL {
		return nil, ErrChallengeTooOld
	}

	// --- Signature verification ---
	pubKey := ed25519.PublicKey(signingKey)
	if !ed25519.Verify(pubKey, challenge.nonce[:], signature) {
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
		user, err = s.db.CreateUser(ctx, identityKey, signingKey, username)
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		isNew = true
		log.Printf("new user registered: %s (%x...)", user.Username, identityKey[:4])
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
		log.Printf("new device registered: %s for user %s", device.DeviceName, user.Username)
	} else {
		// Device exists — verify it belongs to this user
		if device.UserID != user.ID {
			return nil, errors.New("device belongs to another user")
		}
		// Update last seen
		_ = s.db.TouchDevice(ctx, device.ID)
	}

	return &AuthResult{
		UserID:   user.ID,
		DeviceID: device.ID,
		Username: user.Username,
		IsNew:    isNew,
	}, nil
}

// RemoveChallenge cleans up a challenge when a connection drops.
func (s *Service) RemoveChallenge(connID string) {
	s.mu.Lock()
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
				delete(s.challenges, id)
			}
		}
		s.mu.Unlock()
	}
}
