package auth

import (
	"bytes"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

func TestServiceCloseJoinsJanitorAndClearsChallengeSecrets(t *testing.T) {
	origin, err := nodeorigin.ParseCanonical("https://node.example:443")
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(nil, &config.Config{PublicOrigin: origin, AuthChallengeTTL: time.Second})
	if _, err := s.CreateChallengeV3("pending"); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	challenge := s.challenges["pending"]
	s.mu.Unlock()
	s.Close()
	s.Close()
	if !bytes.Equal(challenge.private[:], make([]byte, 32)) {
		t.Fatal("pending private key not cleared")
	}
	select {
	case <-s.done:
	default:
		t.Fatal("janitor still running")
	}
	if _, err := s.CreateChallengeV3("late"); err == nil {
		t.Fatal("closed service admitted a new challenge")
	}
}
