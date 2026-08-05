package auth_test

import (
	"errors"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/config"
	"github.com/NaveLIL/veil/veil-server/internal/nodeorigin"
)

func newTestService() *auth.Service {
	return auth.NewService(nil, &config.Config{AuthChallengeTTL: 5 * time.Second})
}

func newTestServiceWithPublicOrigin(t *testing.T, origin string) *auth.Service {
	t.Helper()
	canonicalOrigin, err := nodeorigin.ParseCanonical(origin)
	if err != nil {
		t.Fatal(err)
	}
	return auth.NewService(nil, &config.Config{
		PublicOrigin: canonicalOrigin, AuthChallengeTTL: 5 * time.Second,
	})
}

func TestCreateChallengeV3RequiresPublicOrigin(t *testing.T) {
	challenge, err := newTestService().CreateChallengeV3("v3-no-origin")
	if !errors.Is(err, auth.ErrPublicOriginRequired) {
		t.Fatalf("CreateChallengeV3 error = %v, want ErrPublicOriginRequired", err)
	}
	if challenge != (auth.ChallengeV3{}) {
		t.Fatalf("failed CreateChallengeV3 returned material: %+v", challenge)
	}
}

func TestCreateChallengeV3FailsClosedWithoutServiceOrConfig(t *testing.T) {
	var nilService *auth.Service
	for name, service := range map[string]*auth.Service{
		"nil service": nilService,
		"nil config":  auth.NewService(nil, nil),
	} {
		t.Run(name, func(t *testing.T) {
			challenge, err := service.CreateChallengeV3(t.Name())
			if !errors.Is(err, auth.ErrPublicOriginRequired) || challenge != (auth.ChallengeV3{}) {
				t.Fatalf("challenge=%+v error=%v", challenge, err)
			}
		})
	}
}

func TestCreateChallengeV3ReturnsExactFreshMaterial(t *testing.T) {
	const origin = "https://veil.example:443"
	service := newTestServiceWithPublicOrigin(t, origin)
	first, err := service.CreateChallengeV3("v3-1")
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateChallengeV3("v3-2")
	if err != nil {
		t.Fatal(err)
	}
	for index, challenge := range []auth.ChallengeV3{first, second} {
		if challenge.ProtocolVersion != 3 || challenge.CanonicalOrigin != origin || challenge.ServerEphemeral == ([32]byte{}) {
			t.Fatalf("challenge %d has invalid live v3 material: %+v", index, challenge)
		}
	}
	if first.ServerEphemeral == second.ServerEphemeral {
		t.Fatal("two v3 challenges produced the same server ephemeral")
	}
}

func TestRemoveChallengeV3IsIdempotent(t *testing.T) {
	service := newTestServiceWithPublicOrigin(t, "https://veil.example:443")
	if _, err := service.CreateChallengeV3("remove-v3"); err != nil {
		t.Fatal(err)
	}
	service.RemoveChallenge("remove-v3")
	service.RemoveChallenge("remove-v3")
}
