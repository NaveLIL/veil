package chat

import (
	"context"
	"errors"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
)

func TestSigningKeyLookupNilDependenciesAreOperationalFailures(t *testing.T) {
	for _, service := range []*Service{nil, {}} {
		key, err := service.SigningKeyLookup().GetSigningKey(context.Background(), "00112233-4455-4677-8899-aabbccddeeff")
		if key != nil || err == nil || errors.Is(err, authmw.ErrSigningKeyNotFound) {
			t.Fatalf("service=%p key=%x err=%v", service, key, err)
		}
	}
}
