//go:build integration

package integration

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/NaveLIL/veil/veil-server/internal/authmw"
	"github.com/NaveLIL/veil/veil-server/internal/servers"
)

const hostileNodeBOrigin = "https://hostile-node-b.example.test:443"

// TestRESTAuthV2HostileTwoNodeRelayMatrix exercises two separately configured
// HTTP authentication stacks against the same account and durable replay
// store. A proof captured at either Node must fail at the other Node before a
// replay claim, while the original proof remains usable only at its intended
// Node. This is the end-to-end counterpart to the transcript-level origin
// mutation tests in authmw.
func TestRESTAuthV2HostileTwoNodeRelayMatrix(t *testing.T) {
	h := New(t)
	alice := h.CreateUser("hostile-node-alice")

	serversSvc := servers.NewService(h.DB, nullBroadcaster{})
	signedMw := authmw.New(serversSvc.SigningKeyLookup())
	t.Cleanup(signedMw.Close)
	verifierB, err := authmw.NewRESTAuthV2Verifier(
		mustIntegrationNodeOrigin(t, hostileNodeBOrigin),
		serversSvc.SigningKeyLookup(),
		h.DB,
	)
	if err != nil {
		t.Fatal(err)
	}
	boundaryB, err := authmw.NewRESTAuthV2HTTPBoundary(verifierB, signedMw)
	if err != nil {
		t.Fatal(err)
	}
	dispatcherB, err := authmw.NewRESTAuthVersionDispatcher(boundaryB)
	if err != nil {
		t.Fatal(err)
	}

	const target = "/v1/conversations"
	var nodeBAdmissions int
	muxB := http.NewServeMux()
	muxB.HandleFunc(target, dispatcherB.RequireSigned(
		authmw.RESTAuthV2BodylessHTTPPolicy(),
		func(w http.ResponseWriter, request *http.Request) {
			userID, ok := authmw.VerifiedUserID(request.Context())
			if !ok || userID != alice.ID {
				http.Error(w, "invalid verified principal", http.StatusInternalServerError)
				return
			}
			nodeBAdmissions++
			w.WriteHeader(http.StatusNoContent)
		},
	))
	nodeB := httptest.NewServer(muxB)
	t.Cleanup(nodeB.Close)

	proofA := newIntegrationRESTAuthV2Request(
		t, alice, integrationNodeOrigin, nodeB.URL, http.MethodGet, target, nil,
	)
	if status := doIntegrationRequest(t, proofA); status != http.StatusUnauthorized {
		t.Fatalf("Node A proof relayed to Node B status=%d, want 401", status)
	}
	if nodeBAdmissions != 0 {
		t.Fatal("cross-Node proof reached Node B handler")
	}

	// The rejected relay must not poison the nonce at its intended Node.
	proofA = rebindIntegrationRequest(t, proofA, h.Server.URL, target)
	if status := doIntegrationRequest(t, proofA); status != http.StatusOK {
		t.Fatalf("intended Node A rejected proof after relay attempt: status=%d", status)
	}

	proofB := newIntegrationRESTAuthV2Request(
		t, alice, hostileNodeBOrigin, h.Server.URL, http.MethodGet, target, nil,
	)
	if status := doIntegrationRequest(t, proofB); status != http.StatusUnauthorized {
		t.Fatalf("Node B proof relayed to Node A status=%d, want 401", status)
	}
	proofB = rebindIntegrationRequest(t, proofB, nodeB.URL, target)
	if status := doIntegrationRequest(t, proofB); status != http.StatusNoContent {
		t.Fatalf("intended Node B rejected proof after relay attempt: status=%d", status)
	}
	if nodeBAdmissions != 1 {
		t.Fatalf("Node B admissions=%d, want 1", nodeBAdmissions)
	}

	legacy, err := http.NewRequest(http.MethodGet, nodeB.URL+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Header.Set(authmw.RESTAuthV2UserHeader, alice.ID)
	legacy.Header.Set(authmw.RESTAuthV2TimestampHeader, strconv.FormatInt(time.Now().UnixMilli(), 10))
	legacy.Header.Set(authmw.RESTAuthV2SignatureHeader, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	if status := doIntegrationRequest(t, legacy); status != http.StatusBadRequest {
		t.Fatalf("v2-only Node accepted or ambiguously handled legacy proof: status=%d", status)
	}
	if nodeBAdmissions != 1 {
		t.Fatal("legacy downgrade reached Node B handler")
	}
}

func rebindIntegrationRequest(t *testing.T, source *http.Request, transportBase, target string) *http.Request {
	t.Helper()
	rebound, err := http.NewRequest(source.Method, transportBase+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	rebound.Header = source.Header.Clone()
	return rebound
}

func newIntegrationRESTAuthV2Request(
	t *testing.T,
	user *User,
	proofOrigin, transportBase, method, target string,
	body []byte,
) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, transportBase+target, nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := time.Now().UnixMilli()
	var nonce [authmw.RESTAuthV2NonceSize]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		t.Fatal(err)
	}
	message, err := authmw.RESTAuthV2SigningMessage(authmw.RESTAuthV2Input{
		CanonicalOrigin: proofOrigin,
		UserID:          user.ID,
		Method:          method,
		RequestTarget:   target,
		TimestampMS:     uint64(timestamp),
		Nonce:           nonce,
		BodySHA256:      authmw.RESTAuthV2BodyDigest(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set(authmw.RESTAuthV2VersionHeader, authmw.RESTAuthV2ProtocolVersion)
	request.Header.Set(authmw.RESTAuthV2UserHeader, user.ID)
	request.Header.Set(authmw.RESTAuthV2TimestampHeader, strconv.FormatInt(timestamp, 10))
	request.Header.Set(authmw.RESTAuthV2NonceHeader, base64.RawURLEncoding.EncodeToString(nonce[:]))
	request.Header.Set(authmw.RESTAuthV2SignatureHeader, base64.RawURLEncoding.EncodeToString(ed25519.Sign(user.SigningKey, message)))
	return request
}

func doIntegrationRequest(t *testing.T, request *http.Request) int {
	t.Helper()
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	return response.StatusCode
}
