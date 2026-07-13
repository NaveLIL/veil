package authmw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AegisSec/veil-server/internal/cryptokey"
)

type countedBody struct{ reads int }

func (body *countedBody) Read([]byte) (int, error) {
	body.reads++
	return 0, io.EOF
}

func (body *countedBody) Close() error { return nil }

type blockingBody struct {
	started chan struct{}
	release <-chan struct{}
	once    sync.Once
}

func newBlockingBody(release <-chan struct{}) *blockingBody {
	return &blockingBody{started: make(chan struct{}), release: release}
}

func (body *blockingBody) Read([]byte) (int, error) {
	body.once.Do(func() { close(body.started) })
	<-body.release
	return 0, io.EOF
}

func (body *blockingBody) Close() error { return nil }

func fakeBodyRequest(body io.ReadCloser) *http.Request {
	request := httptest.NewRequest(http.MethodPost, "/v1/profile", nil)
	request.Body = body
	request.ContentLength = 1
	request.Header.Set("X-Veil-User", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	request.Header.Set("X-Veil-Timestamp", strconv.FormatInt(time.Now().UnixMilli(), 10))
	request.Header.Set("X-Veil-Signature", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	return request
}

func TestRequireSignedRejectsUnknownAccountBeforeReadingBody(t *testing.T) {
	middleware := New(LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return nil, errors.New("unknown")
	}))
	defer middleware.Close()
	body := &countedBody{}
	response := httptest.NewRecorder()
	middleware.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unknown account reached handler")
	})(response, fakeBodyRequest(body))
	if response.Code != http.StatusUnauthorized || body.reads != 0 {
		t.Fatalf("status=%d body reads=%d, want 401 before body read", response.Code, body.reads)
	}
}

func TestRequireSignedBodyAdmissionBoundsRetainedMemory(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	middleware := New(LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return publicKey, nil
	}))
	defer middleware.Close()
	for range cap(middleware.bodySlots) {
		middleware.bodySlots <- struct{}{}
	}
	defer func() {
		for range cap(middleware.bodySlots) {
			<-middleware.bodySlots
		}
	}()
	body := &countedBody{}
	response := httptest.NewRecorder()
	middleware.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("saturated signed-body request reached handler")
	})(response, fakeBodyRequest(body))
	if response.Code != http.StatusTooManyRequests || body.reads != 0 {
		t.Fatalf("status=%d body reads=%d, want 429 before body read", response.Code, body.reads)
	}
}

func TestNonceCacheRejectsAtCapacityWithoutEvictingLiveEntries(t *testing.T) {
	cache := newNonceCache()
	cache.maxEntries = 3
	now := time.Now()
	liveUntil := now.Add(time.Minute)
	for _, nonce := range []string{"first", "second", "third"} {
		if status := cache.add(nonce, liveUntil); status != nonceAccepted {
			t.Fatalf("add %q status=%v, want accepted", nonce, status)
		}
	}
	if status := cache.add("overflow", liveUntil); status != nonceCapacityBusy {
		t.Fatalf("overflow status=%v, want capacity busy", status)
	}
	if len(cache.entries) != cache.maxEntries {
		t.Fatalf("cache grew past capacity: size=%d capacity=%d", len(cache.entries), cache.maxEntries)
	}
	for _, nonce := range []string{"first", "second", "third"} {
		if _, ok := cache.entries[nonce]; !ok {
			t.Fatalf("live nonce %q was evicted", nonce)
		}
	}

	cache.entries["first"] = now.Add(-time.Second)
	if status := cache.add("replacement", liveUntil); status != nonceAccepted {
		t.Fatalf("replacement after expiry status=%v, want accepted", status)
	}
	if len(cache.entries) != cache.maxEntries {
		t.Fatalf("cache size after expired purge=%d, want %d", len(cache.entries), cache.maxEntries)
	}
	if _, ok := cache.entries["first"]; ok {
		t.Fatal("expired nonce was not purged at capacity")
	}
	for _, nonce := range []string{"second", "third", "replacement"} {
		if _, ok := cache.entries[nonce]; !ok {
			t.Fatalf("live nonce %q missing after expired purge", nonce)
		}
	}
}

func TestRequireSignedBodyAdmissionIsFairPerClient(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	middleware := New(LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return publicKey, nil
	}))
	defer middleware.Close()

	// Three global slots make the fairness property observable: the first IP
	// may retain two, but its third request must not take the slot available to
	// a different IP.
	middleware.bodySlots = make(chan struct{}, 3)
	release := make(chan struct{})
	responses := make(chan int, 3)
	handler := middleware.RequireSigned(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid test signature reached downstream handler")
		w.WriteHeader(http.StatusInternalServerError)
	})

	start := func(remoteAddr string, body io.ReadCloser) {
		request := fakeBodyRequest(body)
		request.RemoteAddr = remoteAddr
		response := httptest.NewRecorder()
		go func() {
			handler(response, request)
			responses <- response.Code
		}()
	}
	waitUntilRead := func(body *blockingBody) {
		t.Helper()
		select {
		case <-body.started:
		case <-time.After(2 * time.Second):
			t.Fatal("request did not acquire a signed-body slot")
		}
	}

	first := newBlockingBody(release)
	second := newBlockingBody(release)
	start("198.51.100.10:1001", first)
	start("198.51.100.10:1002", second)
	waitUntilRead(first)
	waitUntilRead(second)

	thirdBody := &countedBody{}
	thirdRequest := fakeBodyRequest(thirdBody)
	thirdRequest.RemoteAddr = "198.51.100.10:1003"
	thirdResponse := httptest.NewRecorder()
	handler(thirdResponse, thirdRequest)
	if thirdResponse.Code != http.StatusTooManyRequests || thirdBody.reads != 0 {
		t.Fatalf("third same-client status=%d body reads=%d, want 429 before body read", thirdResponse.Code, thirdBody.reads)
	}

	otherClient := newBlockingBody(release)
	start("203.0.113.20:2001", otherClient)
	waitUntilRead(otherClient)
	close(release)

	for i := 0; i < 3; i++ {
		select {
		case status := <-responses:
			if status != http.StatusUnauthorized {
				t.Fatalf("invalid signed request status=%d, want 401", status)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("admitted signed-body request did not finish")
		}
	}

	middleware.bodyAdmissionMu.Lock()
	defer middleware.bodyAdmissionMu.Unlock()
	if len(middleware.bodyClientSlotsInUse) != 0 || len(middleware.bodySlots) != 0 {
		t.Fatalf("body admission leaked: clients=%v global=%d", middleware.bodyClientSlotsInUse, len(middleware.bodySlots))
	}
}

func TestValidEd25519PublicKeyRejectsMalformedAndSmallOrderPoints(t *testing.T) {
	valid, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if !cryptokey.ValidEd25519PublicKey(valid) {
		t.Fatal("generated Ed25519 public key was rejected")
	}

	// Canonical representatives include points of orders 1, 2, 4 and 8.
	weakEncodings := []string{
		"0000000000000000000000000000000000000000000000000000000000000000",
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	}
	for _, encoded := range weakEncodings {
		key, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		if cryptokey.ValidEd25519PublicKey(ed25519.PublicKey(key)) {
			t.Fatalf("small-order Ed25519 point %s was accepted", encoded)
		}
	}

	nonCanonical := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for index := range nonCanonical {
		nonCanonical[index] = 0xff
	}
	if cryptokey.ValidEd25519PublicKey(nonCanonical) {
		t.Fatal("non-canonical Ed25519 point was accepted")
	}
}

func TestRequireSignedRejectsLowOrderAccountKeyBeforeReadingBody(t *testing.T) {
	middleware := New(LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		return make(ed25519.PublicKey, ed25519.PublicKeySize), nil
	}))
	defer middleware.Close()

	body := &countedBody{}
	response := httptest.NewRecorder()
	middleware.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("low-order account key authenticated a forged request")
	})(response, fakeBodyRequest(body))
	if response.Code != http.StatusUnauthorized || body.reads != 0 {
		t.Fatalf("status=%d body reads=%d, want 401 before body read", response.Code, body.reads)
	}
}

func TestRequireSignedRejectsOversizedContentLengthBeforeReadingBody(t *testing.T) {
	var lookupCalls atomic.Int32
	middleware := New(LookupFunc(func(context.Context, string) (ed25519.PublicKey, error) {
		lookupCalls.Add(1)
		return make(ed25519.PublicKey, ed25519.PublicKeySize), nil
	}))
	defer middleware.Close()

	body := &countedBody{}
	request := fakeBodyRequest(body)
	request.ContentLength = maxSignedBodyBytes + 1
	response := httptest.NewRecorder()
	middleware.RequireSigned(func(http.ResponseWriter, *http.Request) {
		t.Fatal("oversized declared body reached handler")
	})(response, request)

	if response.Code != http.StatusRequestEntityTooLarge || body.reads != 0 || lookupCalls.Load() != 0 {
		t.Fatalf(
			"status=%d body reads=%d lookup calls=%d, want 413 before lookup/body read",
			response.Code,
			body.reads,
			lookupCalls.Load(),
		)
	}
}
