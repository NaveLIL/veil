package shares

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type mockStore struct {
	shares map[string]*SecureShare
	leases map[string]*ShareLease
}

func newMockStore() *mockStore {
	return &mockStore{
		shares: make(map[string]*SecureShare),
		leases: make(map[string]*ShareLease),
	}
}

func (m *mockStore) CreateShare(ctx context.Context, share *SecureShare) (*SecureShare, error) {
	share.ID = "mock-share-id"
	share.CreatedAt = time.Now()
	share.Status = "active"
	m.shares[share.PublicSelector] = share
	return share, nil
}

func (m *mockStore) ListCreatorShares(ctx context.Context, creatorUserID string, limit int) ([]*SecureShare, error) {
	var list []*SecureShare
	for _, s := range m.shares {
		if s.CreatorUserID == creatorUserID {
			list = append(list, s)
		}
	}
	return list, nil
}

func (m *mockStore) RevokeShare(ctx context.Context, creatorUserID string, selector string) error {
	s, ok := m.shares[selector]
	if !ok || s.CreatorUserID != creatorUserID {
		return ErrShareNotFound
	}
	s.Status = "revoked"
	now := time.Now()
	s.RevokedAt = &now
	return nil
}

func (m *mockStore) GetPublicMetadata(ctx context.Context, selector string) (*PublicShareMetadata, error) {
	s, ok := m.shares[selector]
	if !ok {
		return nil, ErrShareNotFound
	}
	if s.Status == "revoked" {
		return nil, ErrShareRevoked
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, ErrShareExpired
	}
	if s.Status == "burned" || s.ConsumedClaims >= s.MaxClaims {
		return nil, ErrShareBurned
	}
	return &PublicShareMetadata{
		PublicSelector: s.PublicSelector,
		ContentType:    s.ContentType,
		SizeBytes:      s.SizeBytes,
		MaxClaims:      s.MaxClaims,
		ConsumedClaims: s.ConsumedClaims,
		Status:         s.Status,
		ExpiresAt:      s.ExpiresAt,
		CreatedAt:      s.CreatedAt,
	}, nil
}

func (m *mockStore) ClaimShare(
	ctx context.Context,
	selector string,
	redemptionKey []byte,
	leaseTokenHash []byte,
	leaseDuration time.Duration,
) (*ShareLease, error) {
	s, ok := m.shares[selector]
	if !ok {
		return nil, ErrShareNotFound
	}
	if s.Status == "revoked" {
		return nil, ErrShareRevoked
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, ErrShareExpired
	}
	if s.Status == "burned" || s.ConsumedClaims >= s.MaxClaims {
		return nil, ErrShareBurned
	}

	computed := sha256.Sum256(redemptionKey)
	if !bytes.Equal(computed[:], s.RedemptionHash) {
		return nil, ErrRedemptionFailed
	}

	s.ConsumedClaims++
	if s.ConsumedClaims >= s.MaxClaims {
		s.Status = "burned"
	}

	lease := &ShareLease{
		ID:             "mock-lease-id",
		ShareID:        s.ID,
		LeaseTokenHash: leaseTokenHash,
		ExpiresAt:      time.Now().Add(leaseDuration),
		Status:         "issued",
		CreatedAt:      time.Now(),
	}
	m.leases[base64.RawURLEncoding.EncodeToString(leaseTokenHash)] = lease
	return lease, nil
}

func (m *mockStore) GetCiphertextByLease(
	ctx context.Context,
	selector string,
	leaseTokenHash []byte,
) ([]byte, string, int64, error) {
	leaseKey := base64.RawURLEncoding.EncodeToString(leaseTokenHash)
	lease, ok := m.leases[leaseKey]
	if !ok || lease.Status != "issued" || time.Now().After(lease.ExpiresAt) {
		return nil, "", 0, ErrLeaseInvalid
	}

	s, ok := m.shares[selector]
	if !ok || s.ID != lease.ShareID {
		return nil, "", 0, ErrShareNotFound
	}
	if s.Status == "revoked" {
		return nil, "", 0, ErrShareRevoked
	}

	return s.Ciphertext, s.ContentType, s.SizeBytes, nil
}

func (m *mockStore) JanitorPurge(ctx context.Context) (int64, error) {
	return 0, nil
}

func TestSharePublicFlowRoundtrip(t *testing.T) {
	store := newMockStore()
	handler := NewHandler(store, nil, nil, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	selector := "dGVzdC1zZWxlY3Rvci0xMjM0NQ"
	var redemptionKey [32]byte
	_, _ = rand.Read(redemptionKey[:])
	redemptionHash := sha256.Sum256(redemptionKey[:])
	var reportCapHash [32]byte
	_, _ = rand.Read(reportCapHash[:])
	mockCiphertext := []byte("encrypted-payload-bytes")

	// Setup active share
	_, err := store.CreateShare(context.Background(), &SecureShare{
		PublicSelector:       selector,
		RedemptionHash:       redemptionHash[:],
		ReportCapabilityHash: reportCapHash[:],
		CreatorUserID:        "user-1",
		Ciphertext:           mockCiphertext,
		SizeBytes:            int64(len(mockCiphertext)),
		ContentType:          "text",
		MaxClaims:            1,
		ExpiresAt:            time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create mock share: %v", err)
	}

	// 1. Get Public Metadata
	req1 := httptest.NewRequest("GET", "/v1/shares/public/"+selector, nil)
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("expected 200 metadata, got %d: %s", w1.Code, w1.Body.String())
	}

	var meta PublicShareMetadata
	if err := json.NewDecoder(w1.Body).Decode(&meta); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}
	if meta.PublicSelector != selector || meta.MaxClaims != 1 || meta.ConsumedClaims != 0 {
		t.Fatalf("unexpected metadata: %+v", meta)
	}

	// 2. Claim Share with invalid redemption key
	badClaimBody, _ := json.Marshal(ClaimRequest{
		RedemptionKeyBase64: base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})
	reqBadClaim := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(badClaimBody))
	reqBadClaim.Header.Set("Content-Type", "application/json")
	wBadClaim := httptest.NewRecorder()
	mux.ServeHTTP(wBadClaim, reqBadClaim)
	if wBadClaim.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on bad claim, got %d", wBadClaim.Code)
	}

	// 3. Claim Share with valid redemption key
	claimBody, _ := json.Marshal(ClaimRequest{
		RedemptionKeyBase64: base64.RawURLEncoding.EncodeToString(redemptionKey[:]),
	})
	reqClaim := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(claimBody))
	reqClaim.Header.Set("Content-Type", "application/json")
	wClaim := httptest.NewRecorder()
	mux.ServeHTTP(wClaim, reqClaim)
	if wClaim.Code != http.StatusOK {
		t.Fatalf("expected 200 claim, got %d: %s", wClaim.Code, wClaim.Body.String())
	}

	var claimResp ClaimResponse
	if err := json.NewDecoder(wClaim.Body).Decode(&claimResp); err != nil {
		t.Fatalf("failed to decode claim response: %v", err)
	}
	if claimResp.LeaseTokenBase64 == "" {
		t.Fatal("expected lease token")
	}

	// 4. Download content with lease token
	reqContent := httptest.NewRequest("GET", "/v1/shares/public/"+selector+"/content", nil)
	reqContent.Header.Set("Authorization", "Bearer "+claimResp.LeaseTokenBase64)
	wContent := httptest.NewRecorder()
	mux.ServeHTTP(wContent, reqContent)
	if wContent.Code != http.StatusOK {
		t.Fatalf("expected 200 content, got %d: %s", wContent.Code, wContent.Body.String())
	}
	if !bytes.Equal(wContent.Body.Bytes(), mockCiphertext) {
		t.Fatalf("expected %s, got %s", mockCiphertext, wContent.Body.Bytes())
	}

	// 5. Subsequent claim fails because maxClaims == 1 (burned)
	reqBurnedClaim := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(claimBody))
	reqBurnedClaim.Header.Set("Content-Type", "application/json")
	wBurnedClaim := httptest.NewRecorder()
	mux.ServeHTTP(wBurnedClaim, reqBurnedClaim)
	if wBurnedClaim.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on burned share claim, got %d", wBurnedClaim.Code)
	}
}

func TestShareMultiClaimAndRevocation(t *testing.T) {
	store := newMockStore()
	handler := NewHandler(store, nil, nil, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	selector := "bXVsdGktY2xhaW0tc2VsZWN0b3ItMTIz"
	var redemptionKey [32]byte
	_, _ = rand.Read(redemptionKey[:])
	redemptionHash := sha256.Sum256(redemptionKey[:])
	var reportCapHash [32]byte
	_, _ = rand.Read(reportCapHash[:])
	mockCiphertext := []byte("multi-claim-secret")

	_, err := store.CreateShare(context.Background(), &SecureShare{
		PublicSelector:       selector,
		RedemptionHash:       redemptionHash[:],
		ReportCapabilityHash: reportCapHash[:],
		CreatorUserID:        "user-owner",
		Ciphertext:           mockCiphertext,
		SizeBytes:            int64(len(mockCiphertext)),
		ContentType:          "text",
		MaxClaims:            3,
		ExpiresAt:            time.Now().Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("failed to create share: %v", err)
	}

	claimBody, _ := json.Marshal(ClaimRequest{
		RedemptionKeyBase64: base64.RawURLEncoding.EncodeToString(redemptionKey[:]),
	})

	// Claim 1
	req1 := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(claimBody))
	req1.Header.Set("Content-Type", "application/json")
	w1 := httptest.NewRecorder()
	mux.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("claim 1 failed: %d", w1.Code)
	}

	// Claim 2
	req2 := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(claimBody))
	req2.Header.Set("Content-Type", "application/json")
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("claim 2 failed: %d", w2.Code)
	}

	// Revoke by owner
	if err := store.RevokeShare(context.Background(), "user-owner", selector); err != nil {
		t.Fatalf("failed to revoke: %v", err)
	}

	// Claim 3 should fail because share is revoked
	req3 := httptest.NewRequest("POST", "/v1/shares/public/"+selector+"/claim", bytes.NewReader(claimBody))
	req3.Header.Set("Content-Type", "application/json")
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, req3)
	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected 404 after revocation, got %d", w3.Code)
	}
}
