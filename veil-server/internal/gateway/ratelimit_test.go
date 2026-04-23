package gateway

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/AegisSec/veil-server/internal/metrics"
)

// rejectedCount returns the current value of veil_ws_messages_rejected_total
// for (kind, "rate_limit"). Cheap helper to avoid pulling in the testutil.
func rejectedCount(t *testing.T, kind string) float64 {
	t.Helper()
	m := &dto.Metric{}
	if err := metrics.WSMessagesRejectedTotal.WithLabelValues(kind, "rate_limit").Write(m); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return m.GetCounter().GetValue()
}

func TestWSRateLimit_DropsAfterCap(t *testing.T) {
	prev := SetWSLimitsForTest(map[string]wsLimit{
		"typing": {cap: 3, window: time.Second},
	})
	defer SetWSLimitsForTest(prev)

	user := "u-typing"

	// 3 envelopes within the burst should pass.
	for i := 0; i < 3; i++ {
		if !allowEnvelope(user, "typing") {
			t.Fatalf("envelope %d in burst was rejected; expected pass", i+1)
		}
	}

	startRejected := rejectedCount(t, "typing")

	// 4th must be rejected and the rejected counter must increment.
	if allowEnvelope(user, "typing") {
		t.Fatalf("envelope past cap was allowed; expected reject")
	}
	if got := rejectedCount(t, "typing") - startRejected; got != 1 {
		t.Fatalf("rejected counter delta = %v, want 1", got)
	}
}

func TestWSRateLimit_RefillRestoresAccess(t *testing.T) {
	// 4 tokens / 100ms → ~40 tokens/s, one token every 25ms.
	prev := SetWSLimitsForTest(map[string]wsLimit{
		"presence": {cap: 4, window: 100 * time.Millisecond},
	})
	defer SetWSLimitsForTest(prev)

	user := "u-presence"
	for i := 0; i < 4; i++ {
		if !allowEnvelope(user, "presence") {
			t.Fatalf("envelope %d in burst was rejected", i+1)
		}
	}
	if allowEnvelope(user, "presence") {
		t.Fatalf("envelope past cap was allowed without waiting")
	}

	// Wait long enough for at least one full refill step.
	time.Sleep(50 * time.Millisecond)

	if !allowEnvelope(user, "presence") {
		t.Fatalf("token did not refill after wait")
	}
}

func TestWSRateLimit_BucketsAreScopedPerUser(t *testing.T) {
	prev := SetWSLimitsForTest(map[string]wsLimit{
		"send_message": {cap: 2, window: time.Minute},
	})
	defer SetWSLimitsForTest(prev)

	if !allowEnvelope("alice", "send_message") {
		t.Fatal("alice #1 rejected")
	}
	if !allowEnvelope("alice", "send_message") {
		t.Fatal("alice #2 rejected")
	}
	if allowEnvelope("alice", "send_message") {
		t.Fatal("alice #3 should be rate-limited")
	}
	// Bob's bucket must be independent.
	if !allowEnvelope("bob", "send_message") {
		t.Fatal("bob #1 rejected — buckets leaked across users")
	}
}

func TestWSRateLimit_BucketsAreScopedPerKind(t *testing.T) {
	prev := SetWSLimitsForTest(map[string]wsLimit{
		"send_message": {cap: 1, window: time.Minute},
		"typing":       {cap: 1, window: time.Minute},
	})
	defer SetWSLimitsForTest(prev)

	if !allowEnvelope("u", "send_message") {
		t.Fatal("send #1 rejected")
	}
	if allowEnvelope("u", "send_message") {
		t.Fatal("send #2 should be rate-limited")
	}
	// Different kind must still pass (independent bucket).
	if !allowEnvelope("u", "typing") {
		t.Fatal("typing rejected — kind buckets leaked")
	}
}

func TestWSRateLimit_UnauthIsBypass(t *testing.T) {
	// Empty userID → no rate limiting (pre-auth path handles its own
	// attempt cap separately).
	for i := 0; i < 1000; i++ {
		if !allowEnvelope("", "auth_response") {
			t.Fatalf("empty userID should never be rate-limited (iter %d)", i)
		}
	}
}

func TestWSRateLimit_UnknownKindUsesDefault(t *testing.T) {
	prev := SetWSLimitsForTest(map[string]wsLimit{
		// table empty → all kinds fall back to defaultWSLimit.
	})
	defer SetWSLimitsForTest(prev)

	// defaultWSLimit.cap is 60 in production; just confirm at least one
	// envelope passes rather than asserting the exact cap.
	if !allowEnvelope("u-default", "some_unknown_kind") {
		t.Fatal("unknown kind with default limit should allow first call")
	}
}
