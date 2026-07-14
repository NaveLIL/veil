package push

import (
	"encoding/json"
	"testing"
)

func TestPayloadsContainNoMessageMetadata(t *testing.T) {
	var wake payload
	if err := json.Unmarshal(wakePayload(), &wake); err != nil {
		t.Fatal(err)
	}
	if wake.Version != 1 || wake.Type != "wake" || wake.Token != "" {
		t.Fatalf("unexpected wake payload: %+v", wake)
	}

	raw, err := challengePayload(42, "opaque-token")
	if err != nil {
		t.Fatal(err)
	}
	var challenge payload
	if err := json.Unmarshal(raw, &challenge); err != nil {
		t.Fatal(err)
	}
	if challenge.Type != "challenge" || challenge.Token != "opaque-token" || challenge.SubscriptionID != 42 {
		t.Fatalf("unexpected challenge payload: %+v", challenge)
	}
}

func TestChallengePayloadRejectsEmptyToken(t *testing.T) {
	if _, err := challengePayload(0, ""); err == nil {
		t.Fatal("empty challenge token accepted")
	}
}
