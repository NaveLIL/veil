package push

import (
	"encoding/json"
	"errors"
)

const (
	WebPushRecordSize   uint32 = 2048
	WakeTTLSeconds             = 15 * 60
	ChallengeTTLSeconds        = 5 * 60
)

type payload struct {
	Version        int    `json:"v"`
	Type           string `json:"type"`
	Token          string `json:"token,omitempty"`
	SubscriptionID int64  `json:"subscription_id,omitempty"`
}

func wakePayload() []byte {
	return []byte(`{"v":1,"type":"wake"}`)
}

func challengePayload(subscriptionID int64, token string) ([]byte, error) {
	if subscriptionID <= 0 || token == "" {
		return nil, errors.New("invalid push validation challenge")
	}
	return json.Marshal(payload{Version: 1, Type: "challenge", Token: token, SubscriptionID: subscriptionID})
}
