package push

import (
	"strings"
	"testing"
)

func TestValidateSubscriptionRequestStrictMetadata(t *testing.T) {
	valid := &createReq{Endpoint: "https://push.example/topic", DeviceLabel: "Телефон"}
	if err := validateSubscriptionRequest(valid); err != nil || valid.Kind != "unifiedpush" {
		t.Fatalf("valid request rejected/default kind missing: kind=%q err=%v", valid.Kind, err)
	}
	for name, request := range map[string]*createReq{
		"unsupported kind":  {Endpoint: valid.Endpoint, Kind: "webpush"},
		"oversize kind":     {Endpoint: valid.Endpoint, Kind: strings.Repeat("x", 1024)},
		"oversize label":    {Endpoint: valid.Endpoint, DeviceLabel: strings.Repeat("x", 129)},
		"invalid utf8":      {Endpoint: valid.Endpoint, DeviceLabel: string([]byte{0xff})},
		"oversize endpoint": {Endpoint: "https://push.example/" + strings.Repeat("x", 2048)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateSubscriptionRequest(request); err == nil {
				t.Fatal("invalid subscription metadata accepted")
			}
		})
	}
}

func TestValidatePolicyRequest(t *testing.T) {
	enabled := false
	zero := int64(0)
	tooLong := maxPushMuteSeconds + 1
	if err := validatePolicyRequest(&policyReq{Enabled: &enabled}); err != nil {
		t.Fatalf("valid enabled policy rejected: %v", err)
	}
	if err := validatePolicyRequest(&policyReq{MuteSeconds: &zero}); err != nil {
		t.Fatalf("valid mute clear rejected: %v", err)
	}
	if err := validatePolicyRequest(&policyReq{}); err == nil {
		t.Fatal("empty policy accepted")
	}
	if err := validatePolicyRequest(&policyReq{MuteSeconds: &tooLong}); err == nil {
		t.Fatal("oversize mute accepted")
	}
}
