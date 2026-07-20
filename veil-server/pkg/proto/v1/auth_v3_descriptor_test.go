package v1_test

import (
	"testing"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

type fieldExpectation struct {
	name             protoreflect.Name
	number           protoreflect.FieldNumber
	kind             protoreflect.Kind
	typeName         protoreflect.FullName
	hasPresence      bool
	hasOptionalToken bool
}

func TestWebSocketAuthV3DeclarationsAreAppendOnly(t *testing.T) {
	t.Parallel()

	authMessages := pb.File_veil_v1_auth_proto.Messages()
	if authMessages.Len() != 10 {
		t.Fatalf("auth message descriptor count = %d, want 10", authMessages.Len())
	}
	for index, name := range []protoreflect.Name{
		"AuthChallenge",
		"AuthResponse",
		"AuthResult",
		"DeviceBindingV1",
		"DeviceDirectoryEntry",
		"ConversationDeviceDirectory",
		"RegisterDevice",
		"AuthChallengeV3",
		"AuthResponseV3",
		"AuthResultV3",
	} {
		if got := authMessages.Get(index).Name(); got != name {
			t.Fatalf("auth message descriptor index %d = %s, want %s", index, got, name)
		}
	}

	authEnums := pb.File_veil_v1_auth_proto.Enums()
	if authEnums.Len() != 5 {
		t.Fatalf("auth enum descriptor count = %d, want 5", authEnums.Len())
	}
	for index, name := range []protoreflect.Name{
		"AuthFailureReason",
		"DeviceCapability",
		"DeviceBindingStatus",
		"WsRegistrationIntentV3",
		"WsAuthFailureReasonV3",
	} {
		if got := authEnums.Get(index).Name(); got != name {
			t.Fatalf("auth enum descriptor index %d = %s, want %s", index, got, name)
		}
	}

	// Envelope had 41 fields before this additive contract. Appending the v3
	// oneof declarations preserves every legacy field's reflection index.
	envelopeFields := pb.File_veil_v1_envelope_proto.Messages().ByName("Envelope").Fields()
	if envelopeFields.Len() != 44 {
		t.Fatalf("Envelope field descriptor count = %d, want 44", envelopeFields.Len())
	}
	for offset, name := range []protoreflect.Name{
		"auth_challenge_v3",
		"auth_response_v3",
		"auth_result_v3",
	} {
		if got := envelopeFields.Get(41 + offset).Name(); got != name {
			t.Fatalf("Envelope descriptor index %d = %s, want %s", 41+offset, got, name)
		}
	}
}

func TestWebSocketAuthV3MessageDescriptorsAreFrozen(t *testing.T) {
	t.Parallel()

	assertMessageFields(t, "AuthChallengeV3", []fieldExpectation{
		{name: "protocol_version", number: 1, kind: protoreflect.Uint32Kind},
		{name: "server_ephemeral", number: 2, kind: protoreflect.BytesKind},
		{name: "canonical_node_origin", number: 3, kind: protoreflect.StringKind},
	})
	assertMessageFields(t, "AuthResponseV3", []fieldExpectation{
		{name: "protocol_version", number: 1, kind: protoreflect.Uint32Kind},
		{name: "identity_key", number: 2, kind: protoreflect.BytesKind},
		{name: "signing_key", number: 3, kind: protoreflect.BytesKind},
		{name: "account_proof_signature", number: 4, kind: protoreflect.BytesKind},
		{name: "device_id", number: 5, kind: protoreflect.BytesKind},
		{name: "device_name", number: 6, kind: protoreflect.StringKind},
		{name: "client_version", number: 7, kind: protoreflect.StringKind},
		{
			name:        "device_binding",
			number:      8,
			kind:        protoreflect.MessageKind,
			typeName:    "veil.v1.DeviceBindingV1",
			hasPresence: true,
		},
		{name: "device_proof_signature", number: 9, kind: protoreflect.BytesKind},
		{
			name:     "registration_intent",
			number:   10,
			kind:     protoreflect.EnumKind,
			typeName: "veil.v1.WsRegistrationIntentV3",
		},
		{name: "node_access_pass", number: 11, kind: protoreflect.BytesKind},
	})
	assertMessageFields(t, "AuthResultV3", []fieldExpectation{
		{name: "protocol_version", number: 1, kind: protoreflect.Uint32Kind},
		{name: "success", number: 2, kind: protoreflect.BoolKind},
		{
			name:             "user_id",
			number:           3,
			kind:             protoreflect.StringKind,
			hasPresence:      true,
			hasOptionalToken: true,
		},
		{
			name:             "error_message",
			number:           4,
			kind:             protoreflect.StringKind,
			hasPresence:      true,
			hasOptionalToken: true,
		},
		{name: "per_device_secure", number: 5, kind: protoreflect.BoolKind},
		{name: "device_binding_version", number: 6, kind: protoreflect.Uint64Kind},
		{
			name:     "device_binding_status",
			number:   7,
			kind:     protoreflect.EnumKind,
			typeName: "veil.v1.DeviceBindingStatus",
		},
		{
			name:     "failure_reason",
			number:   8,
			kind:     protoreflect.EnumKind,
			typeName: "veil.v1.WsAuthFailureReasonV3",
		},
		{name: "canonical_node_origin", number: 9, kind: protoreflect.StringKind},
	})
}

func TestWebSocketAuthV3EnumDescriptorsAreFrozen(t *testing.T) {
	t.Parallel()

	assertEnumValues(t, "WsRegistrationIntentV3", []enumValueExpectation{
		{name: "WS_REGISTRATION_INTENT_V3_UNSPECIFIED", number: 0},
		{name: "WS_REGISTRATION_INTENT_V3_EXISTING", number: 1},
		{name: "WS_REGISTRATION_INTENT_V3_OPEN", number: 2},
		{name: "WS_REGISTRATION_INTENT_V3_PASS", number: 3},
	})
	assertEnumValues(t, "WsAuthFailureReasonV3", []enumValueExpectation{
		{name: "WS_AUTH_FAILURE_REASON_V3_UNSPECIFIED", number: 0},
		{name: "WS_AUTH_FAILURE_REASON_V3_AUTHENTICATION_FAILED", number: 1},
		{name: "WS_AUTH_FAILURE_REASON_V3_REGISTRATION_CLOSED", number: 2},
		{name: "WS_AUTH_FAILURE_REASON_V3_NODE_ACCESS_PASS_INVALID", number: 3},
	})
}

func TestWebSocketAuthV3EnvelopeTagsAreFrozenAndLegacyTagsRemain(t *testing.T) {
	t.Parallel()

	envelope := pb.File_veil_v1_envelope_proto.Messages().ByName("Envelope")
	if envelope == nil {
		t.Fatal("Envelope descriptor is missing")
	}
	payload := envelope.Oneofs().ByName("payload")
	if payload == nil || payload.IsSynthetic() {
		t.Fatal("Envelope.payload oneof is missing or synthetic")
	}

	for _, expected := range []fieldExpectation{
		{name: "auth_challenge", number: 10, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthChallenge", hasPresence: true},
		{name: "auth_response", number: 11, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthResponse", hasPresence: true},
		{name: "auth_result", number: 12, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthResult", hasPresence: true},
		{name: "register_device", number: 13, kind: protoreflect.MessageKind, typeName: "veil.v1.RegisterDevice", hasPresence: true},
		{name: "auth_challenge_v3", number: 14, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthChallengeV3", hasPresence: true},
		{name: "auth_response_v3", number: 15, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthResponseV3", hasPresence: true},
		{name: "auth_result_v3", number: 16, kind: protoreflect.MessageKind, typeName: "veil.v1.AuthResultV3", hasPresence: true},
	} {
		field := envelope.Fields().ByName(expected.name)
		assertField(t, field, expected)
		if field.ContainingOneof() != payload {
			t.Fatalf("Envelope.%s is not in payload oneof", expected.name)
		}
		if byNumber := envelope.Fields().ByNumber(expected.number); byNumber != field {
			t.Fatalf("Envelope tag %d resolves to %v, want %s", expected.number, byNumber, expected.name)
		}
	}
}

func assertMessageFields(t *testing.T, messageName protoreflect.Name, expected []fieldExpectation) {
	t.Helper()
	message := pb.File_veil_v1_auth_proto.Messages().ByName(messageName)
	if message == nil {
		t.Fatalf("%s descriptor is missing", messageName)
	}
	fields := message.Fields()
	if fields.Len() != len(expected) {
		t.Fatalf("%s field count = %d, want %d", messageName, fields.Len(), len(expected))
	}
	for index, want := range expected {
		field := fields.Get(index)
		assertField(t, field, want)
		if byNumber := fields.ByNumber(want.number); byNumber != field {
			t.Fatalf("%s tag %d resolves to %v, want %s", messageName, want.number, byNumber, want.name)
		}
	}
}

func assertField(t *testing.T, field protoreflect.FieldDescriptor, expected fieldExpectation) {
	t.Helper()
	if field == nil {
		t.Fatalf("field %s is missing", expected.name)
	}
	if field.Name() != expected.name || field.Number() != expected.number || field.Kind() != expected.kind {
		t.Fatalf(
			"field descriptor = %s/%d/%s, want %s/%d/%s",
			field.Name(), field.Number(), field.Kind(), expected.name, expected.number, expected.kind,
		)
	}
	if field.Cardinality() != protoreflect.Optional {
		t.Fatalf("field %s cardinality = %s, want optional/singular", expected.name, field.Cardinality())
	}
	if field.HasPresence() != expected.hasPresence || field.HasOptionalKeyword() != expected.hasOptionalToken {
		t.Fatalf(
			"field %s presence/optional = %v/%v, want %v/%v",
			expected.name, field.HasPresence(), field.HasOptionalKeyword(), expected.hasPresence, expected.hasOptionalToken,
		)
	}
	if expected.typeName == "" {
		return
	}
	var gotType protoreflect.FullName
	switch field.Kind() {
	case protoreflect.MessageKind:
		gotType = field.Message().FullName()
	case protoreflect.EnumKind:
		gotType = field.Enum().FullName()
	default:
		t.Fatalf("field %s has a type name expectation for scalar kind %s", expected.name, field.Kind())
	}
	if gotType != expected.typeName {
		t.Fatalf("field %s type = %s, want %s", expected.name, gotType, expected.typeName)
	}
}

type enumValueExpectation struct {
	name   protoreflect.Name
	number protoreflect.EnumNumber
}

func assertEnumValues(t *testing.T, enumName protoreflect.Name, expected []enumValueExpectation) {
	t.Helper()
	enum := pb.File_veil_v1_auth_proto.Enums().ByName(enumName)
	if enum == nil {
		t.Fatalf("%s descriptor is missing", enumName)
	}
	values := enum.Values()
	if values.Len() != len(expected) {
		t.Fatalf("%s value count = %d, want %d", enumName, values.Len(), len(expected))
	}
	for index, want := range expected {
		value := values.Get(index)
		if value.Name() != want.name || value.Number() != want.number {
			t.Fatalf(
				"%s value %d = %s/%d, want %s/%d",
				enumName, index, value.Name(), value.Number(), want.name, want.number,
			)
		}
		if byNumber := values.ByNumber(want.number); byNumber != value {
			t.Fatalf("%s number %d resolves to %v, want %s", enumName, want.number, byNumber, want.name)
		}
	}
}
