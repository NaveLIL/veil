package gateway

import (
	"errors"
	"testing"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/db"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

func TestDeviceBindingFromProtoRejectsUnknownStatusBeforeNarrowing(t *testing.T) {
	for _, status := range []pb.DeviceBindingStatus{
		pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_UNSPECIFIED,
		pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_LEGACY_UNBOUND,
		pb.DeviceBindingStatus(257),
		pb.DeviceBindingStatus(-255),
	} {
		if _, err := deviceBindingFromProto(&pb.DeviceBindingV1{Status: status}); !errors.Is(err, auth.ErrBadDeviceBinding) {
			t.Fatalf("status %d error = %v, want ErrBadDeviceBinding", status, err)
		}
	}
}

func TestDeviceBindingFromProtoPreservesSignedFields(t *testing.T) {
	wire := &pb.DeviceBindingV1{
		DeviceId:          []byte{1, 2, 3},
		DeviceIdentityKey: []byte{4, 5, 6},
		DeviceSigningKey:  []byte{7, 8, 9},
		Version:           11,
		Capabilities:      3,
		Status:            pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_EXCLUDED,
		AccountSignature:  []byte{10, 11, 12},
	}
	binding, err := deviceBindingFromProto(wire)
	if err != nil {
		t.Fatal(err)
	}
	if binding.Version != 11 || binding.Capabilities != 3 || binding.Status != db.DeviceBindingExcluded {
		t.Fatalf("numeric fields were not preserved: %+v", binding)
	}
	// Conversion owns its slices so protobuf message reuse cannot mutate the
	// security decision after validation.
	wire.DeviceId[0] = 0xff
	wire.DeviceIdentityKey[0] = 0xff
	wire.DeviceSigningKey[0] = 0xff
	wire.AccountSignature[0] = 0xff
	if binding.DeviceKey[0] != 1 || binding.DeviceIdentityKey[0] != 4 ||
		binding.DeviceSigningKey[0] != 7 || binding.AccountSignature[0] != 10 {
		t.Fatalf("binding aliases protobuf buffers: %+v", binding)
	}
}
