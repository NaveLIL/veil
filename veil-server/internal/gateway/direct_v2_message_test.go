package gateway

import (
	"bytes"
	"testing"

	"github.com/NaveLIL/veil/veil-server/internal/db"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"google.golang.org/protobuf/proto"
)

func validDirectV2SendForTest() *pb.SendMessage {
	sessionID := bytes.Repeat([]byte{0x41}, 32)
	header := make([]byte, 1+32+32+4+4+41)
	header[0] = 0x11
	copy(header[1:33], sessionID)
	return &pb.SendMessage{
		CryptoProfile:        db.MessageCryptoProfileDirectV2,
		CryptoEra:            db.MessageCryptoEraDirectV2,
		TargetDeviceId:       bytes.Repeat([]byte{0x42}, 16),
		TargetBindingVersion: 7,
		DirectSessionId:      sessionID,
		Header:               header,
	}
}

func TestValidateDirectV2SendShapeIsExactAndCommitsHeaderSession(t *testing.T) {
	valid := validDirectV2SendForTest()
	if direct, err := validateDirectV2SendShape(valid); err != nil || !direct {
		t.Fatalf("valid Direct v2 shape: direct=%v err=%v", direct, err)
	}

	legacy := &pb.SendMessage{Header: []byte{0x01}}
	if direct, err := validateDirectV2SendShape(legacy); err != nil || direct {
		t.Fatalf("legacy shape: direct=%v err=%v", direct, err)
	}

	mutations := map[string]func(*pb.SendMessage){
		"profile": func(message *pb.SendMessage) { message.CryptoProfile = "direct_v3" },
		"era": func(message *pb.SendMessage) { message.CryptoEra++ },
		"target length": func(message *pb.SendMessage) { message.TargetDeviceId = message.TargetDeviceId[:15] },
		"target zero": func(message *pb.SendMessage) { message.TargetDeviceId = make([]byte, 16) },
		"binding zero": func(message *pb.SendMessage) { message.TargetBindingVersion = 0 },
		"session length": func(message *pb.SendMessage) { message.DirectSessionId = message.DirectSessionId[:31] },
		"session zero": func(message *pb.SendMessage) { message.DirectSessionId = make([]byte, 32) },
		"wire tag": func(message *pb.SendMessage) { message.Header[0] = 0x01 },
		"wire length": func(message *pb.SendMessage) { message.Header = message.Header[:113] },
		"wire session": func(message *pb.SendMessage) { message.Header[1] ^= 1 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			message := proto.Clone(valid).(*pb.SendMessage)
			mutate(message)
			if direct, err := validateDirectV2SendShape(message); err == nil || direct {
				t.Fatalf("mutated shape accepted: direct=%v err=%v", direct, err)
			}
		})
	}
}
