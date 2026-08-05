package transparency

import "testing"

func FuzzTransparencyProofRoundTrip(f *testing.F) {
	f.Add([]byte("account|device|binding"), uint8(3), uint8(1))
	f.Add([]byte{0x01}, uint8(1), uint8(0))
	f.Fuzz(func(t *testing.T, material []byte, requestedEvents uint8, requestedLeaf uint8) {
		if len(material) == 0 {
			return
		}
		eventCount := int(requestedEvents%8) + 1
		if eventCount > len(material) {
			eventCount = len(material)
		}
		events := make([][]byte, 0, eventCount)
		for index := 0; index < eventCount; index++ {
			start := index * len(material) / eventCount
			end := (index + 1) * len(material) / eventCount
			if end-start > MaxEventBytes {
				end = start + MaxEventBytes
			}
			events = append(events, append([]byte(nil), material[start:end]...))
		}
		leafIndex := int(requestedLeaf) % len(events)
		root, err := TreeRoot(events)
		if err != nil {
			t.Fatalf("bounded event corpus failed to hash: %v", err)
		}
		proof, err := InclusionProof(events, leafIndex)
		if err != nil || !VerifyInclusion(
			events[leafIndex], uint64(leafIndex), uint64(len(events)), proof, root,
		) {
			t.Fatalf("generated inclusion proof did not verify: %v", err)
		}
		mutatedEvent := append([]byte(nil), events[leafIndex]...)
		mutatedEvent[0] ^= 1
		if VerifyInclusion(
			mutatedEvent, uint64(leafIndex), uint64(len(events)), proof, root,
		) {
			t.Fatal("mutated transparency event verified against the original proof")
		}
		if len(events) > 1 {
			oldSize := len(events) - 1
			oldRoot, err := TreeRoot(events[:oldSize])
			if err != nil {
				t.Fatal(err)
			}
			consistency, err := ConsistencyProof(events, oldSize)
			if err != nil || !VerifyConsistency(
				uint64(oldSize), uint64(len(events)), oldRoot, root, consistency,
			) {
				t.Fatalf("generated consistency proof did not verify: %v", err)
			}
		}
	})
}
