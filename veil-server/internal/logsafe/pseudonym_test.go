package logsafe

import (
	"bytes"
	"testing"
	"time"
)

func TestRefsAreDomainSeparatedAndRotateDaily(t *testing.T) {
	p, err := New(bytes.Repeat([]byte{7}, secretSize))
	if err != nil {
		t.Fatal(err)
	}
	p.now = func() time.Time { return time.Date(2026, 7, 11, 10, 0, 0, 0, time.UTC) }
	user := p.Ref("user", "same-raw-value")
	if user == "same-raw-value" || user == p.Ref("ip", "same-raw-value") {
		t.Fatal("refs must be non-raw and domain-separated")
	}
	if user != p.Ref("user", "same-raw-value") {
		t.Fatal("same-day refs must be stable")
	}
	p.now = func() time.Time { return time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC) }
	if user == p.Ref("user", "same-raw-value") {
		t.Fatal("refs must rotate at the UTC day boundary")
	}
}

func TestEmptyIdentifiersStayAnonymous(t *testing.T) {
	p, err := New(bytes.Repeat([]byte{9}, secretSize))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Ref("user", ""); got != "-" {
		t.Fatalf("empty ref = %q", got)
	}
}
