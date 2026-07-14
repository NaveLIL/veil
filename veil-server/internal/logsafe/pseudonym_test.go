package logsafe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
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

type sensitiveSQLStateError struct {
	state string
	text  string
}

func (e sensitiveSQLStateError) Error() string    { return e.text }
func (e sensitiveSQLStateError) SQLState() string { return e.state }

func TestErrorClassNeverRendersSensitiveErrorText(t *testing.T) {
	const raw = "42a565c5-9767-40ea-87fd-please-never-log"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "nil", want: "-"},
		{name: "canceled", err: fmt.Errorf("user %s: %w", raw, context.Canceled), want: "context_canceled"},
		{name: "deadline", err: fmt.Errorf("user %s: %w", raw, context.DeadlineExceeded), want: "context_deadline"},
		{
			name: "database",
			err:  fmt.Errorf("insert %s: %w", raw, sensitiveSQLStateError{state: "23505", text: "Key (user_id)=(" + raw + ") already exists"}),
			want: "database_23505",
		},
		{
			name: "invalid database state",
			err:  sensitiveSQLStateError{state: raw, text: raw},
			want: "database_error",
		},
		{
			name: "secret endpoint path",
			err:  &url.Error{Op: "Post", URL: "https://push.example/" + raw, Err: errors.New(raw)},
			want: "network_error",
		},
		{
			name: "filesystem path",
			err:  &os.PathError{Op: "open", Path: "C:/uploads/" + raw, Err: errors.New(raw)},
			want: "filesystem_error",
		},
		{name: "generic", err: errors.New(raw), want: "internal_error"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ErrorClass(tc.err)
			if got != tc.want {
				t.Fatalf("ErrorClass() = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, raw) {
				t.Fatalf("ErrorClass leaked raw error data: %q", got)
			}
		})
	}
}
