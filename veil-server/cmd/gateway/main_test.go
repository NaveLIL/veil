package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

type pingerFunc func(context.Context) error

func (f pingerFunc) Ping(ctx context.Context) error { return f(ctx) }

func TestReadinessReflectsDatabaseAvailability(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		body   string
	}{
		{name: "ready", status: http.StatusOK, body: `{"status":"ready"}`},
		{name: "database unavailable", err: errors.New("offline"), status: http.StatusServiceUnavailable, body: `{"status":"unavailable"}`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := readinessHandler(pingerFunc(func(context.Context) error { return tc.err }))
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if recorder.Code != tc.status || recorder.Body.String() != tc.body {
				t.Fatalf("response = %d %q, want %d %q", recorder.Code, recorder.Body.String(), tc.status, tc.body)
			}
			if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", got)
			}
		})
	}
}

func TestParseCORSOriginsFailsClosedWhenUnset(t *testing.T) {
	t.Setenv("VEIL_CORS_ORIGINS", "")
	got, err := parseCORSOrigins()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("unset origins = %v, want deny-all", got)
	}
}

func TestParseCORSOriginsValidatesExactOrigins(t *testing.T) {
	t.Setenv("VEIL_CORS_ORIGINS", "https://APP.example, http://127.0.0.1:1420")
	got, err := parseCORSOrigins()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://app.example", "http://127.0.0.1:1420"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("origins = %v, want %v", got, want)
	}

	t.Setenv("VEIL_CORS_ORIGINS", "https://app.example/path")
	if _, err := parseCORSOrigins(); err == nil {
		t.Fatal("origin containing a path must be rejected")
	}
}
