package main

import (
	"reflect"
	"testing"
)

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
