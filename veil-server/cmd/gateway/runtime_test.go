package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRequestRuntimeStopsAdmissionAndJoinsCancelledHandlers(t *testing.T) {
	rt := newRequestRuntime()
	started := make(chan struct{})
	finished := make(chan struct{})
	handler := rt.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
	}))
	go func() {
		defer close(finished)
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/", nil))
	}()
	<-started
	rt.StopAdmission()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("new request admitted: %d", recorder.Code)
	}
	rt.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := awaitRuntime(ctx, &rt.active); err != nil {
		t.Fatal(err)
	}
	<-finished
}
