package main

import (
	"context"
	"net/http"
	"sync"
)

// requestRuntime includes handlers that Server.Close does not wait for after
// a graceful deadline. Add and admission shutdown share a lock.
type requestRuntime struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	stopping bool
	active   sync.WaitGroup
}

func newRequestRuntime() *requestRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &requestRuntime{ctx: ctx, cancel: cancel}
}

func (rt *requestRuntime) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rt.mu.Lock()
		if rt.stopping {
			rt.mu.Unlock()
			http.Error(w, "server shutting down", http.StatusServiceUnavailable)
			return
		}
		rt.active.Add(1)
		rt.mu.Unlock()
		defer rt.active.Done()
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(rt.ctx, cancel)
		defer cancel()
		defer stop()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (rt *requestRuntime) StopAdmission() {
	rt.mu.Lock()
	rt.stopping = true
	rt.mu.Unlock()
}

func awaitRuntime(ctx context.Context, group *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
