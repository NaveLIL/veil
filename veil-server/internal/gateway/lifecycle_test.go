package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/gorilla/websocket"
)

func TestCommandDeadlineCancelsWorkAndClosesTransport(t *testing.T) {
	h := NewHub(nil, nil)
	h.SetCommandBudgets(CommandBudgets{Auth: time.Second, Read: time.Second, Mutation: 20 * time.Millisecond, Ephemeral: time.Second})
	closed := make(chan struct{})
	c := &Client{hub: h, closeFn: func() error { close(closed); return nil }}
	ctx, finish, ok := c.beginEnvelope(&pb.Envelope{Payload: &pb.Envelope_SendMessage{}})
	if !ok {
		t.Fatal("command refused before shutdown")
	}
	defer finish()
	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Fatal(ctx.Err())
		}
	case <-time.After(time.Second):
		t.Fatal("command exceeded budget")
	}
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("uncertain command left transport open")
	}
	// A timeout must not be published as a permanent domain rejection.
	c.sendError(1, 400, "conversation not found")
}

func TestCommandDrainAllowsExistingWorkAndRejectsNewAdmission(t *testing.T) {
	h := NewHub(nil, nil)
	c := &Client{hub: h}
	_, finish, ok := c.beginEnvelope(&pb.Envelope{})
	if !ok {
		t.Fatal("initial admission rejected")
	}
	h.StopAdmission()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := h.DrainCommands(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain returned before active work: %v", err)
	}
	if _, _, ok := (&Client{hub: h}).beginEnvelope(&pb.Envelope{}); ok {
		t.Fatal("new command admitted during drain")
	}
	if h.admitSession() {
		t.Fatal("new session admitted during drain")
	}
	finish()
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := h.DrainCommands(ctx2); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownJoinsBlockedHandshakeAndRun(t *testing.T) {
	h := NewHub(nil, nil)
	go h.Run()
	started := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !h.admitSession() {
			http.Error(w, "stopping", 503)
			return
		}
		defer h.sessions.Done()
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Error(err)
			return
		}
		ctx, cancel := context.WithCancel(h.lifecycleContext())
		c := &Client{hub: h, conn: conn, ctx: ctx, cancel: cancel, send: make(chan outboundBatch), registered: make(chan struct{})}
		h.register <- c
		<-c.registered
		stop := context.AfterFunc(ctx, c.failClosed)
		defer stop()
		defer c.unregisterClient()
		close(started)
		_, _, _ = conn.ReadMessage() // half-open authentication, no response
	}))
	defer srv.Close()
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.runDone:
	default:
		t.Fatal("Hub.Run remains alive")
	}
	h.mu.RLock()
	n := len(h.clients)
	h.mu.RUnlock()
	if n != 0 {
		t.Fatalf("%d clients remain registered", n)
	}
}

func TestConcurrentStopAdmissionAndCommandDrain(t *testing.T) {
	h := NewHub(nil, nil)
	var starters sync.WaitGroup
	for range 100 {
		starters.Add(1)
		go func() {
			defer starters.Done()
			if h.beginCommand() {
				defer h.commands.Done()
			}
		}()
	}
	h.StopAdmission()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := h.DrainCommands(ctx); err != nil {
		t.Fatal(err)
	}
	starters.Wait()
}
