package gateway

import (
	"context"
	"sync"
	"time"

	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
	"github.com/gorilla/websocket"
)

// CommandBudgets bounds database and transport work by operation class.
type CommandBudgets struct {
	Auth, Read, Mutation, Ephemeral time.Duration
}

func DefaultCommandBudgets() CommandBudgets {
	return CommandBudgets{Auth: 10 * time.Second, Read: 10 * time.Second, Mutation: 15 * time.Second, Ephemeral: 3 * time.Second}
}

// SetCommandBudgets is startup-only; config validation happens before serving.
func (h *Hub) SetCommandBudgets(b CommandBudgets) { h.budgets = b }

func (h *Hub) lifecycleContext() context.Context {
	if h.ctx != nil {
		return h.ctx
	}
	return context.Background() // only manually constructed test hubs
}

func (h *Hub) commandBudget(env *pb.Envelope) time.Duration {
	b := h.budgets
	if b.Read == 0 {
		b = DefaultCommandBudgets()
	}
	switch env.Payload.(type) {
	case *pb.Envelope_TypingEvent, *pb.Envelope_PresenceUpdate:
		return b.Ephemeral
	case *pb.Envelope_PrekeyRequest, *pb.Envelope_FriendListRequest:
		return b.Read
	default:
		return b.Mutation
	}
}

// Admission and Add are serialized with StopAdmission, so shutdown never
// calls Wait while an accepted session/command can still increment its group.
func (h *Hub) admitSession() bool {
	h.lifecycleMu.Lock()
	defer h.lifecycleMu.Unlock()
	if h.stopping {
		return false
	}
	h.sessions.Add(1)
	return true
}

func (h *Hub) beginCommand() bool {
	h.lifecycleMu.Lock()
	defer h.lifecycleMu.Unlock()
	if h.stopping {
		return false
	}
	h.commands.Add(1)
	return true
}

func (h *Hub) StopAdmission() {
	h.lifecycleMu.Lock()
	h.stopping = true
	h.lifecycleMu.Unlock()
}

func waitGroup(ctx context.Context, group *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() { group.Wait(); close(done) }()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *Hub) DrainCommands(ctx context.Context) error {
	h.StopAdmission()
	return waitGroup(ctx, &h.commands)
}

// Shutdown cancels all remaining command/handshake work, closes transports,
// and joins both pumps before stopping Run. Call DrainCommands first to give
// commands a bounded grace period. Cancellation never changes a committed
// send outcome: reconnecting clients reconcile using the original ID/bytes.
func (h *Hub) Shutdown(ctx context.Context) error {
	h.StopAdmission()
	h.mu.RLock()
	clients := make([]*Client, 0, len(h.clients))
	for c := range h.clients {
		clients = append(clients, c)
	}
	h.mu.RUnlock()
	var notifications sync.WaitGroup
	for _, c := range clients {
		c.closing.Store(true)
		notifications.Add(1)
		go func() {
			defer notifications.Done()
			if c.conn != nil && ctx.Err() == nil {
				deadline := time.Now().Add(100 * time.Millisecond)
				if end, ok := ctx.Deadline(); ok && end.Before(deadline) {
					deadline = end
				}
				_ = c.conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseGoingAway, "server shutdown"), deadline)
			}
			c.failClosed()
		}()
	}
	_ = waitGroup(ctx, &notifications)
	if h.cancel != nil {
		h.cancel()
	}
	if err := waitGroup(ctx, &h.sessions); err != nil {
		return err
	}
	if err := waitGroup(ctx, &h.background); err != nil {
		return err
	}
	if h.stopRun != nil {
		h.stopRunOnce.Do(func() { close(h.stopRun) })
		select {
		case <-h.runDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (h *Hub) startBackground(fn func()) {
	h.lifecycleMu.Lock()
	if h.stopping {
		h.lifecycleMu.Unlock()
		return
	}
	h.background.Add(1)
	h.lifecycleMu.Unlock()
	go func() { defer h.background.Done(); fn() }()
}

func (c *Client) connectionContext() context.Context {
	if c.ctx != nil {
		return c.ctx
	}
	return c.hub.lifecycleContext()
}

func (c *Client) beginEnvelope(env *pb.Envelope) (context.Context, func(), bool) {
	if !c.hub.beginCommand() {
		c.failClosed()
		return nil, nil, false
	}
	ctx, cancel := context.WithTimeout(c.connectionContext(), c.hub.commandBudget(env))
	c.activeCommand = ctx
	// Deadline/cancellation is a transport failure, not a permanent domain
	// rejection. This also interrupts a synchronous handshake/network wait.
	stop := context.AfterFunc(ctx, c.failClosed)
	return ctx, func() {
		stop()
		cancel()
		c.activeCommand = nil
		c.hub.commands.Done()
	}, true
}

func (c *Client) unregisterClient() {
	c.failClosed()
	select {
	case c.hub.unregister <- c:
	case <-c.hub.runDone:
	}
}
