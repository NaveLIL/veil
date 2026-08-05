package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/chat"
	"github.com/NaveLIL/veil/veil-server/internal/db"
	"github.com/NaveLIL/veil/veil-server/internal/httpmw"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/metrics"
	"github.com/NaveLIL/veil/veil-server/internal/publicerr"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

const (
	maxMessageSize = 64 * 1024
	// Friend metadata travels over the same authenticated event queue as Direct
	// traffic. Keep sender validation aligned with the client ingress bound so
	// one client cannot persist a request that forces another to reject its
	// authenticated epoch.
	maxFriendRequestMessageBytes = 1024
	writeWait                    = 10 * time.Second
	pongWait                     = 60 * time.Second
	pingPeriod                   = (pongWait * 9) / 10

	// defaultMaxConnsPerIP caps concurrent WebSocket connections originating
	// from a single client IP. Override via VEIL_WS_MAX_CONNS_PER_IP. Zero or
	// negative disables the check (NOT recommended in production).
	defaultMaxConnsPerIP = 64
)

// allowedOrigins is the WebSocket Origin allow-list. Browsers must send a
// non-empty Origin matching one of the entries (or "*" with originAllowAll).
// Native clients (Tauri/mobile) omit Origin entirely and bypass this check;
// the WS Origin header exists for browser CSRF defence only.
//
// Default policy is FAIL-CLOSED: an unconfigured allow-list rejects every
// browser request. Operators must opt in explicitly via SetAllowedOrigins
// or the VEIL_WS_ORIGINS env var (an explicit "*" disables the check with
// a warning log).
var (
	allowedOriginsMu sync.RWMutex
	allowedOrigins   map[string]struct{}
	originAllowAll   = false
)

// SetAllowedOrigins replaces the WebSocket origin allow-list.
//   - nil/empty: fail-closed — every browser Origin is rejected (native
//     clients without Origin still pass).
//   - slice containing "*": fail-open — every Origin allowed. Use only for
//     local development.
//   - any other slice: explicit allow-list of Origin header values.
//
// Call once at startup before HandleWebSocket begins serving.
func SetAllowedOrigins(origins []string) {
	allowedOriginsMu.Lock()
	defer allowedOriginsMu.Unlock()
	allowedOrigins = nil
	originAllowAll = false
	if len(origins) == 0 {
		return
	}
	entries := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if o == "*" {
			allowedOrigins = nil
			originAllowAll = true
			return
		}
		entries[o] = struct{}{}
	}
	if len(entries) > 0 {
		allowedOrigins = entries
	}
}

// ConfigureFromEnv applies VEIL_WS_ORIGINS (comma-separated, REQUIRED — set
// to "*" to keep legacy allow-all behaviour) and VEIL_WS_MAX_CONNS_PER_IP
// (integer) to package-level defaults. Call from main before starting the
// gateway. Returns an error when VEIL_WS_ORIGINS is unset so callers can
// fail-fast (preventing accidental allow-all in production).
func ConfigureFromEnv() error {
	raw := strings.TrimSpace(os.Getenv("VEIL_WS_ORIGINS"))
	if raw == "" {
		return fmt.Errorf("VEIL_WS_ORIGINS must be set (use \"*\" to keep legacy allow-all, otherwise list comma-separated browser origins like \"https://app.example,tauri://localhost\")")
	}
	SetAllowedOrigins(strings.Split(raw, ","))
	if originAllowAll {
		log.Printf("WARN: VEIL_WS_ORIGINS=* — accepting any browser Origin (development mode); set explicit origins in production")
	}
	if v := strings.TrimSpace(os.Getenv("VEIL_WS_MAX_CONNS_PER_IP")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxConnsPerIPOverride.Store(int64(n))
		}
	}
	return nil
}

// maxConnsPerIPOverride lets ops tune the per-IP cap at startup without a
// recompile. Zero means "use defaultMaxConnsPerIP".
var maxConnsPerIPOverride atomicInt64

type atomicInt64 struct{ v int64 }

func (a *atomicInt64) Load() int64       { return a.v }
func (a *atomicInt64) Store(n int64)     { a.v = n }
func (a *atomicInt64) effectiveCap() int { return effectiveMaxConns(a.Load()) }
func effectiveMaxConns(override int64) int {
	if override == 0 {
		return defaultMaxConnsPerIP
	}
	return int(override)
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		// Native clients (Tauri/mobile) often omit Origin entirely; this is
		// expected and not a browser CSRF risk because the WS protocol
		// requires Origin only from web pages.
		if origin == "" {
			return true
		}
		allowedOriginsMu.RLock()
		defer allowedOriginsMu.RUnlock()
		if originAllowAll {
			return true
		}
		_, ok := allowedOrigins[origin]
		return ok
	},
}

// Client represents a connected WebSocket client.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan outboundBatch

	// closing is set before a saturated client is disconnected. Fan-out skips
	// such sessions immediately, even while the read pump is still unwinding
	// and Hub.Run has not removed the indexes yet.
	closing   atomic.Bool
	closeOnce sync.Once
	// closeFn is a deterministic test seam. Production falls back to conn.Close.
	closeFn    func() error
	registered chan struct{}

	// Connection ID for challenge tracking (not user-visible)
	connID string
	// Originating client IP (used for per-IP connection cap accounting).
	ip string

	// Identity (set after successful authentication)
	authenticated        bool
	userID               string
	deviceID             string
	deviceKey            []byte
	username             string
	identityKey          []byte
	perDeviceSecure      bool
	deviceBindingVersion uint64
	deviceBindingStatus  db.DeviceBindingStatus

	// Rate limiting
	authAttempts int
}

type authenticatedSenderSnapshot struct {
	identityKey []byte
	username    string
}

// snapshotAuthenticatedSender captures the identity authenticated on this
// transport. Message mutation handlers take it before touching durable state,
// so live events never depend on a fallible post-ACK directory lookup.
func (c *Client) snapshotAuthenticatedSender() (authenticatedSenderSnapshot, bool) {
	if !c.authenticated || c.userID == "" || len(c.identityKey) != 32 || c.username == "" {
		return authenticatedSenderSnapshot{}, false
	}
	return authenticatedSenderSnapshot{
		identityKey: append([]byte(nil), c.identityKey...),
		username:    c.username,
	}, true
}

// outboundBatch is one indivisible FIFO unit for the single WebSocket writer.
// Authentication publishes retained control envelopes and the successful
// AuthResult in one batch so no live event can be written between them.
type outboundBatch struct {
	frames      [][]byte
	publication *publicationGate
}

// publicationGate prevents writePump from exposing a successful AuthResult
// until the Hub has published the authenticated connection in both indexes.
// Closing ready synchronizes the allowed write with wait().
type publicationGate struct {
	once    sync.Once
	ready   chan struct{}
	allowed bool
}

func newPublicationGate() *publicationGate {
	return &publicationGate{ready: make(chan struct{})}
}

func (g *publicationGate) resolve(allowed bool) {
	if g == nil {
		return
	}
	g.once.Do(func() {
		g.allowed = allowed
		close(g.ready)
	})
}

func (g *publicationGate) wait() bool {
	if g == nil {
		return true
	}
	<-g.ready
	return g.allowed
}

func singleOutbound(data []byte) outboundBatch {
	return outboundBatch{frames: [][]byte{data}}
}

func (c *Client) markClosing() bool {
	return c.closing.CompareAndSwap(false, true)
}

func (c *Client) closeTransportOnce() {
	c.closeOnce.Do(func() {
		if c.closeFn != nil {
			_ = c.closeFn()
			return
		}
		if c.conn != nil {
			_ = c.conn.Close()
		}
	})
}

func (c *Client) failClosed() {
	c.closing.Store(true)
	c.closeTransportOnce()
}

// Hub maintains active clients and routes messages.
type Hub struct {
	// All connected clients
	clients map[*Client]bool
	// Index: userID → set of clients (for message fan-out)
	userClients map[string]map[*Client]bool
	// Index: database device UUID → authenticated connections for only that
	// exact cryptographic device.
	deviceClients map[string]map[*Client]bool
	// Index: client IP → live connection count (per-IP cap enforcement)
	ipConns map[string]int
	mu      sync.RWMutex

	register   chan *Client
	unregister chan *Client

	// Services
	authSvc *auth.Service
	chatSvc *chat.Service

	// Optional offline-push notifier. When non-nil, recipients with
	// zero live WebSocket sessions on a NEW message event get an
	// encrypted envelope POSTed to every distributor URL they have
	// registered. Wired by cmd/gateway/main.go via SetPushNotifier.
	pushNotifier PushNotifier
}

func NewHub(authSvc *auth.Service, chatSvc *chat.Service) *Hub {
	return &Hub{
		clients:       make(map[*Client]bool),
		userClients:   make(map[string]map[*Client]bool),
		deviceClients: make(map[string]map[*Client]bool),
		ipConns:       make(map[string]int),
		register:      make(chan *Client),
		unregister:    make(chan *Client),
		authSvc:       authSvc,
		chatSvc:       chatSvc,
	}
}

// tryAcquireIP increments the connection count for ip if it's still under
// the per-IP cap. Returns true on success; false (without incrementing) when
// the cap would be exceeded. ip="" bypasses the check.
func (h *Hub) tryAcquireIP(ip string) bool {
	if ip == "" {
		return true
	}
	cap := maxConnsPerIPOverride.effectiveCap()
	if cap <= 0 {
		return true
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ipConns[ip] >= cap {
		return false
	}
	h.ipConns[ip]++
	return true
}

// releaseIP decrements the per-IP counter. Safe to call with ip="".
func (h *Hub) releaseIP(ip string) {
	if ip == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if n := h.ipConns[ip]; n > 1 {
		h.ipConns[ip] = n - 1
	} else {
		delete(h.ipConns, ip)
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			n := len(h.clients)
			h.mu.Unlock()
			if client.registered != nil {
				close(client.registered)
			}
			metrics.WSConnectionsTotal.Inc()
			metrics.WSConnectionsActive.Set(float64(n))
			log.Printf("client connected: %s (total: %d)", client.connID, n)

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
				// Remove from user index
				if client.userID != "" {
					if uc, ok := h.userClients[client.userID]; ok {
						delete(uc, client)
						if len(uc) == 0 {
							delete(h.userClients, client.userID)
							// Last connection for this user — broadcast offline
							go h.broadcastPresenceOnDisconnect(client.userID, client.identityKey)
						}
					}
				}
				if client.deviceID != "" {
					if dc, ok := h.deviceClients[client.deviceID]; ok {
						delete(dc, client)
						if len(dc) == 0 {
							delete(h.deviceClients, client.deviceID)
						}
					}
				}
			}
			n := len(h.clients)
			h.mu.Unlock()
			metrics.WSConnectionsActive.Set(float64(n))
			h.releaseIP(client.ip)
			// Clean up auth challenge
			h.authSvc.RemoveChallenge(client.connID)
			log.Printf("client disconnected: %s (total: %d)", client.connID, n)
		}
	}
}

func (h *Hub) indexClientLocked(client *Client) {
	if h.userClients[client.userID] == nil {
		h.userClients[client.userID] = make(map[*Client]bool)
	}
	h.userClients[client.userID][client] = true
	if h.deviceClients == nil {
		h.deviceClients = make(map[string]map[*Client]bool)
	}
	if h.deviceClients[client.deviceID] == nil {
		h.deviceClients[client.deviceID] = make(map[*Client]bool)
	}
	h.deviceClients[client.deviceID][client] = true
}

// publishAuthenticatedClient is the sole successful authentication cutover.
// The success batch is already queued but writePump is blocked on gate. While
// holding the write lock we publish identity state and both fan-out indexes,
// then release the writer. Fan-out takes the matching read lock, so every live
// envelope accepted after this point is queued strictly behind AuthResult.
func (h *Hub) publishAuthenticatedClient(client *Client, gate *publicationGate) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if gate == nil || client == nil || !h.clients[client] || client.closing.Load() ||
		client.userID == "" || client.deviceID == "" {
		if gate != nil {
			gate.resolve(false)
		}
		return false
	}
	client.authenticated = true
	h.indexClientLocked(client)
	gate.resolve(true)
	return true
}

// enqueueToUser sends a serialized Envelope to every currently indexed
// connection and reports whether at least one queue actually accepted it.
//
// The read lock deliberately covers each non-blocking channel send. Hub.Run
// removes the client and closes that channel while holding the write lock, so
// releasing the lock before enqueueing would leave a send-on-closed-channel
// race. It also keeps iteration over userClients synchronized with concurrent
// connection indexing and removal.
func (h *Hub) enqueueToUser(userID string, data []byte) bool {
	h.mu.RLock()
	clients := h.userClients[userID]
	enqueued := false
	toClose := make([]*Client, 0)
	for c := range clients {
		if c.closing.Load() {
			continue
		}
		select {
		case c.send <- singleOutbound(data):
			enqueued = true
		default:
			if c.markClosing() {
				toClose = append(toClose, c)
			}
		}
	}
	h.mu.RUnlock()
	for _, client := range toClose {
		client.closeTransportOnce()
	}
	return enqueued
}

// sendToUser sends a serialized Envelope to all connections of a user.
func (h *Hub) sendToUser(userID string, data []byte) {
	h.enqueueToUser(userID, data)
}

// enqueueToDevice sends only to sessions authenticated as one exact database
// device UUID. It deliberately does not fall back to the account index and
// returns true only when at least one queue accepted the bytes; a connected but
// saturated session is not considered online for push fallback.
func (h *Hub) enqueueToDevice(deviceID string, data []byte) bool {
	h.mu.RLock()
	clients := h.deviceClients[deviceID]
	enqueued := false
	toClose := make([]*Client, 0)
	for client := range clients {
		if client.closing.Load() {
			continue
		}
		select {
		case client.send <- singleOutbound(data):
			enqueued = true
		default:
			if client.markClosing() {
				toClose = append(toClose, client)
			}
		}
	}
	h.mu.RUnlock()
	for _, client := range toClose {
		client.closeTransportOnce()
	}
	return enqueued
}

// PushNotifier is the seam between the gateway and the push package
// (UnifiedPush + ntfy delivery). It is invoked when the message-event
// fan-out finds no live WebSocket session for a recipient. Wiring is
// optional — the gateway boots fine without a notifier; in that mode
// offline recipients just wait for their next /v1/messages sync poll.
type PushNotifier interface {
	NotifyOffline(ctx context.Context, userID string, env *pb.Envelope)
}

// SetPushNotifier installs (or replaces) the notifier. nil disables.
// Safe to call before Run; not safe to swap mid-flight.
func (h *Hub) SetPushNotifier(n PushNotifier) { h.pushNotifier = n }

// NotifyMLSWelcome implements mls.Fanout. Phase 6 stub: a richer
// real-time signal (new envelope variant or a dedicated WS event
// channel) is tracked in INTEGRATION_ROADMAP.md. Today, recipients
// discover queued welcomes by polling GET /v1/mls/welcomes on
// reconnect, so this method intentionally no-ops at the wire level
// while keeping a structured log entry for observability.
func (h *Hub) NotifyMLSWelcome(recipientUserID, conversationID, welcomeID string) {
	log.Printf("mls: queued welcome user_ref=%s conv_ref=%s welcome_ref=%s",
		logsafe.Ref("user", recipientUserID), logsafe.Ref("conversation", conversationID), logsafe.Ref("welcome", welcomeID))
}

// NotifyMLSCommit implements mls.Fanout. Same caveat as
// NotifyMLSWelcome: clients fetch via GET /v1/mls/commits/{id}?after_epoch=N
// on reconnect or after each accepted commit. Logged for ops visibility.
func (h *Hub) NotifyMLSCommit(conversationID string, epoch uint64, senderUserID string) {
	log.Printf("mls: committed conv_ref=%s epoch=%d sender_ref=%s",
		logsafe.Ref("conversation", conversationID), epoch, logsafe.Ref("user", senderUserID))
}

// fanoutMessageEvent dispatches a freshly produced MessageEvent to
// every recipient. Recipients with at least one live WS session
// receive the envelope through the regular send queue; recipients with
// zero live sessions are routed to the push notifier (if any).
//
// Used only for NEW message events. Edits/deletes/reactions remain on
// the original sendToUser path because the on-device push UX for those
// is noisy and out of scope for Phase 4.
func (h *Hub) fanoutMessageEvent(ctx context.Context, recipients []string, data []byte, env *pb.Envelope) {
	for _, uid := range recipients {
		if h.enqueueToUser(uid, data) {
			continue
		}
		if h.pushNotifier != nil {
			h.pushNotifier.NotifyOffline(ctx, uid, env)
		}
	}
}

// fanoutMessageEventToDevices routes group/channel ciphertext only to exact
// eligible device sessions. Push remains an account-scoped opaque wake-up and
// is emitted once only when none of that user's eligible target devices is
// online.
func (h *Hub) fanoutMessageEventToDevices(ctx context.Context, recipients []deviceFanoutRecipient, base *pb.Envelope) {
	type userDelivery struct {
		online bool
		wake   *pb.Envelope
	}
	users := make(map[string]*userDelivery)
	for _, recipient := range recipients {
		env := proto.Clone(base).(*pb.Envelope)
		event := env.GetMessageEvent()
		if event == nil {
			continue
		}
		event.TargetDeviceId = append([]byte(nil), recipient.DeviceKey...)
		data, err := proto.Marshal(env)
		if err != nil {
			log.Printf("device message fanout: marshal failed: class=%s", logsafe.ErrorClass(err))
			continue
		}
		delivery := users[recipient.UserID]
		if delivery == nil {
			delivery = &userDelivery{wake: env}
			users[recipient.UserID] = delivery
		}
		if h.enqueueToDevice(recipient.DeviceID, data) {
			delivery.online = true
		}
	}
	if h.pushNotifier != nil {
		for userID, delivery := range users {
			if !delivery.online && delivery.wake != nil {
				h.pushNotifier.NotifyOffline(ctx, userID, delivery.wake)
			}
		}
	}
}

// BroadcastToUsers serializes the envelope once and delivers it to all listed users.
// Used by the servers package as a Broadcaster implementation.
func (h *Hub) BroadcastToUsers(userIDs []string, env *pb.Envelope) {
	if env == nil || len(userIDs) == 0 {
		return
	}
	data, err := proto.Marshal(env)
	if err != nil {
		log.Printf("hub broadcast: marshal failed: class=%s", logsafe.ErrorClass(err))
		return
	}
	for _, uid := range userIDs {
		h.sendToUser(uid, data)
	}
}

// HandleWebSocket upgrades HTTP to WebSocket, sends auth challenge, starts pumps.
func HandleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	ip := wsClientIP(r)

	// Per-IP connection cap. Reject BEFORE upgrade so we don't waste a
	// goroutine + websocket buffer on an attacker flooding from one IP.
	if !hub.tryAcquireIP(ip) {
		metrics.WSRefusedTotal.WithLabelValues("ip_cap").Inc()
		http.Error(w, "too many connections from this address", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Upgrade may fail because of CheckOrigin too — count it.
		metrics.WSRefusedTotal.WithLabelValues("upgrade_error").Inc()
		hub.releaseIP(ip)
		log.Printf("upgrade error: class=%s", logsafe.ErrorClass(err))
		return
	}

	connID := fmt.Sprintf("%p-%d", conn, time.Now().UnixNano())
	client := &Client{
		hub:        hub,
		conn:       conn,
		send:       make(chan outboundBatch, 256),
		connID:     connID,
		ip:         ip,
		registered: make(chan struct{}),
	}

	hub.register <- client
	<-client.registered

	// Send auth challenge immediately
	nonce, err := hub.authSvc.CreateChallenge(connID)
	if err != nil {
		log.Printf("failed to create challenge: class=%s", logsafe.ErrorClass(err))
		client.failClosed()
		// Pumps have not started yet, so no readPump defer exists to return the
		// registered client, IP slot and send channel to Hub.Run.
		hub.unregister <- client
		return
	}

	env := &pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_AuthChallenge{
			AuthChallenge: &pb.AuthChallenge{Challenge: nonce[:]},
		},
	}
	data, _ := proto.Marshal(env)
	client.send <- singleOutbound(data)

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.failClosed()
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("read error [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
			}
			break
		}

		// Decode Protobuf Envelope
		var env pb.Envelope
		if err := proto.Unmarshal(message, &env); err != nil {
			c.sendError(0, 400, "invalid protobuf envelope")
			continue
		}

		metrics.WSMessagesTotal.WithLabelValues(envelopeKind(&env)).Inc()
		c.handleEnvelope(&env)
	}
}

// envelopeKind returns a low-cardinality string label for the envelope's
// payload variant — used as a Prometheus label for veil_ws_messages_total.
func envelopeKind(env *pb.Envelope) string {
	switch env.Payload.(type) {
	case *pb.Envelope_AuthResponse:
		return "auth_response"
	case *pb.Envelope_SendMessage:
		return "send_message"
	case *pb.Envelope_EditMessage:
		return "edit_message"
	case *pb.Envelope_DeleteMessage:
		return "delete_message"
	case *pb.Envelope_ReactionUpdate:
		return "reaction"
	case *pb.Envelope_PrekeyRequest:
		return "prekey_request"
	case *pb.Envelope_TypingEvent:
		return "typing"
	case *pb.Envelope_PresenceUpdate:
		return "presence"
	case *pb.Envelope_SenderKeyDist:
		return "sender_key_dist"
	case *pb.Envelope_SenderKeyReceipt:
		return "sender_key_receipt"
	case *pb.Envelope_FriendRequest:
		return "friend_request"
	case *pb.Envelope_FriendRespond:
		return "friend_respond"
	case *pb.Envelope_FriendRemove:
		return "friend_remove"
	case *pb.Envelope_FriendListRequest:
		return "friend_list_request"
	default:
		return "other"
	}
}

func (c *Client) handleEnvelope(env *pb.Envelope) {
	// AuthResponseV3 remains deliberately unactivated, but the generated oneof
	// now decodes its raw Pass field. Clear that unavoidable decoded bearer copy
	// on every legacy/default dispatch path instead of leaving it until GC.
	if response := env.GetAuthResponseV3(); response != nil {
		defer clear(response.NodeAccessPass)
	}
	ctx := context.Background()
	clientMessageID, sendMessageReason := sendMessageEnvelopeContext(env)

	switch payload := env.Payload.(type) {

	// === Auth Response ===
	case *pb.Envelope_AuthResponse:
		c.handleAuth(ctx, env.Seq, payload.AuthResponse)

	// === All other messages require authentication ===
	default:
		if !c.authenticated {
			if clientMessageID != "" {
				sendMessageReason = sendMessageReasonNotAuthenticated
			}
			c.sendErrorWithSendMessageContext(
				env.Seq, 401, "not authenticated", clientMessageID, sendMessageReason,
			)
			return
		}

		// W10 — per-(user, kind) rate limit. Drop with a 429-equivalent
		// error so the client knows to back off, and increment the
		// rejected-total metric so ops can see the offender.
		kind := kindForUserBucket(envelopeKind(env))
		if !allowEnvelope(c.userID, kind) {
			if clientMessageID != "" {
				sendMessageReason = sendMessageReasonRateLimited
			}
			c.sendErrorWithSendMessageContext(
				env.Seq, 429, "ws rate limit exceeded for "+kind, clientMessageID, sendMessageReason,
			)
			return
		}

		switch p := env.Payload.(type) {
		case *pb.Envelope_SendMessage:
			c.handleSendMessage(ctx, env.Seq, p.SendMessage)
		case *pb.Envelope_EditMessage:
			c.handleEditMessage(ctx, env.Seq, p.EditMessage)
		case *pb.Envelope_DeleteMessage:
			c.handleDeleteMessage(ctx, env.Seq, p.DeleteMessage)
		case *pb.Envelope_ReactionUpdate:
			c.handleReaction(ctx, env.Seq, p.ReactionUpdate)
		case *pb.Envelope_PrekeyRequest:
			c.handlePreKeyRequest(ctx, env.Seq, p.PrekeyRequest)
		case *pb.Envelope_TypingEvent:
			c.handleTyping(ctx, env.Seq, p.TypingEvent)
		case *pb.Envelope_PresenceUpdate:
			c.handlePresence(ctx, p.PresenceUpdate)
		case *pb.Envelope_SenderKeyDist:
			c.handleSenderKeyDist(ctx, env.Seq, p.SenderKeyDist)
		case *pb.Envelope_SenderKeyReceipt:
			c.handleSenderKeyReceipt(ctx, env.Seq, p.SenderKeyReceipt)
		case *pb.Envelope_FriendRequest:
			c.handleFriendRequest(ctx, env.Seq, p.FriendRequest)
		case *pb.Envelope_FriendRespond:
			c.handleFriendRespond(ctx, env.Seq, p.FriendRespond)
		case *pb.Envelope_FriendRemove:
			c.handleFriendRemove(ctx, env.Seq, p.FriendRemove)
		case *pb.Envelope_FriendListRequest:
			c.handleFriendListRequest(ctx, env.Seq)
		default:
			c.sendError(env.Seq, 501, "unsupported message type")
		}
	}
}

// sendMessageEnvelopeContext extracts correlation only from send_message.
// Invalid or absent IDs are never reflected back to the peer; the stable
// reason lets clients distinguish this wire-contract failure from unrelated
// authentication and rate-limit errors.
func sendMessageEnvelopeContext(env *pb.Envelope) (string, string) {
	if env == nil {
		return "", ""
	}
	payload, ok := env.Payload.(*pb.Envelope_SendMessage)
	if !ok {
		return "", ""
	}
	if clientMessageID, valid := chat.CanonicalClientMessageID(payload.SendMessage); valid {
		return clientMessageID, ""
	}
	return "", sendMessageReasonInvalidClientMessageID
}

// --- Auth ---

func deviceBindingFromProto(binding *pb.DeviceBindingV1) (*auth.DeviceBindingInput, error) {
	if binding == nil {
		return nil, nil
	}
	// Protobuf enums can carry unknown int32 values. Validate before narrowing
	// to the DB's byte-sized status, otherwise values such as 257 would wrap to
	// ACTIVE and bypass the signed-state allow-list.
	status := binding.GetStatus()
	switch status {
	case pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_ACTIVE,
		pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_EXCLUDED,
		pb.DeviceBindingStatus_DEVICE_BINDING_STATUS_REVOKED:
	default:
		return nil, auth.ErrBadDeviceBinding
	}
	return &auth.DeviceBindingInput{
		DeviceKey:         append([]byte(nil), binding.GetDeviceId()...),
		DeviceIdentityKey: append([]byte(nil), binding.GetDeviceIdentityKey()...),
		DeviceSigningKey:  append([]byte(nil), binding.GetDeviceSigningKey()...),
		Version:           binding.GetVersion(),
		Capabilities:      binding.GetCapabilities(),
		Status:            db.DeviceBindingStatus(status),
		AccountSignature:  append([]byte(nil), binding.GetAccountSignature()...),
	}, nil
}

func (c *Client) handleAuth(ctx context.Context, seq uint64, resp *pb.AuthResponse) {
	c.authAttempts++
	if c.authAttempts > 3 {
		c.sendError(seq, 429, "too many auth attempts")
		c.failClosed()
		return
	}

	if resp == nil {
		metrics.WSAuthFailuresTotal.Inc()
		_ = c.sendPublicAuthFailure(seq, publicerr.New(
			http.StatusUnauthorized, "authentication_failed", "authentication failed", errors.New("missing authentication response"),
		))
		return
	}
	// The access pass is a short-lived bearer. Protobuf and WebSocket/TLS
	// decoding necessarily create transient wire copies, but this avoidable
	// decoded field must not remain in the heap until the envelope is collected.
	defer clear(resp.NodeAccessInvite)
	deviceBinding, err := deviceBindingFromProto(resp.GetDeviceBinding())
	if err != nil {
		metrics.WSAuthFailuresTotal.Inc()
		_ = c.sendPublicAuthFailure(seq, publicerr.New(
			http.StatusUnauthorized, "authentication_failed", "authentication failed", err,
		))
		return
	}
	result, err := c.hub.authSvc.VerifyResponseV2(
		ctx, c.connID,
		resp.IdentityKey, resp.SigningKey, resp.Signature,
		resp.DeviceId, resp.DeviceName, deviceBinding, resp.GetDeviceSignature(),
		resp.GetNodeAccessInvite(),
	)
	if err != nil {
		log.Printf("auth failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		metrics.WSAuthFailuresTotal.Inc()
		_ = c.sendMappedAuthFailure(seq, err)
		return
	}

	c.userID = result.UserID
	c.deviceID = result.DeviceID
	c.deviceKey = append([]byte(nil), resp.DeviceId...)
	c.username = result.Username
	c.identityKey = resp.IdentityKey
	c.perDeviceSecure = result.PerDeviceSecure
	c.deviceBindingVersion = result.DeviceBindingVersion
	c.deviceBindingStatus = result.DeviceBindingStatus

	// Restore durable sender-key state before declaring the session ready. A
	// database failure forces a reconnect so the client cannot start sending
	// group messages without the latest retained generation.
	pendingSenderKeys, err := c.pendingSenderKeyEnvelopes(ctx)
	if err != nil {
		log.Printf("auth state restore failed [%s]: reason=%s", c.connID, senderKeyRestoreErrorLabel(err))
		message := "failed to restore encrypted session state"
		switch {
		case errors.Is(err, db.ErrSenderKeyRetentionExpired):
			message = "encrypted history unavailable: sender-key receipt deadline expired"
		case errors.Is(err, db.ErrSenderKeyRestoreBacklogExceeded):
			message = "encrypted session backlog exceeds the safe restore limit"
		case errors.Is(err, db.ErrSenderKeyLegacyState):
			message = "encrypted session contains unsupported legacy sender-key state"
		}
		_ = c.sendAuthResult(seq, false, "", message)
		c.failClosed()
		return
	}
	// Retained device controls and the successful AuthResult are one gated FIFO
	// batch. writePump may dequeue it, but cannot expose any frame until the Hub
	// has atomically published this connection in both authenticated indexes.
	// Once released, live fan-out can only enqueue behind the complete batch.
	authData, err := marshalEnvelope(authResultEnvelope(seq, true, result.UserID, "", result))
	if err != nil {
		log.Printf("auth result encode failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return
	}
	frames := make([][]byte, 0, len(pendingSenderKeys)+1)
	frames = append(frames, pendingSenderKeys...)
	frames = append(frames, authData)
	gate := newPublicationGate()
	if err := c.enqueueBatch(outboundBatch{frames: frames, publication: gate}); err != nil {
		gate.resolve(false)
		log.Printf("auth result queue failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return
	}
	if !c.hub.publishAuthenticatedClient(c, gate) {
		log.Printf("auth publication failed [%s]", c.connID)
		c.failClosed()
		return
	}
	log.Printf("auth success [%s]: user_ref=%s device_ref=%s", c.connID, logsafe.Ref("user", c.userID), logsafe.Ref("device", c.deviceID))
}

// --- Chat ---

func validateDirectV2SendShape(msg *pb.SendMessage) (bool, error) {
	if msg == nil {
		return false, chat.ErrInvalidSendMessage
	}
	absent := msg.CryptoProfile == "" && msg.CryptoEra == 0 &&
		len(msg.TargetDeviceId) == 0 && msg.TargetBindingVersion == 0 &&
		len(msg.DirectSessionId) == 0
	if absent {
		return false, nil
	}
	if (msg.CryptoProfile == db.MessageCryptoProfileSenderKeyV5 &&
		msg.CryptoEra == db.MessageCryptoEraSenderKeyV5 ||
		msg.CryptoProfile == db.MessageCryptoProfileSenderKeyV6 &&
			msg.CryptoEra == db.MessageCryptoEraSenderKeyV6) &&
		len(msg.TargetDeviceId) == 0 && msg.TargetBindingVersion == 0 &&
		len(msg.DirectSessionId) == 0 {
		return false, nil
	}
	if msg.CryptoProfile != db.MessageCryptoProfileDirectV2 ||
		msg.CryptoEra != db.MessageCryptoEraDirectV2 ||
		len(msg.TargetDeviceId) != 16 || bytes.Equal(msg.TargetDeviceId, make([]byte, 16)) ||
		msg.TargetBindingVersion == 0 || msg.TargetBindingVersion > uint64(^uint64(0)>>1) ||
		len(msg.DirectSessionId) != 32 || bytes.Equal(msg.DirectSessionId, make([]byte, 32)) {
		return false, chat.ErrInvalidSendMessage
	}
	if len(msg.Header) == 0 {
		return false, chat.ErrInvalidSendMessage
	}
	switch msg.Header[0] {
	case 0x11:
		if len(msg.Header) != 1+32+32+4+4+41 {
			return false, chat.ErrInvalidSendMessage
		}
	case 0x12:
		if len(msg.Header) != 1+32+41 {
			return false, chat.ErrInvalidSendMessage
		}
	default:
		return false, chat.ErrInvalidSendMessage
	}
	if !bytes.Equal(msg.Header[1:33], msg.DirectSessionId) {
		return false, chat.ErrInvalidSendMessage
	}
	return true, nil
}

func (c *Client) handleSendMessage(ctx context.Context, seq uint64, msg *pb.SendMessage) {
	clientMessageID, validClientMessageID := chat.CanonicalClientMessageID(msg)
	sender, authenticated := c.snapshotAuthenticatedSender()
	if !authenticated {
		reason := sendMessageReasonNotAuthenticated
		if !validClientMessageID {
			reason = sendMessageReasonInvalidClientMessageID
		}
		c.sendErrorWithSendMessageContext(
			seq, http.StatusUnauthorized, "authentication required", clientMessageID, reason,
		)
		return
	}
	if !validClientMessageID {
		c.sendErrorWithSendMessageContext(
			seq, http.StatusBadRequest, "invalid client message id", "", sendMessageReasonInvalidClientMessageID,
		)
		return
	}
	// Sealed-message semantics are not persisted in REST history yet. Reject
	// this globally unsupported shape before any conversation, device, or
	// roster lookup so every authenticated caller gets the same safe outcome.
	// The Service repeats the guard as defense in depth for non-WS callers.
	if msg != nil && msg.Sealed {
		status, message, reason := classifySendMessageError(chat.ErrSealedMessageUnsupported)
		c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
		return
	}

	// An accepted request remains replayable even when mutable conversation or
	// device state has changed since the original commit. The service compares
	// the canonical request digest and returns the durable ACK tuple. Replays
	// are ACKed here and deliberately never reach fan-out.
	replay, err := c.hub.chatSvc.LookupSendMessageReplay(ctx, c.userID, msg)
	if err != nil {
		status, message, reason := classifySendMessageLookupError(err)
		c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
		return
	}
	if replay != nil {
		c.sendMessageAck(seq, clientMessageID, replay)
		return
	}
	directV2, directShapeErr := validateDirectV2SendShape(msg)
	if directShapeErr != nil {
		status, message, reason := classifySendMessageError(directShapeErr)
		c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
		return
	}

	var secureRoster *db.ConversationDeviceRoster
	var messageSecurity *db.MessageSecurityContext
	var directSourceBinding, directTargetBinding *db.DeviceBinding
	if msg != nil && msg.ConversationId != "" {
		canSend, accessErr := c.hub.chatSvc.DB().CanAccessConversation(
			ctx, msg.ConversationId, c.userID,
			db.PermViewChannel|db.PermSendMessages,
		)
		if accessErr != nil {
			c.sendErrorWithSendMessageContext(
				seq, http.StatusInternalServerError, "internal error", clientMessageID, sendMessageReasonInternalError,
			)
			return
		}
		if !canSend {
			c.sendErrorWithSendMessageContext(
				seq, http.StatusForbidden, "not a conversation member", clientMessageID, sendMessageReasonNotMember,
			)
			return
		}
		conversationType, typeErr := c.hub.chatSvc.DB().GetConversationType(ctx, msg.ConversationId)
		if typeErr != nil {
			c.sendErrorWithSendMessageContext(
				seq, http.StatusBadRequest, "conversation not found", clientMessageID, sendMessageReasonConversationNotFound,
			)
			return
		}
		if conversationType == 1 || conversationType == 2 {
			if directV2 {
				status, message, reason := classifySendMessageError(chat.ErrInvalidSendMessage)
				c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
				return
			}
			if !c.perDeviceSecure || c.deviceBindingStatus != db.DeviceBindingActive ||
				c.deviceBindingVersion == 0 || len(c.deviceKey) != 16 {
				c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
					http.StatusConflict, "device_not_eligible", "device is not eligible for secure channel traffic", errDeviceNotEligible,
				), clientMessageID, sendMessageReasonDeviceNotEligible)
				return
			}
			var rosterErr error
			secureRoster, rosterErr = resolveExactReadyRoster(
				ctx, c.hub.chatSvc.DB(), msg.ConversationId,
				msg.GetRosterVersion(), msg.GetRosterCommitment(),
			)
			if rosterErr != nil {
				c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
					http.StatusConflict, "secure_roster_changed", "secure device roster changed; rotate and redistribute", rosterErr,
				), clientMessageID, sendMessageReasonSecureRosterChanged)
				return
			}
			source, sourceErr := findRosterDeviceByDatabaseID(secureRoster, c.deviceID)
			if sourceErr != nil || !bytes.Equal(source.device.DeviceKey, c.deviceKey) ||
				source.device.Binding.Version != c.deviceBindingVersion {
				c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
					http.StatusConflict, "device_not_eligible", "device is not eligible for secure channel traffic", errDeviceNotEligible,
				), clientMessageID, sendMessageReasonDeviceNotEligible)
				return
			}
			cryptoProfile := db.MessageCryptoProfileSenderKeyV5
			cryptoEra := db.MessageCryptoEraSenderKeyV5
			var membershipEpoch uint64
			var membershipEpochHash []byte
			membershipRecord, membershipErr := c.hub.chatSvc.DB().MembershipEpochForRosterForRequesterV1(
				ctx, msg.ConversationId, c.userID, secureRoster.Version, secureRoster.Commitment,
			)
			switch {
			case errors.Is(membershipErr, pgx.ErrNoRows):
				if msg.MembershipEpoch != 0 || len(msg.MembershipEpochHash) != 0 ||
					(msg.CryptoProfile != "" && msg.CryptoProfile != db.MessageCryptoProfileSenderKeyV5) ||
					(msg.CryptoProfile == "" && msg.CryptoEra != 0) ||
					(msg.CryptoProfile == db.MessageCryptoProfileSenderKeyV5 && msg.CryptoEra != db.MessageCryptoEraSenderKeyV5) {
					status, message, reason := classifySendMessageError(chat.ErrInvalidSendMessage)
					c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
					return
				}
			case membershipErr != nil:
				c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
					http.StatusConflict, "membership_epoch_changed", "signed membership changed; refresh the conversation and retry", membershipErr,
				), clientMessageID, sendMessageReasonSecureRosterChanged)
				return
			default:
				if membershipRecord == nil || msg.CryptoProfile != db.MessageCryptoProfileSenderKeyV6 ||
					msg.CryptoEra != db.MessageCryptoEraSenderKeyV6 ||
					msg.MembershipEpoch != membershipRecord.Epoch.Number ||
					!bytes.Equal(msg.MembershipEpochHash, membershipRecord.Hash[:]) {
					c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
						http.StatusConflict, "membership_epoch_changed", "signed membership changed; refresh the conversation and retry", db.ErrMembershipEpochRosterStale,
					), clientMessageID, sendMessageReasonSecureRosterChanged)
					return
				}
				cryptoProfile = db.MessageCryptoProfileSenderKeyV6
				cryptoEra = db.MessageCryptoEraSenderKeyV6
				membershipEpoch = membershipRecord.Epoch.Number
				membershipEpochHash = append([]byte(nil), membershipRecord.Hash[:]...)
			}
			messageSecurity = &db.MessageSecurityContext{
				CryptoProfile:          cryptoProfile,
				CryptoEra:              cryptoEra,
				RosterVersion:          secureRoster.Version,
				RosterCommitment:       append([]byte(nil), secureRoster.Commitment[:]...),
				MembershipEpoch:        membershipEpoch,
				MembershipEpochHash:    membershipEpochHash,
				SenderDeviceID:         append([]byte(nil), source.device.DeviceKey...),
				SenderBindingVersion:   source.device.Binding.Version,
				SenderDeviceDatabaseID: source.device.DeviceID,
			}
		} else {
			if msg.RosterVersion != 0 || len(msg.RosterCommitment) != 0 {
				status, message, reason := classifySendMessageError(chat.ErrInvalidSendMessage)
				c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
				return
			}
			if !directV2 && (msg.CryptoProfile != "" || msg.CryptoEra != 0 ||
				msg.MembershipEpoch != 0 || len(msg.MembershipEpochHash) != 0) {
				status, message, reason := classifySendMessageError(chat.ErrInvalidSendMessage)
				c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
				return
			}
			if directV2 {
				if !c.perDeviceSecure || c.deviceBindingStatus != db.DeviceBindingActive ||
					c.deviceBindingVersion == 0 || len(c.deviceKey) != 16 {
					c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
						http.StatusConflict, "device_not_eligible", "device is not eligible for Direct v2 traffic", errDeviceNotEligible,
					), clientMessageID, sendMessageReasonDeviceNotEligible)
					return
				}
				directSourceBinding, err = c.hub.chatSvc.DB().GetLatestDeviceBinding(ctx, c.deviceID)
				if err != nil || directSourceBinding.UserID != c.userID ||
					directSourceBinding.Status != db.DeviceBindingActive ||
					directSourceBinding.Version != c.deviceBindingVersion ||
					!bytes.Equal(directSourceBinding.DeviceKey, c.deviceKey) {
					c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
						http.StatusConflict, "device_not_eligible", "source device binding changed; re-authenticate", errDeviceNotEligible,
					), clientMessageID, sendMessageReasonDeviceNotEligible)
					return
				}
				directTargetBinding, err = c.hub.chatSvc.DB().GetLatestDeviceBindingByKey(ctx, msg.TargetDeviceId)
				if err != nil || directTargetBinding.UserID == c.userID ||
					directTargetBinding.Status != db.DeviceBindingActive ||
					directTargetBinding.Version != msg.TargetBindingVersion ||
					!bytes.Equal(directTargetBinding.DeviceKey, msg.TargetDeviceId) {
					c.sendMessagePublicError(seq, http.StatusConflict, publicerr.New(
						http.StatusConflict, "device_not_eligible", "target device binding changed; refresh the peer prekey", errDeviceNotEligible,
					), clientMessageID, sendMessageReasonDeviceNotEligible)
					return
				}
				messageSecurity = &db.MessageSecurityContext{
					CryptoProfile:             db.MessageCryptoProfileDirectV2,
					CryptoEra:                 db.MessageCryptoEraDirectV2,
					SenderDeviceID:            append([]byte(nil), directSourceBinding.DeviceKey...),
					SenderBindingVersion:      directSourceBinding.Version,
					SenderDeviceDatabaseID:    directSourceBinding.DeviceID,
					SenderDeviceIdentityKey:   append([]byte(nil), directSourceBinding.DeviceIdentityKey...),
					SenderDeviceSigningKey:    append([]byte(nil), directSourceBinding.DeviceSigningKey...),
					SenderDeviceCapabilities:  directSourceBinding.Capabilities,
					SenderDeviceBindingStatus: directSourceBinding.Status,
					SenderAccountSignature:    append([]byte(nil), directSourceBinding.AccountSignature...),
					TargetDeviceID:            append([]byte(nil), directTargetBinding.DeviceKey...),
					TargetBindingVersion:      directTargetBinding.Version,
					TargetDeviceDatabaseID:    directTargetBinding.DeviceID,
					DirectSessionID:           append([]byte(nil), msg.DirectSessionId...),
				}
			}
		}
	}

	var result *chat.SendMessageResult
	if messageSecurity != nil {
		result, err = c.hub.chatSvc.HandleSecureSendMessageResult(
			ctx, c.userID, msg, messageSecurity,
		)
	} else {
		result, err = c.hub.chatSvc.HandleSendMessageResult(ctx, c.userID, msg)
	}
	if err != nil {
		status, message, reason := classifySendMessageError(err)
		c.sendErrorWithSendMessageContext(seq, uint32(status), message, clientMessageID, reason)
		return
	}

	if !c.sendMessageAck(seq, clientMessageID, result) {
		return
	}
	if result.Replayed {
		return
	}

	// Fan-out MessageEvent to recipients
	event := &pb.Envelope{
		Timestamp: uint64(result.ServerTimestamp.UnixNano()),
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_NEW,
				MessageId:         result.MessageID,
				ConversationId:    msg.ConversationId,
				SenderIdentityKey: sender.identityKey,
				SenderUsername:    sender.username,
				ServerTimestamp:   uint64(result.ServerTimestamp.UnixNano()),
				Ciphertext:        msg.Ciphertext,
				Header:            msg.Header,
				MsgType:           &msg.MsgType,
				ReplyToId:         msg.ReplyToId,
				TtlSeconds:        msg.TtlSeconds,
				Attachments:       msg.Attachments,
				Sealed:            &msg.Sealed,
			},
		},
	}
	if messageSecurity != nil {
		messageEvent := event.GetMessageEvent()
		messageEvent.SenderDeviceId = append([]byte(nil), messageSecurity.SenderDeviceID...)
		messageEvent.CryptoProfile = messageSecurity.CryptoProfile
		messageEvent.CryptoEra = messageSecurity.CryptoEra
		messageEvent.SenderBindingVersion = messageSecurity.SenderBindingVersion
		switch messageSecurity.CryptoProfile {
		case db.MessageCryptoProfileSenderKeyV5, db.MessageCryptoProfileSenderKeyV6:
			messageEvent.RosterVersion = messageSecurity.RosterVersion
			messageEvent.RosterCommitment = append([]byte(nil), messageSecurity.RosterCommitment...)
			messageEvent.MembershipEpoch = messageSecurity.MembershipEpoch
			messageEvent.MembershipEpochHash = append([]byte(nil), messageSecurity.MembershipEpochHash...)
			c.hub.fanoutMessageEventToDevices(
				ctx, eligibleRosterRecipients(secureRoster, c.deviceID), event,
			)
			return
		case db.MessageCryptoProfileDirectV2:
			if directSourceBinding == nil || directTargetBinding == nil {
				log.Printf("Direct v2 committed without live binding snapshot: message_ref=%s", logsafe.Ref("message", result.MessageID))
				return
			}
			messageEvent.TargetDeviceId = append([]byte(nil), messageSecurity.TargetDeviceID...)
			messageEvent.TargetBindingVersion = messageSecurity.TargetBindingVersion
			messageEvent.DirectSessionId = append([]byte(nil), messageSecurity.DirectSessionID...)
			messageEvent.SenderUserId = c.userID
			messageEvent.SenderDeviceIdentityKey = append([]byte(nil), directSourceBinding.DeviceIdentityKey...)
			messageEvent.SenderDeviceSigningKey = append([]byte(nil), directSourceBinding.DeviceSigningKey...)
			messageEvent.SenderDeviceCapabilities = directSourceBinding.Capabilities
			messageEvent.SenderDeviceBindingStatus = uint32(directSourceBinding.Status)
			messageEvent.SenderAccountSignature = append([]byte(nil), directSourceBinding.AccountSignature...)
			data, marshalErr := proto.Marshal(event)
			if marshalErr != nil {
				log.Printf("Direct v2 message fanout marshal failed: class=%s", logsafe.ErrorClass(marshalErr))
				return
			}
			if !c.hub.enqueueToDevice(directTargetBinding.DeviceID, data) && c.hub.pushNotifier != nil {
				c.hub.pushNotifier.NotifyOffline(ctx, directTargetBinding.UserID, event)
			}
			return
		}
	}
	eventData, _ := proto.Marshal(event)

	c.hub.fanoutMessageEvent(ctx, result.Recipients, eventData, event)
}

func (c *Client) sendMessageAck(seq uint64, clientMessageID string, result *chat.SendMessageResult) bool {
	if result == nil {
		c.sendErrorWithSendMessageContext(
			seq, http.StatusInternalServerError, "internal error", clientMessageID, sendMessageReasonInternalError,
		)
		return false
	}
	ack := &pb.MessageAck{
		MessageId:       result.MessageID,
		ServerTimestamp: uint64(result.ServerTimestamp.UnixNano()),
		RefSeq:          seq,
		ClientMessageId: clientMessageID,
	}
	if result.AckRosterVersion != nil {
		version := *result.AckRosterVersion
		ack.RosterVersion = &version
	}
	if result.MembershipEpoch != nil {
		epoch := *result.MembershipEpoch
		ack.MembershipEpoch = &epoch
		ack.MembershipEpochHash = append([]byte(nil), result.MembershipHash...)
	}
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: uint64(result.ServerTimestamp.UnixNano()),
		Payload: &pb.Envelope_MessageAck{
			MessageAck: ack,
		},
	})
	return true
}

// --- Edit Message ---

func (c *Client) handleEditMessage(ctx context.Context, seq uint64, msg *pb.EditMessage) {
	sender, authenticated := c.snapshotAuthenticatedSender()
	if !authenticated {
		c.sendError(seq, http.StatusUnauthorized, "authentication required")
		return
	}

	conversationID, editedAt, recipients, err := c.hub.chatSvc.HandleEditMessage(ctx, c.userID, msg)
	if err != nil {
		c.sendPublicError(seq, http.StatusBadRequest, err)
		return
	}

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: uint64(editedAt.UnixNano()),
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{
				MessageId:       msg.MessageId,
				ServerTimestamp: uint64(editedAt.UnixNano()),
				RefSeq:          seq,
			},
		},
	})

	editTs := uint64(editedAt.UnixNano())
	event := &pb.Envelope{
		Timestamp: editTs,
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_EDITED,
				MessageId:         msg.MessageId,
				ConversationId:    conversationID,
				SenderIdentityKey: sender.identityKey,
				SenderUsername:    sender.username,
				ServerTimestamp:   editTs,
				Ciphertext:        msg.NewCiphertext,
				Header:            msg.NewHeader,
				EditTimestamp:     &editTs,
			},
		},
	}
	eventData, _ := proto.Marshal(event)
	for _, recipientID := range recipients {
		c.hub.sendToUser(recipientID, eventData)
	}
}

// --- Delete Message ---

func (c *Client) handleDeleteMessage(ctx context.Context, seq uint64, msg *pb.DeleteMessage) {
	sender, authenticated := c.snapshotAuthenticatedSender()
	if !authenticated {
		c.sendError(seq, http.StatusUnauthorized, "authentication required")
		return
	}

	conversationID, deletedAt, recipients, err := c.hub.chatSvc.HandleDeleteMessage(ctx, c.userID, msg)
	if err != nil {
		c.sendPublicError(seq, http.StatusBadRequest, err)
		return
	}

	deletedTimestamp := uint64(deletedAt.UnixNano())

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: deletedTimestamp,
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{
				MessageId:       msg.MessageId,
				ServerTimestamp: deletedTimestamp,
				RefSeq:          seq,
			},
		},
	})

	event := &pb.Envelope{
		Timestamp: deletedTimestamp,
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_DELETED,
				MessageId:         msg.MessageId,
				ConversationId:    conversationID,
				SenderIdentityKey: sender.identityKey,
				SenderUsername:    sender.username,
				ServerTimestamp:   deletedTimestamp,
			},
		},
	}
	eventData, _ := proto.Marshal(event)
	for _, recipientID := range recipients {
		c.hub.sendToUser(recipientID, eventData)
	}
}

// --- Reactions ---

func (c *Client) handleReaction(ctx context.Context, seq uint64, msg *pb.ReactionUpdate) {
	sender, authenticated := c.snapshotAuthenticatedSender()
	if !authenticated {
		c.sendError(seq, http.StatusUnauthorized, "authentication required")
		return
	}

	recipients, changed, err := c.hub.chatSvc.HandleReaction(ctx, c.userID, msg)
	if err != nil {
		switch {
		case errors.Is(err, chat.ErrReactionLimitReached):
			c.sendPublicError(seq, http.StatusConflict, publicerr.New(
				http.StatusConflict,
				"reaction_limit_reached",
				"message reaction limit reached",
				err,
			))
		case errors.Is(err, chat.ErrNotMember):
			c.sendPublicError(seq, http.StatusForbidden, err)
		case errors.Is(err, chat.ErrInvalidReaction),
			errors.Is(err, chat.ErrMessageConversationMismatch):
			c.sendPublicError(seq, http.StatusBadRequest, err)
		default:
			c.sendPublicError(seq, http.StatusInternalServerError, err)
		}
		return
	}

	// ACK to sender
	now := uint64(time.Now().UnixNano())
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: now,
		Payload:   &pb.Envelope_MessageAck{MessageAck: &pb.MessageAck{MessageId: msg.MessageId, ServerTimestamp: now, RefSeq: seq}},
	})
	if !changed {
		return
	}

	// Fan-out ReactionEvent to other members
	event := &pb.Envelope{
		Timestamp: now,
		Payload: &pb.Envelope_ReactionEvent{
			ReactionEvent: &pb.ReactionEvent{
				MessageId:      msg.MessageId,
				ConversationId: msg.ConversationId,
				Emoji:          msg.Emoji,
				UserId:         c.userID,
				Username:       sender.username,
				Add:            msg.Add,
			},
		},
	}
	eventData, _ := proto.Marshal(event)
	for _, recipientID := range recipients {
		c.hub.sendToUser(recipientID, eventData)
	}
}

// --- PreKey Request ---

func (c *Client) handlePreKeyRequest(ctx context.Context, seq uint64, req *pb.PreKeyRequest) {
	bundle, err := c.hub.chatSvc.HandlePreKeyRequest(ctx, c.userID, req.TargetIdentityKey)
	if err != nil {
		if errors.Is(err, chat.ErrPreKeyAccessDenied) {
			c.sendPublicError(seq, http.StatusForbidden, publicerr.New(
				http.StatusForbidden, "prekey_access_denied", "prekey access requires a shared conversation", err,
			))
			return
		}
		c.sendPublicError(seq, http.StatusNotFound, err)
		return
	}

	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_PrekeyBundle{
			PrekeyBundle: bundle,
		},
	})
}

// --- Presence / Typing (fan-out to conversation members) ---

// --- Sender Key Distribution ---

// validateSenderKeyEnvelope parses the public routing/authentication metadata
// of a v3 sealed SKDM. It intentionally accepts only v3; unauthenticated v1
// and the transitional v2 format are rejected fail-closed.
//
// Wire layout:
//
//	[0x03][u16be group_len][group][u32be generation]
//	[sender_ik 32][sender_signing_key 32][ephemeral_pub 32]
//	[nonce 24][ciphertext >= 16][Ed25519 signature 64]
func validateSenderKeyEnvelope(
	wire []byte,
	expectedConversationID string,
	expectedGeneration uint32,
	authenticatedIdentityKey []byte,
	pinnedSigningKey []byte,
	recipientIdentityKey []byte,
) error {
	const (
		version                  = byte(0x03)
		minimumAuthenticatedTail = 4 + 32 + 32 + 32 + 24 + 16 + 64
		maxWireBytes             = 4 * 1024
		maxCiphertextBytes       = 2 * 1024
	)
	if len(wire) > maxWireBytes {
		return fmt.Errorf("sealed SKDM exceeds size limit")
	}
	if len(wire) < 3+minimumAuthenticatedTail {
		return fmt.Errorf("sealed SKDM is too short")
	}
	if wire[0] != version {
		return fmt.Errorf("unsupported sealed SKDM version")
	}
	conversationUUID, uuidErr := uuid.Parse(expectedConversationID)
	if uuidErr != nil || conversationUUID.String() != expectedConversationID || expectedGeneration == 0 ||
		len(authenticatedIdentityKey) != 32 || len(pinnedSigningKey) != ed25519.PublicKeySize ||
		len(recipientIdentityKey) != 32 {
		return fmt.Errorf("invalid expected SKDM metadata")
	}

	groupLength := int(binary.BigEndian.Uint16(wire[1:3]))
	groupEnd := 3 + groupLength
	if groupLength == 0 || groupEnd > len(wire) || len(wire)-groupEnd < minimumAuthenticatedTail {
		return fmt.Errorf("invalid sealed SKDM group length")
	}
	if string(wire[3:groupEnd]) != expectedConversationID {
		return fmt.Errorf("sealed SKDM conversation binding mismatch")
	}

	cursor := groupEnd
	generation := binary.BigEndian.Uint32(wire[cursor : cursor+4])
	cursor += 4
	if generation == 0 || generation != expectedGeneration {
		return fmt.Errorf("sealed SKDM generation binding mismatch")
	}

	senderIdentity := wire[cursor : cursor+32]
	cursor += 32
	if subtle.ConstantTimeCompare(senderIdentity, authenticatedIdentityKey) != 1 {
		return fmt.Errorf("sealed SKDM sender identity binding mismatch")
	}

	senderSigningKey := wire[cursor : cursor+32]
	cursor += 32
	if subtle.ConstantTimeCompare(senderSigningKey, pinnedSigningKey) != 1 {
		return fmt.Errorf("sealed SKDM signing key binding mismatch")
	}

	ephemeralPublic := wire[cursor : cursor+32]
	cursor += 32
	allZero := byte(0)
	for _, value := range ephemeralPublic {
		allZero |= value
	}
	if allZero == 0 {
		return fmt.Errorf("sealed SKDM ephemeral key is invalid")
	}
	nonce := wire[cursor : cursor+24]
	cursor += 24
	signatureStart := len(wire) - ed25519.SignatureSize
	if signatureStart < cursor+16 {
		return fmt.Errorf("sealed SKDM ciphertext is too short")
	}
	ciphertext := wire[cursor:signatureStart]
	if len(ciphertext) > maxCiphertextBytes {
		return fmt.Errorf("sealed SKDM ciphertext exceeds size limit")
	}
	signature := wire[signatureStart:]

	const domain = "veil-sealed-skdm-v3"
	aad := make([]byte, 0, len(domain)+1+2+groupLength+4+32+32+32+32)
	aad = append(aad, domain...)
	aad = append(aad, version)
	aad = append(aad, wire[1:3]...)
	aad = append(aad, wire[3:groupEnd]...)
	aad = append(aad, wire[groupEnd:groupEnd+4]...)
	aad = append(aad, senderIdentity...)
	aad = append(aad, senderSigningKey...)
	aad = append(aad, recipientIdentityKey...)
	aad = append(aad, ephemeralPublic...)
	signed := make([]byte, 0, len(aad)+len(nonce)+len(ciphertext))
	signed = append(signed, aad...)
	signed = append(signed, nonce...)
	signed = append(signed, ciphertext...)
	if !ed25519.Verify(ed25519.PublicKey(pinnedSigningKey), signed, signature) {
		return fmt.Errorf("sealed SKDM signature is invalid")
	}
	return nil
}

// --- Presence / Typing (fan-out to conversation members) ---

func (c *Client) handleTyping(ctx context.Context, seq uint64, ev *pb.TypingEvent) {
	if ev == nil || ev.ConversationId == "" {
		c.sendError(seq, 400, "conversation_id required")
		return
	}
	isMember, err := c.hub.chatSvc.DB().CanAccessConversation(
		ctx,
		ev.ConversationId,
		c.userID,
		db.PermViewChannel|db.PermSendMessages,
	)
	if err != nil || !isMember {
		c.sendError(seq, 403, "not a conversation member")
		return
	}
	ev.IdentityKey = c.identityKey // Server sets sender identity
	members, err := authorizedTypingRecipients(ctx, c.hub.chatSvc.DB(), ev.ConversationId)
	if err != nil {
		return
	}
	data, _ := proto.Marshal(&pb.Envelope{
		Payload: &pb.Envelope_TypingEvent{TypingEvent: ev},
	})
	for _, uid := range members {
		if uid != c.userID {
			c.hub.sendToUser(uid, data)
		}
	}
}

type authorizedConversationMemberStore interface {
	GetAuthorizedConversationMembers(context.Context, string, uint64) ([]string, error)
}

// authorizedTypingRecipients uses the same permission-aware audience as
// message-history/live-message delivery. A server member whose channel access
// was revoked must not continue receiving conversation IDs or activity
// metadata merely because a stale conversation_members row still exists.
func authorizedTypingRecipients(ctx context.Context, store authorizedConversationMemberStore, conversationID string) ([]string, error) {
	return store.GetAuthorizedConversationMembers(ctx, conversationID, db.ChannelReadPermissions)
}

func (c *Client) handlePresence(ctx context.Context, ev *pb.PresenceUpdate) {
	ev.IdentityKey = c.identityKey
	// Only broadcast presence to friends
	friendIDs, err := c.hub.chatSvc.DB().GetFriendIDs(ctx, c.userID)
	if err != nil {
		log.Printf("presence: failed to get friends for user_ref=%s: class=%s", logsafe.Ref("user", c.userID), logsafe.ErrorClass(err))
		return
	}
	data, _ := proto.Marshal(&pb.Envelope{
		Payload: &pb.Envelope_PresenceUpdate{PresenceUpdate: ev},
	})
	for _, fid := range friendIDs {
		c.hub.sendToUser(fid, data)
	}
}

// broadcastPresenceOnDisconnect sends OFFLINE status to all friends when a user's last client disconnects.
func (h *Hub) broadcastPresenceOnDisconnect(userID string, identityKey []byte) {
	ctx := context.Background()
	friendIDs, err := h.chatSvc.DB().GetFriendIDs(ctx, userID)
	if err != nil || len(friendIDs) == 0 {
		return
	}
	now := uint64(time.Now().UnixNano())
	data, _ := proto.Marshal(&pb.Envelope{
		Payload: &pb.Envelope_PresenceUpdate{
			PresenceUpdate: &pb.PresenceUpdate{
				IdentityKey: identityKey,
				Status:      pb.PresenceStatus_PRESENCE_OFFLINE,
				LastSeen:    &now,
			},
		},
	})
	for _, fid := range friendIDs {
		h.sendToUser(fid, data)
	}
}

// --- Friends ---

func (c *Client) handleFriendRequest(ctx context.Context, seq uint64, req *pb.FriendRequest) {
	if !isValidFriendRequestInput(req.TargetUserId, req.Message) {
		c.sendError(seq, http.StatusBadRequest, "invalid friend request")
		return
	}
	// Prevent self-friend
	if req.TargetUserId == c.userID {
		c.sendError(seq, 400, "cannot send friend request to yourself")
		return
	}

	// Check target exists
	target, err := c.hub.chatSvc.DB().FindUserByID(ctx, req.TargetUserId)
	if err != nil {
		c.sendError(seq, 404, "user not found")
		return
	}

	// Check not already friends
	already, err := c.hub.chatSvc.DB().AreFriends(ctx, c.userID, req.TargetUserId)
	if err != nil {
		c.sendError(seq, 500, "internal error")
		return
	}
	if already {
		c.sendError(seq, 409, "already friends")
		return
	}

	// Check if there's already a pending request (either direction)
	pending, err := c.hub.chatSvc.DB().HasPendingFriendRequest(ctx, c.userID, req.TargetUserId)
	if err != nil {
		c.sendError(seq, 500, "internal error")
		return
	}
	if pending {
		c.sendError(seq, 409, "friend request already pending")
		return
	}

	var msg *string
	if req.Message != nil {
		msg = req.Message
	}
	reqID, createdAt, err := c.hub.chatSvc.DB().CreateFriendRequest(ctx, c.userID, req.TargetUserId, msg)
	if err != nil {
		c.sendPublicError(seq, http.StatusBadRequest, err)
		return
	}

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{RefSeq: seq},
		},
	})

	// Notify target user about the incoming friend request
	var msgStr string
	if msg != nil {
		msgStr = *msg
	}
	event := &pb.Envelope{
		Timestamp: uint64(createdAt.UnixNano()),
		Payload: &pb.Envelope_FriendRequestEvent{
			FriendRequestEvent: &pb.FriendRequestEvent{
				RequestId:    reqID,
				FromUserId:   c.userID,
				FromUsername: c.username,
				Message:      &msgStr,
				Timestamp:    uint64(createdAt.UnixNano()),
			},
		},
	}
	eventData, _ := proto.Marshal(event)
	c.hub.sendToUser(target.ID, eventData)
}

func (c *Client) handleFriendRespond(ctx context.Context, seq uint64, resp *pb.FriendRespond) {
	if !isCanonicalNonNilUUID(resp.RequestId) {
		c.sendError(seq, http.StatusBadRequest, "invalid friend request response")
		return
	}
	if resp.Accept {
		otherUserID, err := c.hub.chatSvc.DB().AcceptFriendRequest(ctx, resp.RequestId, c.userID)
		if err != nil {
			c.sendPublicError(seq, http.StatusBadRequest, err)
			return
		}

		// ACK to accepting user
		c.sendEnvelope(&pb.Envelope{
			Seq: seq,
			Payload: &pb.Envelope_MessageAck{
				MessageAck: &pb.MessageAck{RefSeq: seq},
			},
		})

		// Notify both users about new friendship
		acceptor, _ := c.hub.chatSvc.LookupUser(ctx, c.userID)
		requester, _ := c.hub.chatSvc.LookupUser(ctx, otherUserID)

		// Tell the original requester that their request was accepted
		if requester != nil {
			var acceptorName string
			if acceptor != nil {
				acceptorName = acceptor.Username
			}
			ev := &pb.Envelope{
				Timestamp: uint64(time.Now().UnixNano()),
				Payload: &pb.Envelope_FriendAcceptedEvent{
					FriendAcceptedEvent: &pb.FriendAcceptedEvent{
						UserId:   c.userID,
						Username: acceptorName,
					},
				},
			}
			data, _ := proto.Marshal(ev)
			c.hub.sendToUser(otherUserID, data)
		}

		// Tell the acceptor about the new friend (so they can update their list)
		if requester != nil {
			ev := &pb.Envelope{
				Timestamp: uint64(time.Now().UnixNano()),
				Payload: &pb.Envelope_FriendAcceptedEvent{
					FriendAcceptedEvent: &pb.FriendAcceptedEvent{
						UserId:   otherUserID,
						Username: requester.Username,
					},
				},
			}
			data, _ := proto.Marshal(ev)
			c.hub.sendToUser(c.userID, data)
		}
	} else {
		err := c.hub.chatSvc.DB().RejectFriendRequest(ctx, resp.RequestId, c.userID)
		if err != nil {
			c.sendPublicError(seq, http.StatusBadRequest, err)
			return
		}
		c.sendEnvelope(&pb.Envelope{
			Seq: seq,
			Payload: &pb.Envelope_MessageAck{
				MessageAck: &pb.MessageAck{RefSeq: seq},
			},
		})
	}
}

func (c *Client) handleFriendRemove(ctx context.Context, seq uint64, req *pb.FriendRemove) {
	if !isCanonicalNonNilUUID(req.UserId) {
		c.sendError(seq, http.StatusBadRequest, "invalid friend id")
		return
	}
	err := c.hub.chatSvc.DB().RemoveFriend(ctx, c.userID, req.UserId)
	if err != nil {
		c.sendPublicError(seq, http.StatusBadRequest, err)
		return
	}

	// ACK
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{RefSeq: seq},
		},
	})

	// Notify the removed friend
	ev := &pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_FriendRemovedEvent{
			FriendRemovedEvent: &pb.FriendRemovedEvent{
				UserId: c.userID,
			},
		},
	}
	data, _ := proto.Marshal(ev)
	c.hub.sendToUser(req.UserId, data)
}

func (c *Client) handleFriendListRequest(ctx context.Context, seq uint64) {
	dbObj := c.hub.chatSvc.DB()

	friends, err := dbObj.GetFriends(ctx, c.userID)
	if err != nil {
		c.sendError(seq, 500, "failed to get friends")
		return
	}

	pendingReqs, err := dbObj.GetPendingFriendRequests(ctx, c.userID)
	if err != nil {
		c.sendError(seq, 500, "failed to get friend requests")
		return
	}

	// Build friend entries with presence info
	var friendEntries []*pb.FriendEntry
	for _, f := range friends {
		entry := &pb.FriendEntry{
			UserId:   f.UserID,
			Username: f.Username,
			Status:   pb.PresenceStatus_PRESENCE_OFFLINE, // default
		}
		// Check if friend is currently online
		c.hub.mu.RLock()
		if clients, ok := c.hub.userClients[f.UserID]; ok {
			for client := range clients {
				if !client.closing.Load() {
					entry.Status = pb.PresenceStatus_PRESENCE_ONLINE
					break
				}
			}
		}
		c.hub.mu.RUnlock()
		friendEntries = append(friendEntries, entry)
	}

	// Build pending request entries
	var requestEntries []*pb.FriendRequestEntry
	for _, r := range pendingReqs {
		outgoing := r.FromUserID == c.userID
		var otherUserID string
		if outgoing {
			otherUserID = r.ToUserID
		} else {
			otherUserID = r.FromUserID
		}
		otherUser, _ := dbObj.FindUserByID(ctx, otherUserID)
		var otherUsername string
		if otherUser != nil {
			otherUsername = otherUser.Username
		}
		entry := &pb.FriendRequestEntry{
			RequestId:    r.ID,
			FromUserId:   r.FromUserID,
			FromUsername: otherUsername,
			Timestamp:    uint64(r.CreatedAt.UnixNano()),
			Outgoing:     outgoing,
		}
		if r.Message != nil {
			entry.Message = r.Message
		}
		requestEntries = append(requestEntries, entry)
	}

	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_FriendListResponse{
			FriendListResponse: &pb.FriendListResponse{
				Friends:         friendEntries,
				PendingRequests: requestEntries,
			},
		},
	})
}

func isCanonicalNonNilUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func isValidFriendRequestInput(targetUserID string, message *string) bool {
	return isCanonicalNonNilUUID(targetUserID) &&
		(message == nil || len(*message) <= maxFriendRequestMessageBytes)
}

// --- Helpers ---

func (c *Client) sendEnvelope(env *pb.Envelope) {
	data, err := marshalEnvelope(env)
	if err != nil {
		log.Printf("marshal error: class=%s", logsafe.ErrorClass(err))
		return
	}
	select {
	case c.send <- singleOutbound(data):
	default:
		c.failClosed()
	}
}

func marshalEnvelope(env *pb.Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("nil websocket envelope")
	}
	return proto.Marshal(env)
}

// enqueueBatch is used for authentication publication where dropping or
// partially ordering an envelope would be unsafe.
func (c *Client) enqueueBatch(batch outboundBatch) error {
	if len(batch.frames) == 0 {
		return errors.New("empty websocket batch")
	}
	for _, frame := range batch.frames {
		if len(frame) == 0 {
			return errors.New("empty websocket envelope")
		}
	}
	timer := time.NewTimer(writeWait)
	defer timer.Stop()
	select {
	case c.send <- batch:
		return nil
	case <-timer.C:
		c.failClosed()
		return errors.New("websocket send queue timeout")
	}
}

func (c *Client) enqueueData(data []byte) error {
	return c.enqueueBatch(singleOutbound(data))
}

func (c *Client) enqueueEnvelope(env *pb.Envelope) error {
	data, err := marshalEnvelope(env)
	if err != nil {
		return fmt.Errorf("marshal envelope: %w", err)
	}
	return c.enqueueData(data)
}

func (c *Client) sendError(refSeq uint64, code uint32, message string) {
	c.sendErrorWithSendMessageContext(refSeq, code, message, "", "")
}

func (c *Client) sendErrorWithSendMessageContext(refSeq uint64, code uint32, message, clientMessageID, reason string) {
	var refSeqPtr *uint64
	if refSeq > 0 {
		refSeqPtr = &refSeq
	}
	errorPayload := &pb.Error{
		Code:    code,
		Message: message,
		RefSeq:  refSeqPtr,
	}
	if clientMessageID != "" {
		canonical, valid := chat.CanonicalClientMessageID(&pb.SendMessage{ClientMessageId: clientMessageID})
		if valid {
			if reason == "" {
				reason = sendMessageReasonInternalError
			}
			errorPayload.ClientMessageId = &canonical
		} else {
			reason = sendMessageReasonInvalidClientMessageID
		}
	}
	if reason != "" {
		value := reason
		errorPayload.Reason = &value
	}
	c.sendEnvelope(&pb.Envelope{
		Payload: &pb.Envelope_Error{
			Error: errorPayload,
		},
	})
}

func (c *Client) sendPublicError(refSeq uint64, status int, err error) {
	c.sendError(refSeq, uint32(status), publicerr.Message(status, err))
}

func (c *Client) sendMessagePublicError(refSeq uint64, status int, err error, clientMessageID, reason string) {
	c.sendErrorWithSendMessageContext(
		refSeq, uint32(status), publicerr.Message(status, err), clientMessageID, reason,
	)
}

func (c *Client) sendPublicAuthFailure(seq uint64, err error) error {
	return c.sendAuthFailure(
		seq,
		pb.AuthFailureReason_AUTH_FAILURE_REASON_AUTHENTICATION_FAILED,
		publicerr.Message(http.StatusUnauthorized, err),
	)
}

// sendMappedAuthFailure exposes the two enrollment outcomes only after the
// auth service has completed account-key proof. Every earlier failure remains
// the same generic authentication result.
func (c *Client) sendMappedAuthFailure(seq uint64, err error) error {
	switch {
	case errors.Is(err, auth.ErrRegistrationClosed):
		return c.sendAuthFailure(
			seq,
			pb.AuthFailureReason_AUTH_FAILURE_REASON_REGISTRATION_CLOSED,
			"registration is closed",
		)
	case errors.Is(err, auth.ErrInviteInvalid):
		return c.sendAuthFailure(
			seq,
			pb.AuthFailureReason_AUTH_FAILURE_REASON_INVITE_INVALID,
			"invite is invalid, expired, or already used",
		)
	default:
		return c.sendPublicAuthFailure(seq, publicerr.New(
			http.StatusUnauthorized, "authentication_failed", "authentication failed", err,
		))
	}
}

func (c *Client) sendAuthFailure(seq uint64, reason pb.AuthFailureReason, message string) error {
	result := &pb.AuthResult{
		Success:       false,
		FailureReason: reason,
		ErrorMessage:  &message,
	}
	return c.enqueueEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_AuthResult{
			AuthResult: result,
		},
	})
}

func authResultEnvelope(seq uint64, success bool, userID, errMsg string, authDetails ...*auth.AuthResult) *pb.Envelope {
	result := &pb.AuthResult{Success: success}
	if success {
		result.UserId = &userID
		if len(authDetails) == 1 && authDetails[0] != nil {
			result.PerDeviceSecure = authDetails[0].PerDeviceSecure
			result.DeviceBindingVersion = authDetails[0].DeviceBindingVersion
			result.DeviceBindingStatus = pb.DeviceBindingStatus(authDetails[0].DeviceBindingStatus)
		}
	}
	if errMsg != "" {
		result.ErrorMessage = &errMsg
	}
	return &pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_AuthResult{
			AuthResult: result,
		},
	}
}

func (c *Client) sendAuthResult(seq uint64, success bool, userID, errMsg string, authDetails ...*auth.AuthResult) error {
	return c.enqueueEnvelope(authResultEnvelope(seq, success, userID, errMsg, authDetails...))
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.failClosed()
	}()

	for {
		select {
		case batch, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if !batch.publication.wait() {
				return
			}
			for _, message := range batch.frames {
				c.conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := c.conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
					log.Printf("write error [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
					return
				}
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// wsClientIP extracts the originating client IP for a WebSocket upgrade
// request, honouring X-Forwarded-For (first hop) when behind a reverse
// proxy. Returns "" if RemoteAddr is malformed and no XFF is set, in which
// case the per-IP cap is bypassed (callers handle this).
func wsClientIP(r *http.Request) string {
	return httpmw.ClientIP(r)
}
