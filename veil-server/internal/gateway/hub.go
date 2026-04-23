package gateway

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/AegisSec/veil-server/internal/auth"
	"github.com/AegisSec/veil-server/internal/chat"
	"github.com/AegisSec/veil-server/internal/metrics"
	pb "github.com/AegisSec/veil-server/pkg/proto/v1"
)

const (
	maxMessageSize = 64 * 1024
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10

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
	send chan []byte

	// Connection ID for challenge tracking (not user-visible)
	connID string
	// Originating client IP (used for per-IP connection cap accounting).
	ip string

	// Identity (set after successful authentication)
	authenticated bool
	userID        string
	deviceID      string
	username      string
	identityKey   []byte

	// Rate limiting
	authAttempts int
}

// Hub maintains active clients and routes messages.
type Hub struct {
	// All connected clients
	clients map[*Client]bool
	// Index: userID → set of clients (for message fan-out)
	userClients map[string]map[*Client]bool
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
		clients:     make(map[*Client]bool),
		userClients: make(map[string]map[*Client]bool),
		ipConns:     make(map[string]int),
		register:    make(chan *Client),
		unregister:  make(chan *Client),
		authSvc:     authSvc,
		chatSvc:     chatSvc,
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

// indexClient adds a client to the userID index after authentication.
func (h *Hub) indexClient(client *Client) {
	h.mu.Lock()
	if h.userClients[client.userID] == nil {
		h.userClients[client.userID] = make(map[*Client]bool)
	}
	h.userClients[client.userID][client] = true
	h.mu.Unlock()
}

// sendToUser sends a serialized Envelope to all connections of a user.
func (h *Hub) sendToUser(userID string, data []byte) {
	h.mu.RLock()
	clients := h.userClients[userID]
	h.mu.RUnlock()

	for c := range clients {
		select {
		case c.send <- data:
		default:
			// Client too slow, will be cleaned up by writePump
		}
	}
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
		h.mu.RLock()
		clients := h.userClients[uid]
		online := len(clients) > 0
		h.mu.RUnlock()

		if online {
			for c := range clients {
				select {
				case c.send <- data:
				default:
				}
			}
			continue
		}
		if h.pushNotifier != nil {
			h.pushNotifier.NotifyOffline(ctx, uid, env)
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
		log.Printf("hub broadcast: marshal failed: %v", err)
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
		log.Printf("upgrade error: %v", err)
		return
	}

	connID := fmt.Sprintf("%p-%d", conn, time.Now().UnixNano())
	client := &Client{
		hub:    hub,
		conn:   conn,
		send:   make(chan []byte, 256),
		connID: connID,
		ip:     ip,
	}

	hub.register <- client

	// Send auth challenge immediately
	nonce, err := hub.authSvc.CreateChallenge(connID)
	if err != nil {
		log.Printf("failed to create challenge: %v", err)
		conn.Close()
		return
	}

	env := &pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_AuthChallenge{
			AuthChallenge: &pb.AuthChallenge{Challenge: nonce[:]},
		},
	}
	data, _ := proto.Marshal(env)
	client.send <- data

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
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
				log.Printf("read error [%s]: %v", c.connID, err)
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
	ctx := context.Background()

	switch payload := env.Payload.(type) {

	// === Auth Response ===
	case *pb.Envelope_AuthResponse:
		c.handleAuth(ctx, env.Seq, payload.AuthResponse)

	// === All other messages require authentication ===
	default:
		if !c.authenticated {
			c.sendError(env.Seq, 401, "not authenticated")
			return
		}

		// W10 — per-(user, kind) rate limit. Drop with a 429-equivalent
		// error so the client knows to back off, and increment the
		// rejected-total metric so ops can see the offender.
		kind := kindForUserBucket(envelopeKind(env))
		if !allowEnvelope(c.userID, kind) {
			c.sendError(env.Seq, 429, "ws rate limit exceeded for "+kind)
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
			c.handleTyping(ctx, p.TypingEvent)
		case *pb.Envelope_PresenceUpdate:
			c.handlePresence(ctx, p.PresenceUpdate)
		case *pb.Envelope_SenderKeyDist:
			c.handleSenderKeyDist(ctx, env.Seq, p.SenderKeyDist)
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

// --- Auth ---

func (c *Client) handleAuth(ctx context.Context, seq uint64, resp *pb.AuthResponse) {
	c.authAttempts++
	if c.authAttempts > 3 {
		c.sendError(seq, 429, "too many auth attempts")
		c.conn.Close()
		return
	}

	result, err := c.hub.authSvc.VerifyResponse(
		ctx, c.connID,
		resp.IdentityKey, resp.SigningKey, resp.Signature,
		resp.DeviceId, resp.DeviceName,
	)
	if err != nil {
		log.Printf("auth failed [%s]: %v", c.connID, err)
		metrics.WSAuthFailuresTotal.Inc()
		c.sendAuthResult(seq, false, "", err.Error())
		return
	}

	c.authenticated = true
	c.userID = result.UserID
	c.deviceID = result.DeviceID
	c.username = result.Username
	c.identityKey = resp.IdentityKey

	// Add to user index for message fan-out
	c.hub.indexClient(c)

	c.sendAuthResult(seq, true, result.UserID, "")
	log.Printf("auth success [%s]: user=%s device=%s", c.connID, c.username, c.deviceID)
}

// --- Chat ---

func (c *Client) handleSendMessage(ctx context.Context, seq uint64, msg *pb.SendMessage) {
	msgID, serverTime, recipients, err := c.hub.chatSvc.HandleSendMessage(ctx, c.userID, msg)
	if err != nil {
		c.sendError(seq, 400, err.Error())
		return
	}

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: uint64(serverTime.UnixNano()),
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{
				MessageId:       msgID,
				ServerTimestamp: uint64(serverTime.UnixNano()),
				RefSeq:          seq,
			},
		},
	})

	// Lookup sender info for the event
	sender, _ := c.hub.chatSvc.LookupUser(ctx, c.userID)
	var senderKey []byte
	var senderName string
	if sender != nil {
		senderKey = sender.IdentityKey
		senderName = sender.Username
	}

	// Fan-out MessageEvent to recipients
	event := &pb.Envelope{
		Timestamp: uint64(serverTime.UnixNano()),
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_NEW,
				MessageId:         msgID,
				ConversationId:    msg.ConversationId,
				SenderIdentityKey: senderKey,
				SenderUsername:    senderName,
				ServerTimestamp:   uint64(serverTime.UnixNano()),
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
	eventData, _ := proto.Marshal(event)

	c.hub.fanoutMessageEvent(ctx, recipients, eventData, event)
}

// --- Edit Message ---

func (c *Client) handleEditMessage(ctx context.Context, seq uint64, msg *pb.EditMessage) {
	editedAt, recipients, err := c.hub.chatSvc.HandleEditMessage(ctx, c.userID, msg)
	if err != nil {
		c.sendError(seq, 400, err.Error())
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

	sender, _ := c.hub.chatSvc.LookupUser(ctx, c.userID)
	var senderKey []byte
	var senderName string
	if sender != nil {
		senderKey = sender.IdentityKey
		senderName = sender.Username
	}

	editTs := uint64(editedAt.UnixNano())
	event := &pb.Envelope{
		Timestamp: editTs,
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_EDITED,
				MessageId:         msg.MessageId,
				ConversationId:    msg.ConversationId,
				SenderIdentityKey: senderKey,
				SenderUsername:    senderName,
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
	recipients, err := c.hub.chatSvc.HandleDeleteMessage(ctx, c.userID, msg)
	if err != nil {
		c.sendError(seq, 400, err.Error())
		return
	}

	now := uint64(time.Now().UnixNano())

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: now,
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{
				MessageId:       msg.MessageId,
				ServerTimestamp: now,
				RefSeq:          seq,
			},
		},
	})

	sender, _ := c.hub.chatSvc.LookupUser(ctx, c.userID)
	var senderKey []byte
	var senderName string
	if sender != nil {
		senderKey = sender.IdentityKey
		senderName = sender.Username
	}

	event := &pb.Envelope{
		Timestamp: now,
		Payload: &pb.Envelope_MessageEvent{
			MessageEvent: &pb.MessageEvent{
				EventType:         pb.MessageEvent_DELETED,
				MessageId:         msg.MessageId,
				ConversationId:    msg.ConversationId,
				SenderIdentityKey: senderKey,
				SenderUsername:    senderName,
				ServerTimestamp:   now,
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
	recipients, err := c.hub.chatSvc.HandleReaction(ctx, c.userID, msg)
	if err != nil {
		c.sendError(seq, 400, err.Error())
		return
	}

	// ACK to sender
	now := uint64(time.Now().UnixNano())
	c.sendEnvelope(&pb.Envelope{
		Seq:       seq,
		Timestamp: now,
		Payload:   &pb.Envelope_MessageAck{MessageAck: &pb.MessageAck{MessageId: msg.MessageId, ServerTimestamp: now, RefSeq: seq}},
	})

	// Lookup sender info
	sender, _ := c.hub.chatSvc.LookupUser(ctx, c.userID)
	var senderName string
	if sender != nil {
		senderName = sender.Username
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
				Username:       senderName,
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
	bundle, err := c.hub.chatSvc.HandlePreKeyRequest(ctx, req.TargetIdentityKey)
	if err != nil {
		c.sendError(seq, 404, err.Error())
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

func (c *Client) handleSenderKeyDist(ctx context.Context, seq uint64, skd *pb.SenderKeyDistribution) {
	// Verify sender is a member of the conversation
	isMember, err := c.hub.chatSvc.DB().IsConversationMember(ctx, skd.ConversationId, c.userID)
	if err != nil || !isMember {
		c.sendError(seq, 403, "not a group member")
		return
	}

	// Forward the sender key to the target user (find by identity key)
	target, err := c.hub.chatSvc.DB().FindUserByIdentityKey(ctx, skd.TargetIdentityKey)
	if err != nil {
		c.sendError(seq, 404, "target user not found")
		return
	}

	// Forward as-is to the target — client will decrypt with their ratchet session
	fwd := &pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_SenderKeyDist{
			SenderKeyDist: &pb.SenderKeyDistribution{
				ConversationId:    skd.ConversationId,
				SenderKeyMessage:  skd.SenderKeyMessage,
				Generation:        skd.Generation,
				TargetIdentityKey: skd.TargetIdentityKey,
			},
		},
	}
	data, _ := proto.Marshal(fwd)
	c.hub.sendToUser(target.ID, data)

	// ACK to sender
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_MessageAck{
			MessageAck: &pb.MessageAck{
				RefSeq: seq,
			},
		},
	})
}

// --- Presence / Typing (fan-out to conversation members) ---

func (c *Client) handleTyping(ctx context.Context, ev *pb.TypingEvent) {
	ev.IdentityKey = c.identityKey // Server sets sender identity
	members, err := c.hub.chatSvc.GetConversationMembers(ctx, ev.ConversationId)
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

func (c *Client) handlePresence(ctx context.Context, ev *pb.PresenceUpdate) {
	ev.IdentityKey = c.identityKey
	// Only broadcast presence to friends
	friendIDs, err := c.hub.chatSvc.DB().GetFriendIDs(ctx, c.userID)
	if err != nil {
		log.Printf("presence: failed to get friends for %s: %v", c.userID, err)
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
		c.sendError(seq, 400, err.Error())
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
	if resp.Accept {
		otherUserID, err := c.hub.chatSvc.DB().AcceptFriendRequest(ctx, resp.RequestId, c.userID)
		if err != nil {
			c.sendError(seq, 400, err.Error())
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
			c.sendError(seq, 400, err.Error())
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
	err := c.hub.chatSvc.DB().RemoveFriend(ctx, c.userID, req.UserId)
	if err != nil {
		c.sendError(seq, 400, err.Error())
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
		if clients, ok := c.hub.userClients[f.UserID]; ok && len(clients) > 0 {
			entry.Status = pb.PresenceStatus_PRESENCE_ONLINE
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

// --- Helpers ---

func (c *Client) sendEnvelope(env *pb.Envelope) {
	data, err := proto.Marshal(env)
	if err != nil {
		log.Printf("marshal error: %v", err)
		return
	}
	select {
	case c.send <- data:
	default:
	}
}

func (c *Client) sendError(refSeq uint64, code uint32, message string) {
	var refSeqPtr *uint64
	if refSeq > 0 {
		refSeqPtr = &refSeq
	}
	c.sendEnvelope(&pb.Envelope{
		Payload: &pb.Envelope_Error{
			Error: &pb.Error{
				Code:    code,
				Message: message,
				RefSeq:  refSeqPtr,
			},
		},
	})
}

func (c *Client) sendAuthResult(seq uint64, success bool, userID, errMsg string) {
	result := &pb.AuthResult{Success: success}
	if success {
		result.UserId = &userID
	}
	if errMsg != "" {
		result.ErrorMessage = &errMsg
	}
	c.sendEnvelope(&pb.Envelope{
		Seq: seq,
		Payload: &pb.Envelope_AuthResult{
			AuthResult: result,
		},
	})
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
				log.Printf("write error [%s]: %v", c.connID, err)
				return
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
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
