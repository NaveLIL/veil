package gateway

// ws_v3.go — /v3/events WebSocket transport (background events subprotocol).
//
// Wire contract (checked against the Rust client in veil-client, which
// enforces every rule below fail-closed):
//
//  1. Server sends exactly one Envelope{AuthChallengeV3} immediately after
//     upgrade: protocol_version=3, server_ephemeral = 32-byte X25519 public
//     key, canonical_node_origin = EXACT configured origin spelling.
//  2. Client answers with exactly one Envelope{AuthResponseV3}. The client
//     bounds its handshake at 8s; the server read deadline matches.
//  3. On success the server sends retained SenderKeyDist envelopes (and
//     NOTHING else) strictly BEFORE the successful Envelope{AuthResultV3}.
//     Any other pre-result frame fail-closes the client permanently.
//  4. The successful AuthResultV3 must echo protocol_version=3, the exact
//     canonical origin, user_id, per_device_secure, device_binding_version
//     and device_binding_status from the verified principal. Do not hardcode
//     "true"/ACTIVE: any incoherence is a client InvalidResult => NO retry.
//  5. A failure AuthResultV3 carries NO user_id, per_device_secure=false,
//     zero binding fields and one known non-zero failure_reason coherent
//     with the signed registration intent (classifyWSAuthV3AdmissionError
//     already guarantees that coherence). error_message is untrusted
//     diagnostic text only.
//  6. Internal server errors (config/origin/store unavailable, sender-key
//     restore failure, encode failure) close the socket WITHOUT any
//     AuthResultV3 on purpose: the client classifies a bare transport close
//     as RetryableTransport and reconnects with backoff, whereas an
//     AUTHENTICATION_FAILED result would permanently fail-close a healthy
//     client over a transient server problem.
//  7. Post-auth heartbeat: the client pings every 25s and enforces its own
//     75s liveness deadline. Overriding SetPingHandler removes gorilla's
//     automatic Pong, so the handler must send the Pong itself and also
//     refresh the server read deadline (readPump otherwise refreshes it only
//     on Pongs to the server's own pings).
//
// Registration in cmd/gateway/main.go:
//
//	mux.HandleFunc("/v3/events", func(w http.ResponseWriter, r *http.Request) {
//		gateway.HandleWebSocketV3(hub, w, r)
//	})
//
// Also append "Disallow: /v3/events" to cmd/gateway/web/robots.txt.
//
// VERIFY BEFORE COMMIT (declared in files I did not see; names inferred):
//   - pb.Envelope_AuthChallengeV3 / pb.Envelope_AuthResultV3 oneof wrapper
//     names. hub.go's env.GetAuthResponseV3() proves the Envelope oneof
//     already carries the v3 variants; the wrapper names follow protoc
//     conventions but the Envelope .pb.go was not provided.
//   - auth.WSAuthRegistrationExistingOnlyV3 / WSAuthRegistrationCreateOpenV3 /
//     WSAuthRegistrationCreateWithPassV3 constants (used inside
//     ws_v3_verifier.go, defined elsewhere in internal/auth).
//   - Whether publishAuthenticatedClient sets c.authenticated. The v2
//     handleAuth never sets it explicitly in hub.go, so it must happen inside
//     publication; if not, set it in the same place v2 does.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/proto"

	"github.com/NaveLIL/veil/veil-server/internal/auth"
	"github.com/NaveLIL/veil/veil-server/internal/logsafe"
	"github.com/NaveLIL/veil/veil-server/internal/metrics"
	pb "github.com/NaveLIL/veil/veil-server/pkg/proto/v1"
)

// wsV3AuthReadTimeout bounds the single AuthResponseV3 read. The Rust client
// aborts its own handshake at 8s; matching it keeps half-open sockets from
// parking a goroutine here.
const wsV3AuthReadTimeout = 8 * time.Second

// HandleWebSocketV3 serves one /v3/events connection using the shared
// connection primitives (per-IP cap, upgrader, Client, Hub registration,
// pumps, gated retained-batch publication) and the mandatory v3 handshake.
func HandleWebSocketV3(hub *Hub, w http.ResponseWriter, r *http.Request) {
	ip := wsClientIP(r)

	// Same pre-upgrade per-IP budget as /ws — shared across both endpoints so
	// mixing transports cannot double the cap.
	if !hub.tryAcquireIP(ip) {
		metrics.WSRefusedTotal.WithLabelValues("ip_cap").Inc()
		http.Error(w, "too many connections from this address", http.StatusTooManyRequests)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		metrics.WSRefusedTotal.WithLabelValues("upgrade_error").Inc()
		hub.releaseIP(ip)
		log.Printf("v3 upgrade error: class=%s", logsafe.ErrorClass(err))
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

	// The whole handshake runs synchronously on this goroutine BEFORE the
	// pumps start. Challenge write, the single response read and any failure
	// result write use the connection directly while it is still exclusively
	// owned, so a failure result is flushed before Close instead of racing a
	// writePump shutdown.
	if !client.runWSAuthV3(context.Background()) {
		// Pumps never started, so no readPump defer exists to return the
		// registered client, IP slot and send channel to Hub.Run (same
		// pattern as the v2 pre-pump failure path).
		hub.unregister <- client
		return
	}

	// Post-auth heartbeat: the v3 client pings every 25s. This override must
	// send the Pong itself (gorilla's default handler is replaced) and must
	// refresh the read deadline, because an idle background client produces
	// nothing but Pings for hours.
	conn.SetPingHandler(func(message string) error {
		conn.SetReadDeadline(time.Now().Add(pongWait))
		err := conn.WriteControl(websocket.PongMessage, []byte(message), time.Now().Add(writeWait))
		if err == websocket.ErrCloseSent {
			return nil
		}
		return err
	})

	go client.writePump()
	go client.readPump()
}

// runWSAuthV3 performs the single-attempt v3 handshake. takeChallenge burns
// the pending challenge on first use, so a retry requires a fresh connection
// with a fresh server ephemeral.
func (c *Client) runWSAuthV3(ctx context.Context) bool {
	challenge, err := c.hub.authSvc.CreateChallengeV3(c.connID)
	if err != nil {
		log.Printf("v3 challenge failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}

	if !c.writeEnvelopeDirectV3(&pb.Envelope{
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_AuthChallengeV3{
			AuthChallengeV3: &pb.AuthChallengeV3{
				ProtocolVersion:     challenge.ProtocolVersion,
				ServerEphemeral:     challenge.ServerEphemeral[:],
				CanonicalNodeOrigin: challenge.CanonicalOrigin,
			},
		},
	}) {
		return false
	}

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(wsV3AuthReadTimeout))
	msgType, message, err := c.conn.ReadMessage()
	if err != nil {
		log.Printf("v3 auth read failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}

	var env pb.Envelope
	if msgType != websocket.BinaryMessage || proto.Unmarshal(message, &env) != nil {
		metrics.WSAuthFailuresTotal.Inc()
		c.failClosed()
		return false
	}
	metrics.WSMessagesTotal.WithLabelValues(envelopeKind(&env)).Inc()

	resp := env.GetAuthResponseV3()
	if resp == nil {
		// The only legal first frame on /v3/events is AuthResponseV3.
		metrics.WSAuthFailuresTotal.Inc()
		c.failClosed()
		return false
	}
	// VerifyResponseV3 clears its copy of this decoded bearer, but clear here
	// too so pre-verifier rejects never leave it in the heap.
	defer clear(resp.NodeAccessPass)

	binding, err := deviceBindingFromProto(resp.GetDeviceBinding())
	if err != nil || binding == nil {
		// v3 requires an explicit, well-formed device binding.
		metrics.WSAuthFailuresTotal.Inc()
		c.rejectWSAuthV3(env.Seq, challenge.CanonicalOrigin,
			pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_AUTHENTICATION_FAILED,
			"WebSocket authentication failed")
		return false
	}

	intent, ok := wsRegistrationIntentV3FromProto(resp.GetRegistrationIntent())
	if !ok {
		metrics.WSAuthFailuresTotal.Inc()
		c.rejectWSAuthV3(env.Seq, challenge.CanonicalOrigin,
			pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_AUTHENTICATION_FAILED,
			"WebSocket authentication failed")
		return false
	}

	verified, err := c.hub.authSvc.VerifyResponseV3(ctx, c.connID, auth.WSAuthV3ResponseInput{
		ProtocolVersion:       resp.GetProtocolVersion(),
		IdentityKey:           resp.GetIdentityKey(),
		SigningKey:            resp.GetSigningKey(),
		AccountProofSignature: resp.GetAccountProofSignature(),
		DeviceID:              resp.GetDeviceId(),
		DeviceName:            resp.GetDeviceName(),
		ClientVersion:         resp.GetClientVersion(),
		DeviceBinding:         binding,
		DeviceProofSignature:  resp.GetDeviceProofSignature(),
		RegistrationIntent:    intent,
		NodeAccessPass:        resp.GetNodeAccessPass(),
	})
	if err != nil {
		metrics.WSAuthFailuresTotal.Inc()
		log.Printf("v3 auth failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		var failure *auth.WSAuthV3Failure
		if errors.As(err, &failure) {
			// Public-safe vocabulary; failure.Error() is fixed non-secret
			// text and the reason is already intent-coherent.
			c.rejectWSAuthV3(env.Seq, challenge.CanonicalOrigin,
				wsAuthFailureReasonV3ToProto(failure.Reason()), failure.Error())
		} else {
			// Internal/config error: close WITHOUT a result so the client
			// sees a retryable transport failure, not a permanent rejection.
			c.failClosed()
		}
		return false
	}

	principal := verified.Principal()
	c.userID = principal.UserID
	c.deviceID = principal.DeviceID
	c.deviceKey = append([]byte(nil), resp.GetDeviceId()...)
	c.username = principal.Username
	c.identityKey = append([]byte(nil), resp.GetIdentityKey()...)
	c.perDeviceSecure = principal.PerDeviceSecure
	c.deviceBindingVersion = principal.DeviceBindingVersion
	c.deviceBindingStatus = principal.DeviceBindingStatus

	// A database failure forces a reconnect so the client cannot run without
	// the latest retained generation. Close
	// without a result => retryable on the client.
	pendingSenderKeys, err := c.pendingSenderKeyEnvelopes(ctx)
	if err != nil {
		log.Printf("v3 auth state restore failed [%s]: reason=%s", c.connID, senderKeyRestoreErrorLabel(err))
		c.failClosed()
		return false
	}

	authData, err := marshalEnvelope(wsAuthResultV3SuccessEnvelope(env.Seq, verified))
	if err != nil {
		log.Printf("v3 auth result encode failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}

	// Retained SenderKeyDist frames strictly BEFORE the success result, as one
	// gated FIFO batch. writePump (started by the caller) may dequeue it, but
	// cannot expose any frame until the Hub has atomically published this
	// connection; live fan-out can only enqueue behind the complete batch.
	frames := make([][]byte, 0, len(pendingSenderKeys)+1)
	frames = append(frames, pendingSenderKeys...)
	frames = append(frames, authData)
	gate := newPublicationGate()
	if err := c.enqueueBatch(outboundBatch{frames: frames, publication: gate}); err != nil {
		gate.resolve(false)
		log.Printf("v3 auth result queue failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}
	if !c.hub.publishAuthenticatedClient(c, gate) {
		log.Printf("v3 auth publication failed [%s]", c.connID)
		c.failClosed()
		return false
	}

	log.Printf("v3 auth success [%s]: user_ref=%s device_ref=%s",
		c.connID, logsafe.Ref("user", c.userID), logsafe.Ref("device", c.deviceID))
	return true
}

// writeEnvelopeDirectV3 writes one envelope while this goroutine still owns
// the connection exclusively (before the pumps start). Never call it after
// writePump is running.
func (c *Client) writeEnvelopeDirectV3(env *pb.Envelope) bool {
	data, err := marshalEnvelope(env)
	if err != nil {
		log.Printf("v3 envelope encode failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}
	c.conn.SetWriteDeadline(time.Now().Add(writeWait))
	if err := c.conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
		log.Printf("v3 write failed [%s]: class=%s", c.connID, logsafe.ErrorClass(err))
		c.failClosed()
		return false
	}
	return true
}

// rejectWSAuthV3 flushes one canonical failure result and fail-closes.
// Canonical failure shape: no user_id, per_device_secure=false, binding
// version 0 / status UNSPECIFIED, exactly one known non-zero reason, and the
// exact configured canonical origin echo.
func (c *Client) rejectWSAuthV3(seq uint64, canonicalOrigin string, reason pb.WsAuthFailureReasonV3, message string) {
	env := &pb.Envelope{
		Seq:       seq,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_AuthResultV3{
			AuthResultV3: &pb.AuthResultV3{
				ProtocolVersion:     auth.WSAuthProtocolVersionV3,
				Success:             false,
				ErrorMessage:        &message,
				FailureReason:       reason,
				CanonicalNodeOrigin: canonicalOrigin,
			},
		},
	}
	// Best effort: writeEnvelopeDirectV3 already fail-closes on write errors.
	if c.writeEnvelopeDirectV3(env) {
		c.failClosed()
	}
}

// wsAuthResultV3SuccessEnvelope echoes the verified principal. Nothing here
// may be hardcoded: the Rust client cross-checks protocol version, origin,
// user id canonicality, per_device_secure and the binding version/status, and
// treats any incoherence as a permanent (non-retryable) InvalidResult.
func wsAuthResultV3SuccessEnvelope(seq uint64, verified *auth.WSAuthV3VerifiedResult) *pb.Envelope {
	principal := verified.Principal()
	userID := principal.UserID
	return &pb.Envelope{
		Seq:       seq,
		Timestamp: uint64(time.Now().UnixNano()),
		Payload: &pb.Envelope_AuthResultV3{
			AuthResultV3: &pb.AuthResultV3{
				ProtocolVersion:      verified.ProtocolVersion(),
				Success:              true,
				UserId:               &userID,
				PerDeviceSecure:      principal.PerDeviceSecure,
				DeviceBindingVersion: principal.DeviceBindingVersion,
				DeviceBindingStatus:  pb.DeviceBindingStatus(principal.DeviceBindingStatus),
				FailureReason:        pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_UNSPECIFIED,
				CanonicalNodeOrigin:  verified.CanonicalOrigin(),
			},
		},
	}
}

// wsRegistrationIntentV3FromProto maps the signed wire intent onto the
// verifier vocabulary. UNSPECIFIED and unknown values are rejected before the
// verifier runs; the verifier re-checks intent coherence anyway.
func wsRegistrationIntentV3FromProto(intent pb.WsRegistrationIntentV3) (auth.WSAuthRegistrationIntentV3, bool) {
	switch intent {
	case pb.WsRegistrationIntentV3_WS_REGISTRATION_INTENT_V3_EXISTING:
		return auth.WSAuthRegistrationExistingOnlyV3, true
	case pb.WsRegistrationIntentV3_WS_REGISTRATION_INTENT_V3_OPEN:
		return auth.WSAuthRegistrationCreateOpenV3, true
	case pb.WsRegistrationIntentV3_WS_REGISTRATION_INTENT_V3_PASS:
		return auth.WSAuthRegistrationCreateWithPassV3, true
	default:
		return 0, false
	}
}

// wsAuthFailureReasonV3ToProto maps the verifier's public-safe reasons onto
// the wire enum. Anything unknown collapses to AUTHENTICATION_FAILED.
func wsAuthFailureReasonV3ToProto(reason auth.WSAuthV3FailureReason) pb.WsAuthFailureReasonV3 {
	switch reason {
	case auth.WSAuthV3RegistrationClosed:
		return pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_REGISTRATION_CLOSED
	case auth.WSAuthV3NodeAccessPassInvalid:
		return pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_NODE_ACCESS_PASS_INVALID
	default:
		return pb.WsAuthFailureReasonV3_WS_AUTH_FAILURE_REASON_V3_AUTHENTICATION_FAILED
	}
}
