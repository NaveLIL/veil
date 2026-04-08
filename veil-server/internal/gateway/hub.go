package gateway

import (
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	// Maximum message size in bytes (64KB)
	maxMessageSize = 64 * 1024
	// Time allowed to write a message to the peer
	writeWait = 10 * time.Second
	// Time allowed to read the next pong message from the peer
	pongWait = 60 * time.Second
	// Send pings to peer with this period (must be < pongWait)
	pingPeriod = (pongWait * 9) / 10
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		// Native clients (Tauri, React Native) don't send Origin header.
		// Reject browser-based connections to prevent CSWSH.
		origin := r.Header.Get("Origin")
		return origin == ""
	},
}

// Client represents a connected WebSocket client.
type Client struct {
	Hub  *Hub
	Conn *websocket.Conn
	Send chan []byte

	// Identity (set after authentication)
	IdentityKey []byte
	DeviceID    []byte
	Username    string
}

// Hub maintains the set of active clients and broadcasts messages.
type Hub struct {
	Clients    map[*Client]bool
	mu         sync.RWMutex
	Register   chan *Client
	Unregister chan *Client
	Broadcast  chan []byte
}

func NewHub() *Hub {
	return &Hub{
		Clients:    make(map[*Client]bool),
		Register:   make(chan *Client),
		Unregister: make(chan *Client),
		Broadcast:  make(chan []byte, 256),
	}
}

func (h *Hub) Run() {
	for {
		select {
		case client := <-h.Register:
			h.mu.Lock()
			h.Clients[client] = true
			h.mu.Unlock()
			log.Printf("client connected (total: %d)", len(h.Clients))

		case client := <-h.Unregister:
			h.mu.Lock()
			if _, ok := h.Clients[client]; ok {
				delete(h.Clients, client)
				close(client.Send)
			}
			h.mu.Unlock()
			log.Printf("client disconnected (total: %d)", len(h.Clients))

		case message := <-h.Broadcast:
			h.mu.RLock()
			var slow []*Client
			for client := range h.Clients {
				select {
				case client.Send <- message:
				default:
					slow = append(slow, client)
				}
			}
			h.mu.RUnlock()

			// Remove slow clients under write lock (avoids data race)
			if len(slow) > 0 {
				h.mu.Lock()
				for _, c := range slow {
					if _, ok := h.Clients[c]; ok {
						delete(h.Clients, c)
						close(c.Send)
					}
				}
				h.mu.Unlock()
			}
		}
	}
}

// HandleWebSocket upgrades HTTP to WebSocket and registers the client.
func HandleWebSocket(hub *Hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade error: %v", err)
		return
	}

	client := &Client{
		Hub:  hub,
		Conn: conn,
		Send: make(chan []byte, 256),
	}

	hub.Register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) readPump() {
	defer func() {
		c.Hub.Unregister <- c
		c.Conn.Close()
	}()

	c.Conn.SetReadLimit(maxMessageSize)
	c.Conn.SetReadDeadline(time.Now().Add(pongWait))
	c.Conn.SetPongHandler(func(string) error {
		c.Conn.SetReadDeadline(time.Now().Add(pongWait))
		return nil
	})

	for {
		_, message, err := c.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("read error: %v", err)
			}
			break
		}

		// TODO: Decode Protobuf Envelope, route to appropriate handler
		// For now: echo back
		c.Send <- message
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.Send:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				c.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			if err := c.Conn.WriteMessage(websocket.BinaryMessage, message); err != nil {
				log.Printf("write error: %v", err)
				return
			}
		case <-ticker.C:
			c.Conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.Conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}
