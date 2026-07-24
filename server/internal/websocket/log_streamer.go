package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// LogEntry represents a structured log message that will be sent to clients
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Message   string `json:"message"`
}

// LogStreamer handles capturing logs and streaming them to connected WebSocket clients
// It implements io.Writer to intercept log output and implements a pub/sub pattern
// for distributing log entries to multiple clients.
type LogStreamer struct {
	clients       map[*websocket.Conn]bool
	clientsMutex  sync.RWMutex
	logfile       *os.File
	upgrader      websocket.Upgrader
	logBuffer     []LogEntry // Circular buffer for recent log entries
	logBufferSize int
	bufferMutex   sync.RWMutex
	bufferIndex   int
}

// NewLogStreamer creates a new log streamer instance
//
// Pre-conditions:
//   - logfile is a valid, writable os.File
//
// Post-conditions:
//   - Returns an initialized LogStreamer
//   - LogStreamer is set up to capture log output and stream to clients
//   - Recent logs are retained in a circular buffer
func NewLogStreamer(logfile *os.File) *LogStreamer {
	return &LogStreamer{
		clients: make(map[*websocket.Conn]bool),
		logfile: logfile,
		upgrader: websocket.Upgrader{
			CheckOrigin: DefaultOriginCheck,
		},
		logBuffer:     make([]LogEntry, 100), // Retain last 100 log entries
		logBufferSize: 100,
	}
}

// SetCheckOrigin replaces the WebSocket origin policy used for upgrades.
// Passing nil restores the default same-origin policy.
func (ls *LogStreamer) SetCheckOrigin(checkOrigin func(*http.Request) bool) {
	if checkOrigin == nil {
		checkOrigin = DefaultOriginCheck
	}
	ls.upgrader.CheckOrigin = checkOrigin
}

// Write implements io.Writer to capture log output and distribute to clients
//
// Pre-conditions:
//   - p contains valid log data in expected format
//
// Post-conditions:
//   - Log data is written to the underlying log file
//   - Log data is parsed and distributed to connected clients
//   - Log entry is added to the circular buffer
//   - Returns number of bytes written and any write error
func (ls *LogStreamer) Write(p []byte) (n int, err error) {
	// Write to log file
	n, err = ls.logfile.Write(p)
	if err != nil {
		return n, err
	}

	// Parse log message assuming standard format: YYYY/MM/DD HH:MM:SS [LEVEL] Message
	logStr := string(p)
	level := "INFO"
	message := logStr

	// Extract log level if present
	if len(logStr) > 20 && logStr[19] == '[' {
		end := 0
		for i := 20; i < len(logStr); i++ {
			if logStr[i] == ']' {
				end = i
				break
			}
		}
		if end > 0 {
			level = logStr[20:end]
			message = logStr[end+1:]
		}
	}

	// Create log entry
	entry := LogEntry{
		Timestamp: time.Now().Format(time.RFC3339),
		Level:     level,
		Message:   message,
	}

	// Add to circular buffer
	ls.bufferMutex.Lock()
	ls.logBuffer[ls.bufferIndex] = entry
	ls.bufferIndex = (ls.bufferIndex + 1) % ls.logBufferSize
	ls.bufferMutex.Unlock()

	// Send to all connected clients
	ls.broadcast(entry)

	return n, nil
}

// HandleConnection handles new WebSocket connections for log streaming
//
// Pre-conditions:
//   - Valid HTTP request and response writer
//   - Client supports WebSocket protocol
//
// Post-conditions:
//   - WebSocket connection established with the client
//   - Recent logs sent to the client as initial history
//   - Client added to subscribers for future log events
//   - Connection handled until client disconnects
func (ls *LogStreamer) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := ls.upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Failed to upgrade connection
		log.Printf("failed to upgrade WebSocket connection: %v", err)
		return
	}

	// Add client to the clients map
	ls.clientsMutex.Lock()
	ls.clients[conn] = true
	ls.clientsMutex.Unlock()

	// Send recent log entries
	ls.sendRecentLogs(conn)

	// Handle ping-pong for connection keepalive
	conn.SetPingHandler(func(message string) error {
		// Respond with pong
		err := conn.WriteMessage(websocket.PongMessage, []byte("pong"))
		if err != nil {
			// Remove client on error
			ls.clientsMutex.Lock()
			delete(ls.clients, conn)
			ls.clientsMutex.Unlock()
			conn.Close()
		}
		return nil
	})

	// Listen for close message
	go func() {
		for {
			_, _, err := conn.ReadMessage()
			if err != nil {
				// Remove client on error or close
				ls.clientsMutex.Lock()
				delete(ls.clients, conn)
				ls.clientsMutex.Unlock()
				conn.Close()
				break
			}
		}
	}()
}

// broadcast sends a log entry to all connected WebSocket clients
//
// Pre-conditions:
//   - entry is a properly initialized LogEntry
//
// Post-conditions:
//   - Log entry is sent to all connected clients
//   - Failed connections are properly cleaned up
func (ls *LogStreamer) broadcast(entry LogEntry) {
	data, err := json.Marshal(entry)
	if err != nil {
		return
	}

	var clientsToRemove []*websocket.Conn

	// Send to all clients
	ls.clientsMutex.RLock()
	for client := range ls.clients {
		// Set a write deadline to avoid blocking on unresponsive clients
		client.SetWriteDeadline(time.Now().Add(10 * time.Second))
		err := client.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			// Mark client for removal
			clientsToRemove = append(clientsToRemove, client)
		}
	}
	ls.clientsMutex.RUnlock()

	// Ensure proper mutex protection for client management
	// All accesses to the `clients` map are guarded by `clientsMutex`.

	// Remove failed clients
	if len(clientsToRemove) > 0 {
		ls.clientsMutex.Lock()
		for _, client := range clientsToRemove {
			delete(ls.clients, client)
			client.Close()
		}
		ls.clientsMutex.Unlock()
	}
}

// sendRecentLogs sends recent log entries from the buffer to a newly connected client
//
// Pre-conditions:
//   - conn is a valid WebSocket connection
//
// Post-conditions:
//   - Recent log entries are sent to the client in chronological order
//   - Failed connections are properly handled
func (ls *LogStreamer) sendRecentLogs(conn *websocket.Conn) {
	ls.bufferMutex.RLock()
	defer ls.bufferMutex.RUnlock()

	// Send in chronological order
	for i := 0; i < ls.logBufferSize; i++ {
		index := (ls.bufferIndex + i) % ls.logBufferSize
		entry := ls.logBuffer[index]

		// Skip empty entries
		if entry.Timestamp == "" {
			continue
		}

		data, err := json.Marshal(entry)
		if err != nil {
			continue
		}

		err = conn.WriteMessage(websocket.TextMessage, data)
		if err != nil {
			return
		}
	}
}
