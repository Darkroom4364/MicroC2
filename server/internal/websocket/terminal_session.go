package websocket

import (
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gorilla/websocket"
)

// TerminalSession represents a user's terminal session on the server
// It maintains state about the current working directory and command context.
type TerminalSession struct {
	WorkingDir string
}

// TerminalRequest defines the structure of requests from the client
type TerminalRequest struct {
	Type    string `json:"type,omitempty"`
	Partial string `json:"partial,omitempty"`
}

// TerminalResponse defines the structure of responses sent back to the client
// It provides command output, current working directory, and error status.
type TerminalResponse struct {
	Output      string   `json:"output,omitempty"`
	CWD         string   `json:"cwd,omitempty"`
	Error       bool     `json:"error,omitempty"`
	Type        string   `json:"type,omitempty"`
	Completions []string `json:"completions,omitempty"`
}

// TerminalHandler manages terminal websocket sessions
type TerminalHandler struct {
	upgrader websocket.Upgrader
}

// NewTerminalHandler creates a new terminal handler with configured websocket settings
//
// Pre-conditions:
//   - None
//
// Post-conditions:
//   - Returns a properly initialized TerminalHandler with CORS support
func NewTerminalHandler() *TerminalHandler {
	return &TerminalHandler{
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true
			},
		},
	}
}

// HandleConnection handles a new terminal websocket connection
//
// Pre-conditions:
//   - Valid HTTP request and response writer
//   - Client supports WebSocket protocol
//
// Post-conditions:
//   - WebSocket connection established with the client
//   - Terminal session started and commands processed until disconnection
//   - Resources properly cleaned up when the connection is closed
func (h *TerminalHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	session := &TerminalSession{
		WorkingDir: os.Getenv("HOME"),
	}

	// Send initial connection message with working directory
	initialResponse := TerminalResponse{
		Output: "Connected to server terminal (Bash shell).\n",
		CWD:    formatPath(session.WorkingDir),
	}
	msg, _ := json.Marshal(initialResponse)
	conn.WriteMessage(websocket.TextMessage, msg)

	for {
		// Read message from the WebSocket
		_, message, err := conn.ReadMessage()
		if err != nil {
			break
		}

		// Try to parse as JSON first (for tab completion and other structured requests)
		var request TerminalRequest
		if err := json.Unmarshal(message, &request); err == nil {
			// Handle structured requests
			if request.Type == "tab_completion" {
				h.handleTabCompletion(conn, session, request.Partial)
				continue
			}
		}

		// Handle as plain text command
		command := string(message)

		// Handle built-in commands
		if command == "pwd" {
			response := TerminalResponse{
				Output: session.WorkingDir + "\n",
				CWD:    formatPath(session.WorkingDir),
			}
			msg, _ := json.Marshal(response)
			conn.WriteMessage(websocket.TextMessage, msg)
			continue
		}

		if strings.HasPrefix(command, "cd ") {
			dir := strings.TrimSpace(strings.TrimPrefix(command, "cd "))
			if dir == "~" {
				dir = os.Getenv("HOME")
			} else if strings.HasPrefix(dir, "~/") {
				dir = filepath.Join(os.Getenv("HOME"), dir[2:])
			} else if !filepath.IsAbs(dir) {
				dir = filepath.Join(session.WorkingDir, dir)
			}

			if _, err := os.Stat(dir); err == nil {
				session.WorkingDir = dir
				response := TerminalResponse{
					CWD: formatPath(session.WorkingDir),
				}
				msg, _ := json.Marshal(response)
				conn.WriteMessage(websocket.TextMessage, msg)
			} else {
				response := TerminalResponse{
					Output: "cd: " + dir + ": No such file or directory\n",
					Error:  true,
					CWD:    formatPath(session.WorkingDir),
				}
				msg, _ := json.Marshal(response)
				conn.WriteMessage(websocket.TextMessage, msg)
			}
			continue
		}

		// Execute command
		cmd := exec.Command("/bin/bash", "-c", command)
		cmd.Dir = session.WorkingDir
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")

		output, err := cmd.CombinedOutput()

		response := TerminalResponse{
			Output: string(output),
			CWD:    formatPath(session.WorkingDir),
			Error:  err != nil,
		}

		msg, _ := json.Marshal(response)
		conn.WriteMessage(websocket.TextMessage, msg)
	}
}

// handleTabCompletion processes tab completion requests
//
// Pre-conditions:
//   - conn is a valid websocket connection
//   - session contains current working directory state
//   - partial contains the partial command/path to complete
//
// Post-conditions:
//   - Sends back completion suggestions to the client
//   - Handles file/directory completion and basic command completion
func (h *TerminalHandler) handleTabCompletion(conn *websocket.Conn, session *TerminalSession, partial string) {
	completions := h.getCompletions(session, partial)
	
	response := TerminalResponse{
		Type:        "tab_completion",
		Completions: completions,
	}
	
	msg, _ := json.Marshal(response)
	conn.WriteMessage(websocket.TextMessage, msg)
}

// getCompletions generates completion suggestions based on the partial input
//
// Pre-conditions:
//   - session contains valid working directory
//   - partial contains the text to complete
//
// Post-conditions:
//   - Returns a slice of completion suggestions
//   - Handles both command and file/directory completion
func (h *TerminalHandler) getCompletions(session *TerminalSession, partial string) []string {
	// Split command into words
	words := strings.Fields(partial)
	
	// If no words or first word, suggest commands
	if len(words) == 0 || (len(words) == 1 && !strings.HasSuffix(partial, " ")) {
		return h.getCommandCompletions(partial)
	}
	
	// Otherwise, complete file paths for the last word
	lastWord := words[len(words)-1]
	if strings.HasSuffix(partial, " ") {
		lastWord = ""
	}
	
	return h.getPathCompletions(session, lastWord)
}

// getCommandCompletions returns basic shell command completions
//
// Pre-conditions:
//   - partial contains the partial command to complete
//
// Post-conditions:
//   - Returns a slice of matching command suggestions
func (h *TerminalHandler) getCommandCompletions(partial string) []string {
	commands := []string{
		"ls", "cd", "pwd", "cat", "grep", "find", "mkdir", "rmdir", "rm", "cp", "mv",
		"chmod", "chown", "du", "df", "ps", "top", "kill", "which", "whereis",
		"echo", "less", "more", "head", "tail", "wc", "sort", "uniq", "awk", "sed",
		"tar", "gzip", "gunzip", "zip", "unzip", "curl", "wget", "ssh", "scp",
		"git", "nano", "vim", "emacs", "python", "python3", "node", "go", "make",
	}
	
	var matches []string
	for _, cmd := range commands {
		if strings.HasPrefix(cmd, partial) {
			matches = append(matches, cmd)
		}
	}
	
	sort.Strings(matches)
	return matches
}

// getPathCompletions returns file and directory completion suggestions
//
// Pre-conditions:
//   - session contains valid working directory
//   - partial contains the partial path to complete
//
// Post-conditions:
//   - Returns a slice of matching file/directory suggestions
//   - Handles relative and absolute paths, and ~ expansion
func (h *TerminalHandler) getPathCompletions(session *TerminalSession, partial string) []string {
	var searchDir, prefix string
	
	// Handle different path types
	if partial == "" {
		searchDir = session.WorkingDir
		prefix = ""
	} else if strings.HasPrefix(partial, "/") {
		// Absolute path
		searchDir = filepath.Dir(partial)
		prefix = filepath.Base(partial)
		if partial == "/" {
			searchDir = "/"
			prefix = ""
		}
	} else if strings.HasPrefix(partial, "~/") {
		// Home directory path
		home := os.Getenv("HOME")
		if partial == "~/" {
			searchDir = home
			prefix = ""
		} else {
			relativePath := partial[2:]
			searchDir = filepath.Join(home, filepath.Dir(relativePath))
			prefix = filepath.Base(relativePath)
		}
	} else if partial == "~" {
		// Just tilde
		return []string{"~/"}
	} else {
		// Relative path
		if strings.Contains(partial, "/") {
			searchDir = filepath.Join(session.WorkingDir, filepath.Dir(partial))
			prefix = filepath.Base(partial)
		} else {
			searchDir = session.WorkingDir
			prefix = partial
		}
	}
	
	// Read directory contents
	entries, err := os.ReadDir(searchDir)
	if err != nil {
		return []string{}
	}
	
	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		
		// Skip hidden files unless prefix starts with .
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(prefix, ".") {
			continue
		}
		
		// Check if name matches prefix
		if strings.HasPrefix(name, prefix) {
			completionName := name
			
			// Add trailing slash for directories
			if entry.IsDir() {
				completionName += "/"
			}
			
			// Build the full completion based on the original partial path
			var fullCompletion string
			if strings.HasPrefix(partial, "/") {
				fullCompletion = filepath.Join(searchDir, completionName)
			} else if strings.HasPrefix(partial, "~/") {
				home := os.Getenv("HOME")
				relativePath := strings.TrimPrefix(searchDir, home)
				if relativePath == "" {
					fullCompletion = "~/" + completionName
				} else {
					fullCompletion = "~" + filepath.Join(relativePath, completionName)
				}
			} else if strings.Contains(partial, "/") {
				dirPart := filepath.Dir(partial)
				fullCompletion = filepath.Join(dirPart, completionName)
			} else {
				fullCompletion = completionName
			}
			
			matches = append(matches, fullCompletion)
		}
	}
	
	sort.Strings(matches)
	return matches
}

// formatPath formats the path for display in the terminal prompt
// It replaces the home directory with ~ for better readability
//
// Pre-conditions:
//   - path is a valid filesystem path
//
// Post-conditions:
//   - Returns the formatted path with home directory replaced by ~
func formatPath(path string) string {
	home := os.Getenv("HOME")
	if strings.HasPrefix(path, home) {
		return "~" + strings.TrimPrefix(path, home)
	}
	return path
}
