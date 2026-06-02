class DashboardManager {
    constructor() {
        this.autoScroll = true;
        this.previousListenerStates = new Map();
        this.previousAgentStates = new Map();
        this.logWebSocket = null;
        this.wsReconnectAttempts = 0;
        this.MAX_RECONNECT_ATTEMPTS = 10;
        this.RECONNECT_DELAY = 2000;
        this.reconnectTimer = null;

        this.initializeWebSocket();
        this.setupEventListeners();

        this.selectedAgentId = null;
        this.resultsPollingInterval = null;

        // Periodically refresh active components
        this.loadActiveListeners();
        setInterval(() => this.loadActiveListeners(), 10000);
        
        this.loadActiveAgents();
        setInterval(() => this.loadActiveAgents(), 5000); // Update agents every 5 seconds
    }

    initializeWebSocket() {
        if (this.wsReconnectAttempts >= this.MAX_RECONNECT_ATTEMPTS) {
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: 'Maximum WebSocket reconnection attempts reached. Please refresh the page.',
                source: 'system'
            });
            return;
        }

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/logs`;
        
        if (this.logWebSocket) {
            this.logWebSocket.close();
        }

        this.logWebSocket = new WebSocket(wsUrl);
        
        // Set a timeout for the initial connection
        const connectionTimeout = setTimeout(() => {
            if (this.logWebSocket.readyState !== WebSocket.OPEN) {
                this.logWebSocket.close();
                this.handleReconnect();
            }
        }, 5000);

        this.logWebSocket.onopen = () => {
            clearTimeout(connectionTimeout);
            this.wsReconnectAttempts = 0;
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'INFO',
                message: 'Connected to server log stream',
                source: 'system'
            });

            // Set up ping interval
            const pingInterval = setInterval(() => {
                if (this.logWebSocket.readyState === WebSocket.OPEN) {
                    this.logWebSocket.send('ping');
                } else {
                    clearInterval(pingInterval);
                }
            }, 30000);

            // Clean up ping interval when socket closes
            this.logWebSocket.addEventListener('close', () => clearInterval(pingInterval));
        };

        this.logWebSocket.onmessage = (event) => {
            if (event.data === 'pong') return;
            
            try {
                const log = JSON.parse(event.data);
                this.appendLogEntry({
                    timestamp: log.timestamp,
                    severity: log.level.toUpperCase(),
                    message: log.message.trim(),
                    source: 'server'
                });
            } catch (error) {
                console.error('Error parsing log message:', error);
            }
        };

        this.logWebSocket.onclose = (event) => {
            clearTimeout(connectionTimeout);
            if (!event.wasClean) {
                this.handleReconnect();
            }
        };

        this.logWebSocket.onerror = (error) => {
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: 'WebSocket error occurred',
                source: 'system'
            });
        };
    }

    handleReconnect() {
        this.wsReconnectAttempts++;
        this.appendLogEntry({
            timestamp: new Date().toISOString(),
            severity: 'WARNING',
            message: `WebSocket connection closed. Attempt ${this.wsReconnectAttempts}/${this.MAX_RECONNECT_ATTEMPTS}. Retrying in ${this.RECONNECT_DELAY/1000}s...`,
            source: 'system'
        });

        // Clear any existing reconnect timer
        if (this.reconnectTimer) {
            clearTimeout(this.reconnectTimer);
        }

        // Set new reconnect timer
        this.reconnectTimer = setTimeout(() => {
            if (document.visibilityState === 'visible') {
                this.initializeWebSocket();
            }
        }, this.RECONNECT_DELAY);
    }

    setupEventListeners() {
        // Event viewer auto-scroll toggle
        document.getElementById('autoScrollBtn').addEventListener('click', () => this.toggleAutoScroll());

        // Command input handling
        document.getElementById('command-input').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendCommand();
            }
        });

        // Visibility change handler
        document.addEventListener('visibilitychange', () => {
            if (document.visibilityState === 'visible' && 
                (!this.logWebSocket || this.logWebSocket.readyState === WebSocket.CLOSED)) {
                this.initializeWebSocket();
            }
        });
    }

    appendLogEntry(entry) {
        const eventLog = document.getElementById('event-log');
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        
        logEntry.innerHTML = `
            <span class="message">${entry.message}</span>
        `;
        
        eventLog.appendChild(logEntry);
        
        if (this.autoScroll) {
            eventLog.scrollTop = eventLog.scrollHeight;
        }
    }

    clearEventLog() {
        document.getElementById('event-log').innerHTML = '';
    }

    toggleAutoScroll() {
        this.autoScroll = !this.autoScroll;
        const autoScrollBtn = document.getElementById('autoScrollBtn');
        autoScrollBtn.textContent = `Auto-scroll: ${this.autoScroll ? 'On' : 'Off'}`;
        
        if (this.autoScroll) {
            const eventLog = document.getElementById('event-log');
            eventLog.scrollTop = eventLog.scrollHeight;
        }
    }

    async sendCommand() {
        const commandInput = document.getElementById('command-input');
        const command = commandInput.value.trim();

        if (!this.selectedAgentID) {
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'WARNING',
                message: 'No agent selected. Click "Interact" on an agent first.',
                source: 'system'
            });
            return;
        }

        if (command) {
            try {
                const response = await fetch('/api/agents/command', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        agent_id: this.selectedAgentID,
                        command
                    })
                });

                if (!response.ok) {
                    throw new Error(`Server returned ${response.status}`);
                }

                this.appendLogEntry({
                    timestamp: new Date().toISOString(),
                    severity: 'INFO',
                    message: `Command sent to agent ${this.selectedAgentID}: ${command}`,
                    source: 'user'
                });

                commandInput.value = '';
            } catch (error) {
                console.error('Error sending command:', error);
                this.appendLogEntry({
                    timestamp: new Date().toISOString(),
                    severity: 'ERROR',
                    message: `Failed to send command: ${error.message}`,
                    source: 'system'
                });
            }
        }
    }
    
    // Fixed listener display based on actual data structure
    async loadActiveListeners() {
        try {
            const response = await fetch('/api/listeners/list');
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }
            
            const listeners = await response.json();
            const listenersContainer = document.getElementById('active-listeners');
            
            if (!Array.isArray(listeners) || listeners.length === 0) {
                listenersContainer.innerHTML = `
                    <div class="empty-state">
                        <p>No active listeners</p>
                        <p>Go to the Listeners page to create one</p>
                    </div>
                `;
                return;
            }
            
            let html = '';
            listeners.forEach(listener => {
                const config = listener.config || {};
                const listenerId = config.id || listener.id;
                const listenerName = config.name || listener.name || 'Unnamed';
                const listenerProtocol = config.protocol || listener.Protocol || listener.type || 'Unknown';
                const listenerHost = config.host || listener.host || 'Unknown';
                const listenerPort = config.port || listener.port || 'Unknown';
                const listenerStatus = listener.status || 'Unknown';
                const listenerError = listener.error || '';
                
                if (!listenerId) {
                    console.warn('Listener missing ID:', listener);
                    return;
                }

                html += `
                    <div class="listener-card" data-id="${listenerId}" data-host="${listenerHost}" data-port="${listenerPort}">
                        <div class="listener-header">
                            <span class="listener-name">${listenerName}</span>
                            <span class="listener-type">${listenerProtocol}</span>
                        </div>
                        <div class="listener-details">
                            <div class="listener-id">ID: ${listenerId}</div>
                            <div>Host: ${listenerHost}:${listenerPort}</div>
                            <div>Status: <span class="status-${listenerStatus.toLowerCase()}">${listenerStatus}</span></div>
                            ${listenerError ? `<div class="error-message">Error: ${listenerError}</div>` : ''}
                        </div>
                        <div class="listener-actions">
                            ${listenerStatus.toLowerCase() === 'stopped' ? 
                              `<button class="action-button success" onclick="dashboardManager.startListener('${listenerId}')">Start</button>` : 
                              `<button class="action-button" onclick="dashboardManager.stopListener('${listenerId}')">Stop</button>`}
                            <button class="action-button delete" onclick="dashboardManager.deleteListener('${listenerId}', '${listenerName}')">Delete</button>
                        </div>
                    </div>
                `;
                
                // Track listener state changes for notifications
                if (listenerId && listenerName) {
                    const key = `${listenerId}-${listenerName}`;
                    const previousStatus = this.previousListenerStates.get(key);
                    
                    if (previousStatus && previousStatus !== listenerStatus) {
                        this.appendLogEntry({
                            timestamp: new Date().toISOString(),
                            severity: 'INFO',
                            message: `Listener "${listenerName}" changed status from ${previousStatus} to ${listenerStatus}`,
                            source: 'system'
                        });
                    }
                    
                    this.previousListenerStates.set(key, listenerStatus);
                }
            });
            
            listenersContainer.innerHTML = html;
            
        } catch (error) {
            console.error('Error loading listeners:', error);
            document.getElementById('active-listeners').innerHTML = `
                <div class="empty-state">
                    <p>Error loading listeners</p>
                    <p>${error.message}</p>
                </div>
            `;
        }
    }

    async startListener(id) {
        try {
            const response = await fetch(`/api/listeners/${id}/start`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                if (response.status === 405) {
                    return await this.handleStartListenerFallback(id);
                }
                const responseText = await response.text();
                let errorMsg;
                try {
                    const result = JSON.parse(responseText);
                    errorMsg = result.error || `Failed to start listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to start listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            await this.loadActiveListeners();
        } catch (error) {
            console.error('Error starting listener:', error);
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: `Failed to start listener: ${error.message}`,
                source: 'system'
            });
        }
    }

    async stopListener(id) {
        try {
            const response = await fetch(`/api/listeners/${id}/stop`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const responseText = await response.text();
                let errorMsg;
                try {
                    const result = JSON.parse(responseText);
                    errorMsg = result.error || `Failed to stop listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to stop listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            await this.loadActiveListeners();
        } catch (error) {
            console.error('Error stopping listener:', error);
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: `Failed to stop listener: ${error.message}`,
                source: 'system'
            });
        }
    }

    async deleteListener(id, name) {
        if (!confirm(`Are you sure you want to delete ${name}?`)) return;
        
        try {
            const response = await fetch(`/api/listeners/${id}`, { 
                method: 'DELETE',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                const responseText = await response.text();
                let errorMsg;
                try {
                    const result = JSON.parse(responseText);
                    errorMsg = result.error || `Failed to delete listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to delete listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            await this.loadActiveListeners();
        } catch (error) {
            console.error('Error deleting listener:', error);
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: `Failed to delete listener: ${error.message}`,
                source: 'system'
            });
        }
    }

    async handleStartListenerFallback(id) {
        try {
            const response = await fetch(`/api/listeners/${id}`);
            if (!response.ok) {
                throw new Error(`Failed to get listener details (${response.status})`);
            }
            
            const listener = await response.json();
            const config = listener.config || listener;
            const newConfig = {...config};
            delete newConfig.id;
            
            // Delete the old listener
            const deleteResponse = await fetch(`/api/listeners/${id}`, {
                method: 'DELETE'
            });
            
            if (!deleteResponse.ok) {
                throw new Error(`Failed to delete old listener (${deleteResponse.status})`);
            }
            
            // Create a new listener with the same config
            const createResponse = await fetch('/api/listeners/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(newConfig)
            });
            
            if (!createResponse.ok) {
                throw new Error(`Failed to recreate listener (${createResponse.status})`);
            }
            
            await this.loadActiveListeners();
        } catch (error) {
            console.error("Error in fallback listener start:", error);
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: `Failed to start listener (fallback method): ${error.message}`,
                source: 'system'
            });
        }
    }

    async loadActiveAgents() {
        try {
            const response = await fetch('/api/agents/list');
            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            const agentData = await response.json();
            // Convert agent map/object to array for rendering
            const agents = Object.values(agentData);
            const agentsContainer = document.getElementById('agent-list');

            if (!Array.isArray(agents) || agents.length === 0) {
                agentsContainer.innerHTML = `
                    <div class="empty-state">
                        <p>No active agents</p>
                        <p>Generate a payload to get started</p>
                    </div>
                `;
                return;
            }

            let html = '';
            agents.forEach(agent => {
                const lastSeen = new Date(agent.last_seen || Date.now()).toLocaleString();
                const agentStatus = agent.connected ? 'active' : 'disconnected';

                // Track agent state changes for notifications
                const previousStatus = this.previousAgentStates.get(agent.id);
                if (previousStatus !== undefined && previousStatus !== agentStatus) {
                    this.appendLogEntry({
                        timestamp: new Date().toISOString(),
                        severity: agentStatus === 'active' ? 'SUCCESS' : 'WARNING',
                        message: `Agent ${agent.id} is now ${agentStatus}`,
                        source: 'system'
                    });
                }
                this.previousAgentStates.set(agent.id, agentStatus);

                html += `
                    <div class="agent-card" data-id="${agent.id}">
                        <div class="agent-header">
                            <div class="agent-title">
                                <div class="agent-status ${agentStatus}"></div>
                                <span class="agent-name">${agent.id}</span>
                            </div>
                            <span class="agent-type">${agent.type || 'Standard'}</span>
                        </div>
                        <div class="agent-details">
                            <div>Last Seen: ${lastSeen}</div>
                            <div>IP: ${agent.ip || 'Unknown'}</div>
                            <div>Hostname: ${agent.hostname || 'Unknown'}</div>
                            <div>OS: ${agent.os || 'Unknown'}</div>
                        </div>
                        <div class="agent-actions">
                            <button class="action-button" onclick="dashboardManager.interactWithAgent('${agent.id}')">Interact</button>
                            <button class="action-button delete" onclick="dashboardManager.removeAgent('${agent.id}')">Remove</button>
                        </div>
                    </div>
                `;
            });

            agentsContainer.innerHTML = html;
        } catch (error) {
            console.error('Error loading agents:', error);
            document.getElementById('agent-list').innerHTML = `
                <div class="empty-state">
                    <p>Error loading agents</p>
                    <p>${error.message}</p>
                </div>
            `;
        }
    }

    async interactWithAgent(AgentID) {
        // Select the agent for interaction
        // This will be used by the command shell
        this.selectedAgentID = AgentID;
        
        this.appendLogEntry({
            timestamp: new Date().toISOString(),
            severity: 'INFO',
            message: `Selected agent ${AgentID} for interaction`,
            source: 'system'
        });

        // Update command input prompt
        const input = document.getElementById('command-input');
        input.placeholder = `Enter command for agent ${AgentID}...`;

        this.loadAgentResults(AgentID);
    }

    async removeAgent(AgentID) {
        if (!confirm(`Are you sure you want to remove agent ${AgentID}?`)) return;

        try {
            const response = await fetch(`/api/agents/${AgentID}`, {
                method: 'DELETE'
            });

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}`);
            }

            await this.loadActiveAgents();
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'SUCCESS',
                message: `Agent ${AgentID} removed successfully`,
                source: 'system'
            });
        } catch (error) {
            console.error('Error removing agent:', error);
            this.appendLogEntry({
                timestamp: new Date().toISOString(),
                severity: 'ERROR',
                message: `Failed to remove agent: ${error.message}`,
                source: 'system'
            });
        }
    }

    async loadAgentResults(AgentID) {
        const outputDiv = document.getElementById('command-output');
        outputDiv.innerHTML = '<div>Loading results...</div>';
        try {
            const response = await fetch(`/api/agents/${AgentID}/results`);
            if (!response.ok) {
                outputDiv.innerHTML = '<div>No results found.</div>';
                return;
            }
            const results = await response.json();
            console.log('Results from backend:', results);
            if (!Array.isArray(results) || results.length === 0) {
                outputDiv.innerHTML = '<div>No results found.</div>';
                return;
            }
            outputDiv.innerHTML = results.map(res => `
                <div class="command-result">
                    <span class="timestamp">${res.timestamp || ''}</span>
                    <span class="command">${res.command || ''}</span>
                    <pre class="output">${res.output || ''}</pre>
                </div>
            `).join('');
        } catch (e) {
            outputDiv.innerHTML = `<div>Error loading results: ${e.message}</div>`;
        }
    }
}

// Initialize the dashboard manager when the page loads
let dashboardManager;
document.addEventListener('DOMContentLoaded', () => {
    dashboardManager = new DashboardManager();
});
