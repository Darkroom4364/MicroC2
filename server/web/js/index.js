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

        this.selectedAgentID = null;
        this.resultsPollingInterval = null;
        this.taskStates = new Map();
        this.taskRequestSequence = 0;
        this.taskRequestController = null;
        this.taskRequestAgentID = null;
        this.taskRequestOffset = null;
        this.taskRequestPromise = null;
        this.taskPageAgentID = null;
        this.taskPageOffset = 0;
        this.taskDetailCache = new Map();
        this.taskDetailRequests = new Map();
        this.taskElements = new Map();
        this.TASK_PAGE_LIMIT = 50;
        this.MAX_TASK_DETAIL_CACHE = 20;
        this.agentInteractionSequence = 0;

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

        const message = document.createElement('span');
        message.className = 'message';
        message.textContent = entry.message;
        logEntry.appendChild(message);

        eventLog.appendChild(logEntry);
        
        if (this.autoScroll) {
            eventLog.scrollTop = eventLog.scrollHeight;
        }
    }

    clearEventLog() {
        document.getElementById('event-log').replaceChildren();
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
            const agentID = this.selectedAgentID;
            try {
                // The root-relative API path and encoded ID cannot select another origin.
                // foxguard: ignore[js/no-ssrf]
                const response = await fetch(`/api/agents/${encodeURIComponent(agentID)}/tasks`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        schema_version: 1,
                        type: 'shell',
                        arguments: {
                            command
                        },
                        timeout_seconds: 30,
                        expires_in_seconds: 300
                    })
                });

                if (response.status !== 202) {
                    throw new Error(`Server returned ${response.status}; expected 202 Accepted`);
                }

                const acceptedTask = await response.json();
                const taskID = acceptedTask.id || acceptedTask.task_id;
                const taskStatus = acceptedTask.status || 'queued';
                if (!taskID) {
                    throw new Error('Server accepted the task without returning a task ID');
                }
                this.taskStates.set(taskID, taskStatus);

                this.appendLogEntry({
                    timestamp: new Date().toISOString(),
                    severity: 'INFO',
                    message: `Task ${taskID} accepted for agent ${agentID} (${taskStatus})`,
                    source: 'user'
                });

                commandInput.value = '';
                if (this.selectedAgentID === agentID) {
                    await this.loadAgentResults(agentID, 0);
                }
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
                this.replaceWithEmptyState(listenersContainer, [
                    'No active listeners',
                    'Go to the Listeners page to create one'
                ]);
                return;
            }
            
            const listenerCards = [];
            listeners.forEach(listener => {
                const config = listener.config || {};
                const listenerId = config.id || listener.id;
                const listenerName = config.name || listener.name || 'Unnamed';
                const listenerProtocol = config.protocol || listener.protocol ||
                    listener.Protocol || listener.type || 'Unknown';
                const listenerHost = config.host || listener.host || 'Unknown';
                const listenerPort = config.port || listener.port || 'Unknown';
                const listenerStatus = listener.status || 'Unknown';
                const listenerError = listener.error || '';
                
                if (!listenerId) {
                    console.warn('Listener missing ID:', listener);
                    return;
                }

                listenerCards.push(this.createListenerCard({
                    id: listenerId,
                    name: listenerName,
                    protocol: listenerProtocol,
                    host: listenerHost,
                    port: listenerPort,
                    status: listenerStatus,
                    error: listenerError
                }));
                
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
            
            listenersContainer.replaceChildren(...listenerCards);
            
        } catch (error) {
            console.error('Error loading listeners:', error);
            this.replaceWithEmptyState(
                document.getElementById('active-listeners'),
                ['Error loading listeners', error.message]
            );
        }
    }

    createListenerCard(listener) {
        const card = document.createElement('div');
        card.className = 'listener-card';
        card.dataset.id = String(listener.id);
        card.dataset.host = String(listener.host);
        card.dataset.port = String(listener.port);

        const header = document.createElement('div');
        header.className = 'listener-header';
        this.appendTextElement(header, 'span', 'listener-name', listener.name);
        this.appendTextElement(header, 'span', 'listener-type', listener.protocol);
        card.appendChild(header);

        const details = document.createElement('div');
        details.className = 'listener-details';
        this.appendTextElement(details, 'div', 'listener-id', `ID: ${listener.id}`);
        this.appendTextElement(details, 'div', '', `Host: ${listener.host}:${listener.port}`);

        const statusLine = document.createElement('div');
        statusLine.appendChild(document.createTextNode('Status: '));
        this.appendTextElement(
            statusLine,
            'span',
            this.listenerStatusClass(listener.status),
            listener.status
        );
        details.appendChild(statusLine);

        if (listener.error) {
            this.appendTextElement(
                details,
                'div',
                'error-message',
                `Error: ${listener.error}`
            );
        }
        card.appendChild(details);

        const actions = document.createElement('div');
        actions.className = 'listener-actions';
        const stopped = String(listener.status).toLowerCase() === 'stopped';
        const stateButton = this.createActionButton(
            stopped ? 'action-button success' : 'action-button',
            stopped ? 'Start' : 'Stop',
            () => {
                if (stopped) {
                    void this.startListener(listener.id);
                } else {
                    void this.stopListener(listener.id);
                }
            }
        );
        actions.appendChild(stateButton);
        actions.appendChild(this.createActionButton(
            'action-button delete',
            'Delete',
            () => void this.deleteListener(listener.id, listener.name)
        ));
        card.appendChild(actions);

        return card;
    }

    listenerStatusClass(status) {
        const token = String(status).toLowerCase();
        const allowedTokens = new Set(['active', 'inactive', 'stopped', 'pending']);
        return `status-${allowedTokens.has(token) ? token : 'unknown'}`;
    }

    async startListener(id) {
        try {
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(`/api/listeners/${encodeURIComponent(id)}/start`, {
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
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(`/api/listeners/${encodeURIComponent(id)}/stop`, {
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
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(`/api/listeners/${encodeURIComponent(id)}`, {
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
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(`/api/listeners/${encodeURIComponent(id)}`);
            if (!response.ok) {
                throw new Error(`Failed to get listener details (${response.status})`);
            }
            
            const listener = await response.json();
            const config = listener.config || listener;
            const newConfig = {...config};
            delete newConfig.id;
            
            // Delete the old listener
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const deleteResponse = await fetch(`/api/listeners/${encodeURIComponent(id)}`, {
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
                this.replaceWithEmptyState(agentsContainer, [
                    'No active agents',
                    'Generate a payload to get started'
                ]);
                return;
            }

            const agentCards = [];
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

                agentCards.push(this.createAgentCard(agent, lastSeen, agentStatus));
            });

            agentsContainer.replaceChildren(...agentCards);
        } catch (error) {
            console.error('Error loading agents:', error);
            this.replaceWithEmptyState(
                document.getElementById('agent-list'),
                ['Error loading agents', error.message]
            );
        }
    }

    createAgentCard(agent, lastSeen, agentStatus) {
        const card = document.createElement('div');
        card.className = 'agent-card';
        card.dataset.id = String(agent.id);

        const header = document.createElement('div');
        header.className = 'agent-header';
        const title = document.createElement('div');
        title.className = 'agent-title';
        const statusIndicator = document.createElement('div');
        statusIndicator.className = agentStatus === 'active'
            ? 'agent-status active'
            : 'agent-status disconnected';
        title.appendChild(statusIndicator);
        this.appendTextElement(title, 'span', 'agent-name', agent.id);
        header.appendChild(title);
        this.appendTextElement(header, 'span', 'agent-type', agent.type || 'Standard');
        card.appendChild(header);

        const details = document.createElement('div');
        details.className = 'agent-details';
        this.appendTextElement(details, 'div', '', `Last Seen: ${lastSeen}`);
        this.appendTextElement(details, 'div', '', `IP: ${agent.ip || 'Unknown'}`);
        this.appendTextElement(details, 'div', '', `Hostname: ${agent.hostname || 'Unknown'}`);
        this.appendTextElement(details, 'div', '', `OS: ${agent.os || 'Unknown'}`);
        card.appendChild(details);

        const actions = document.createElement('div');
        actions.className = 'agent-actions';
        actions.appendChild(this.createActionButton(
            'action-button',
            'Interact',
            () => void this.interactWithAgent(agent.id)
        ));
        actions.appendChild(this.createActionButton(
            'action-button delete',
            'Remove',
            () => void this.removeAgent(agent.id)
        ));
        card.appendChild(actions);

        return card;
    }

    appendTextElement(parent, tag, className, value) {
        const element = document.createElement(tag);
        if (className) {
            element.className = className;
        }
        element.textContent = String(value);
        parent.appendChild(element);
        return element;
    }

    createActionButton(className, label, action) {
        const button = document.createElement('button');
        button.className = className;
        button.textContent = label;
        button.addEventListener('click', action);
        return button;
    }

    replaceWithEmptyState(container, messages) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state';
        messages.forEach(message => {
            this.appendTextElement(emptyState, 'p', '', message);
        });
        container.replaceChildren(emptyState);
    }

    async interactWithAgent(AgentID) {
        const interactionSequence = ++this.agentInteractionSequence;
        const previousAgentID = this.selectedAgentID;

        // Select the agent for interaction
        // This will be used by the command shell
        this.selectedAgentID = AgentID;
        if (previousAgentID !== AgentID) {
            this.abortTaskDetailRequests();
            this.taskPageAgentID = AgentID;
            this.taskPageOffset = 0;
        }
        
        this.appendLogEntry({
            timestamp: new Date().toISOString(),
            severity: 'INFO',
            message: `Selected agent ${AgentID} for interaction`,
            source: 'system'
        });

        // Update command input prompt
        const input = document.getElementById('command-input');
        input.placeholder = `Enter command for agent ${AgentID}...`;

        if (this.resultsPollingInterval) {
            clearInterval(this.resultsPollingInterval);
            this.resultsPollingInterval = null;
        }
        await this.loadAgentResults(AgentID);
        if (
            this.selectedAgentID !== AgentID ||
            this.agentInteractionSequence !== interactionSequence
        ) {
            return;
        }
        this.resultsPollingInterval = setInterval(() => {
            if (document.visibilityState === 'visible' && this.selectedAgentID === AgentID) {
                void this.loadAgentResults(AgentID);
            }
        }, 2000);
    }

    async removeAgent(AgentID) {
        if (!confirm(`Are you sure you want to remove agent ${AgentID}?`)) return;

        try {
            // The root-relative API path and encoded ID cannot select another origin.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(`/api/agents/${encodeURIComponent(AgentID)}`, {
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

    loadAgentResults(AgentID, requestedOffset = this.taskPageOffsetFor(AgentID)) {
        const outputDiv = document.getElementById('command-output');
        if (!Number.isInteger(requestedOffset) || requestedOffset < 0) {
            throw new Error('Task page offset must be a nonnegative integer');
        }
        if (this.taskRequestController) {
            if (
                this.taskRequestAgentID === AgentID &&
                this.taskRequestOffset === requestedOffset &&
                this.taskRequestPromise
            ) {
                return this.taskRequestPromise;
            }
            this.taskRequestController.abort();
        }

        const requestSequence = ++this.taskRequestSequence;
        const requestController = new AbortController();
        this.taskRequestController = requestController;
        this.taskRequestAgentID = AgentID;
        this.taskRequestOffset = requestedOffset;
        this.taskPageAgentID = AgentID;
        this.taskPageOffset = requestedOffset;
        const isCurrentRequest = () => (
            this.selectedAgentID === AgentID &&
            this.taskRequestSequence === requestSequence &&
            this.taskRequestController === requestController
        );

        if (!outputDiv.hasChildNodes()) {
            this.replaceTaskOutputMessage(outputDiv, 'Loading tasks...');
        }

        const requestPromise = this.fetchAgentTaskSummaries(
            AgentID,
            outputDiv,
            requestController,
            isCurrentRequest,
            requestedOffset
        );
        this.taskRequestPromise = requestPromise;
        requestPromise.then(
            () => this.clearTaskRequest(requestController, requestPromise),
            () => this.clearTaskRequest(requestController, requestPromise)
        );
        return requestPromise;
    }

    async fetchAgentTaskSummaries(
        AgentID,
        outputDiv,
        requestController,
        isCurrentRequest,
        requestedOffset
    ) {
        try {
            // The root-relative API path uses an encoded ID and bounded numeric query values.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(
                `/api/agents/${encodeURIComponent(AgentID)}/tasks` +
                    `?limit=${this.TASK_PAGE_LIMIT}&offset=${requestedOffset}`,
                {signal: requestController.signal}
            );
            if (!isCurrentRequest()) {
                return;
            }
            if (!response.ok) {
                const statusText = response.statusText ? ` ${response.statusText}` : '';
                throw new Error(
                    `Task request failed with HTTP ${response.status}${statusText}`
                );
            }
            const payload = await response.json();
            if (!isCurrentRequest()) {
                return;
            }
            if (!this.isValidTaskPage(payload, requestedOffset)) {
                throw new Error('Task list response did not match schema version 1');
            }
            const tasks = payload.tasks;

            outputDiv.replaceChildren();
            this.taskElements.clear();
            if (tasks.length === 0) {
                this.appendTextElement(
                    outputDiv,
                    'div',
                    '',
                    payload.total === 0 ? 'No tasks found.' : 'No tasks found on this page.'
                );
            } else {
                tasks.forEach(task => {
                    if (task.id || task.task_id) {
                        this.taskStates.set(task.id || task.task_id, task.status || 'unknown');
                    }
                    outputDiv.appendChild(this.createTaskResultElement(task, AgentID));
                });
            }
            this.appendTaskPagination(outputDiv, AgentID, payload);
        } catch (e) {
            if (e.name === 'AbortError' || !isCurrentRequest()) {
                return;
            }
            this.taskElements.clear();
            this.replaceTaskOutputMessage(outputDiv, `Error loading tasks: ${e.message}`);
        }
    }

    clearTaskRequest(requestController, requestPromise) {
        if (
            this.taskRequestController === requestController &&
            this.taskRequestPromise === requestPromise
        ) {
            this.taskRequestController = null;
            this.taskRequestAgentID = null;
            this.taskRequestOffset = null;
            this.taskRequestPromise = null;
        }
    }

    taskPageOffsetFor(AgentID) {
        return this.taskPageAgentID === AgentID ? this.taskPageOffset : 0;
    }

    isValidTaskPage(payload, requestedOffset) {
        if (
            !payload ||
            payload.schema_version !== 1 ||
            !Array.isArray(payload.tasks) ||
            !Number.isInteger(payload.limit) ||
            payload.limit !== this.TASK_PAGE_LIMIT ||
            !Number.isInteger(payload.offset) ||
            payload.offset !== requestedOffset ||
            !Number.isInteger(payload.total) ||
            payload.total < 0 ||
            payload.tasks.length > payload.limit
        ) {
            return false;
        }

        const pageEnd = payload.offset + payload.tasks.length;
        if (
            (payload.offset <= payload.total && pageEnd > payload.total) ||
            (payload.offset > payload.total && payload.tasks.length !== 0)
        ) {
            return false;
        }

        return payload.next_offset === null || (
            Number.isInteger(payload.next_offset) &&
            payload.next_offset > payload.offset &&
            payload.next_offset <= payload.total
        );
    }

    appendTaskPagination(outputDiv, AgentID, page) {
        const hasNewerPage = page.offset > 0;
        const hasOlderPage = page.next_offset !== null;
        if (!hasNewerPage && !hasOlderPage) {
            return;
        }

        const pagination = document.createElement('div');
        pagination.className = 'task-pagination button-group';
        const rangeStart = page.tasks.length === 0 ? 0 : page.offset + 1;
        const rangeEnd = page.offset + page.tasks.length;
        this.appendTextElement(
            pagination,
            'span',
            'timestamp',
            `Tasks ${rangeStart}-${rangeEnd} of ${page.total}`
        );

        if (hasNewerPage) {
            const newerOffset = Math.max(0, page.offset - page.limit);
            pagination.appendChild(this.createActionButton(
                'action-button secondary',
                'Newer',
                () => void this.navigateTaskPage(AgentID, newerOffset)
            ));
        }
        if (hasOlderPage) {
            pagination.appendChild(this.createActionButton(
                'action-button secondary',
                'Older',
                () => void this.navigateTaskPage(AgentID, page.next_offset)
            ));
        }
        outputDiv.appendChild(pagination);
    }

    navigateTaskPage(AgentID, offset) {
        if (this.selectedAgentID !== AgentID) {
            return Promise.resolve();
        }
        this.abortTaskDetailRequests();
        return this.loadAgentResults(AgentID, offset);
    }

    replaceTaskOutputMessage(outputDiv, message) {
        const messageElement = document.createElement('div');
        messageElement.textContent = message;
        outputDiv.replaceChildren(messageElement);
    }

    createTaskResultElement(task, AgentID) {
        const container = document.createElement('div');
        container.className = 'command-result';
        const taskID = task.id || task.task_id || 'unknown';
        const cacheKey = this.taskCacheKey(AgentID, taskID);
        const renderedTask = this.taskDetailCache.get(cacheKey) || task;
        this.renderTaskResultElement(container, renderedTask, AgentID);
        this.taskElements.set(cacheKey, container);
        return container;
    }

    renderTaskResultElement(container, task, AgentID) {
        container.replaceChildren();

        const taskID = task.id || task.task_id || 'unknown';
        const status = task.status || 'unknown';
        const result = task.result || {};
        const outcome = result.outcome || task.outcome || '';
        const command = task.arguments && typeof task.arguments.command === 'string'
            ? task.arguments.command
            : '';

        const heading = document.createElement('div');
        heading.className = 'command';
        heading.textContent = command || `${task.type || 'task'} ${taskID}`;
        container.appendChild(heading);

        const metadata = document.createElement('div');
        metadata.className = 'timestamp';
        const metadataParts = [`Task ${taskID}`, `status: ${status}`];
        if (outcome) {
            metadataParts.push(`outcome: ${outcome}`);
        }
        if (Number.isInteger(result.exit_code)) {
            metadataParts.push(`exit: ${result.exit_code}`);
        }
        metadata.textContent = metadataParts.join(' · ');
        container.appendChild(metadata);

        const timestampParts = [
            ['created', task.created_at],
            ['queued', task.queued_at],
            ['dispatched', task.dispatched_at],
            ['started', task.started_at || result.started_at],
            ['completed', task.completed_at || result.completed_at],
            ['expires', task.expires_at]
        ]
            .filter(([, value]) => value)
            .map(([label, value]) => `${label} ${value}`);
        if (timestampParts.length > 0) {
            const timestampLine = document.createElement('div');
            timestampLine.className = 'timestamp';
            timestampLine.textContent = timestampParts.join(' · ');
            container.appendChild(timestampLine);
        }

        const output = result.output || {};
        const stdout = typeof output === 'string' ? output : output.stdout;
        const stderr = typeof output === 'object' && output !== null ? output.stderr : '';
        this.appendTaskStream(container, 'stdout', stdout);
        this.appendTaskStream(container, 'stderr', stderr);
        this.appendTaskStream(container, 'error', result.error);

        const isOutputBearingTerminal = status === 'completed' || status === 'failed';
        const hasDetailedOutput = this.hasDetailedTaskOutput(task);
        if (isOutputBearingTerminal && !hasDetailedOutput) {
            const loadButton = this.createActionButton(
                'action-button',
                'Load output',
                () => void this.loadTaskDetails(AgentID, taskID, loadButton)
            );
            container.appendChild(loadButton);
        }
    }

    async loadTaskDetails(AgentID, taskID, loadButton) {
        const cacheKey = this.taskCacheKey(AgentID, taskID);
        const cached = this.taskDetailCache.get(cacheKey);
        if (cached) {
            const currentContainer = this.currentTaskContainer(cacheKey, AgentID);
            if (currentContainer) {
                this.renderTaskResultElement(currentContainer, cached, AgentID);
            }
            return;
        }

        const existingRequest = this.taskDetailRequests.get(cacheKey);
        if (existingRequest) {
            return existingRequest.promise;
        }

        const requestController = new AbortController();
        loadButton.disabled = true;
        loadButton.textContent = 'Loading output...';
        const detailPromise = this.fetchTaskDetail(
            AgentID,
            taskID,
            cacheKey,
            requestController,
            loadButton
        );
        this.taskDetailRequests.set(cacheKey, {
            controller: requestController,
            promise: detailPromise
        });
        try {
            await detailPromise;
        } finally {
            const currentRequest = this.taskDetailRequests.get(cacheKey);
            if (currentRequest && currentRequest.controller === requestController) {
                this.taskDetailRequests.delete(cacheKey);
            }
        }
    }

    async fetchTaskDetail(
        AgentID,
        taskID,
        cacheKey,
        requestController,
        loadButton
    ) {
        try {
            // The root-relative API path uses encoded identifiers only.
            // foxguard: ignore[js/no-ssrf]
            const response = await fetch(
                `/api/agents/${encodeURIComponent(AgentID)}/tasks/${encodeURIComponent(taskID)}`,
                {signal: requestController.signal}
            );
            if (!response.ok) {
                const statusText = response.statusText ? ` ${response.statusText}` : '';
                throw new Error(
                    `Task detail request failed with HTTP ${response.status}${statusText}`
                );
            }
            const payload = await response.json();
            const task = payload && payload.task ? payload.task : payload;
            if (!task || (task.id || task.task_id) !== taskID) {
                throw new Error('Task detail response did not match the requested task');
            }
            if (task.agent_id && task.agent_id !== AgentID) {
                throw new Error('Task detail response did not match the selected agent');
            }
            if (!this.hasDetailedTaskOutput(task)) {
                throw new Error('Task detail response did not include full output');
            }
            if (requestController.signal.aborted || this.selectedAgentID !== AgentID) {
                return;
            }

            this.cacheTaskDetail(cacheKey, task);
            const currentContainer = this.currentTaskContainer(cacheKey, AgentID);
            if (currentContainer) {
                this.renderTaskResultElement(currentContainer, task, AgentID);
            }
        } catch (error) {
            if (error.name === 'AbortError') {
                return;
            }
            const currentContainer = this.currentTaskContainer(cacheKey, AgentID);
            if (!currentContainer) {
                return;
            }
            loadButton.disabled = false;
            loadButton.textContent = 'Retry output';
            this.appendTextElement(
                currentContainer,
                'div',
                'error-message',
                `Error loading output: ${error.message}`
            );
        }
    }

    currentTaskContainer(cacheKey, AgentID) {
        if (this.selectedAgentID !== AgentID) {
            return null;
        }
        return this.taskElements.get(cacheKey) || null;
    }

    taskCacheKey(AgentID, taskID) {
        return `${AgentID}\u0000${taskID}`;
    }

    hasDetailedTaskOutput(task) {
        const output = task && task.result && task.result.output;
        return Boolean(
            output &&
            typeof output === 'object' &&
            Object.prototype.hasOwnProperty.call(output, 'stdout') &&
            Object.prototype.hasOwnProperty.call(output, 'stderr')
        );
    }

    cacheTaskDetail(cacheKey, task) {
        this.taskDetailCache.delete(cacheKey);
        this.taskDetailCache.set(cacheKey, task);
        while (this.taskDetailCache.size > this.MAX_TASK_DETAIL_CACHE) {
            const oldestKey = this.taskDetailCache.keys().next().value;
            this.taskDetailCache.delete(oldestKey);
        }
    }

    abortTaskDetailRequests() {
        for (const request of this.taskDetailRequests.values()) {
            request.controller.abort();
        }
        this.taskDetailRequests.clear();
        this.taskElements.clear();
    }

    appendTaskStream(container, label, value) {
        if (typeof value !== 'string' || value.length === 0) {
            return;
        }

        const streamLabel = document.createElement('div');
        streamLabel.className = 'timestamp';
        streamLabel.textContent = label;
        container.appendChild(streamLabel);

        const stream = document.createElement('pre');
        stream.className = 'output';
        stream.textContent = value;
        container.appendChild(stream);
    }
}

let dashboardManager;

// Initialize the dashboard manager when the page loads.
if (typeof document !== 'undefined') {
    document.addEventListener('DOMContentLoaded', () => {
        dashboardManager = new DashboardManager();
    });
}

// Expose the class to the lightweight Node contract tests without changing the
// browser-facing global script behavior.
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {DashboardManager};
}
