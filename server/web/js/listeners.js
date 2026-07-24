// Helper: safely parse JSON text to object or null
function safeParseJson(text) {
    try { return JSON.parse(text); }
    catch (e) { console.error('JSON parse error:', e); return null; }
}

class ListenerManager {
    constructor() {
        this.setupEventListeners();
        this.startAutoRefresh();
        this.fetchListenerList();
    }

    setupEventListeners() {
        // Form submission
        document.getElementById('listenerForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleFormSubmit(e);
        });
    }

    async handleFormSubmit(e) {
        const formData = new FormData(e.target);
        const formValues = Object.fromEntries(formData);
        const advertisedHost = String(formValues.advertisedHost || '').trim();
        
        const listenerConfig = {
            name: String(formValues.listenerName || '').trim(),
            protocol: formValues.payloadType,
            host: String(formValues.bindHost || '').trim(),
            port: parseInt(formValues.port, 10)
        };

        // Basic validation
        if (!listenerConfig.name) {
            this.showError('Listener name is required');
            return;
        }
        if (!Number.isInteger(listenerConfig.port) ||
            listenerConfig.port < 1 ||
            listenerConfig.port > 65535) {
            this.showError('Listener port must be between 1 and 65535');
            return;
        }
        if (advertisedHost) {
            listenerConfig.hosts = [advertisedHost];
        }

        this.showLoading('Creating listener...');

        try {
            const response = await fetch('/api/listeners/create', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(listenerConfig)
            });

            const responseText = await response.text();
            let errorMessage = 'Failed to create listener';
            
            if (!response.ok) {
                try {
                    const errorJson = safeParseJson(responseText);
                    if (errorJson && errorJson.error) errorMessage = errorJson.error;
                } catch {
                    errorMessage = responseText || errorMessage;
                }
                throw new Error(errorMessage);
            }

            this.showSuccess('Listener created successfully');
            e.target.reset();
            await this.fetchListenerList();
        } catch (error) {
            console.error('Error creating listener:', error);
            this.showError(error.message);
        }
    }

    async fetchListenerList() {
        const listenersList = document.getElementById('active-listeners');
        if (!listenersList) {
            console.warn("Element 'active-listeners' not found in DOM");
            return;
        }
        // show loading state
        listenersList.textContent = '';
        const spinner = document.createElement('div'); spinner.className = 'loading-spinner'; spinner.textContent = 'Loading...';
        listenersList.appendChild(spinner);
        try {
            const response = await fetch('/api/listeners/list');
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            const listeners = await response.json();
            // if empty
            if (!Array.isArray(listeners) || listeners.length === 0) {
                listenersList.textContent = '';
                const empty = document.createElement('div'); empty.className='empty-state'; empty.textContent='No active listeners';
                listenersList.appendChild(empty);
                return;
            }
            // rebuild list via fragment
            const frag = document.createDocumentFragment();
            listeners.forEach(listener => {
                const config = listener.config||{};
                const id = config.id||listener.id; if(!id) return;
                const card = document.createElement('div'); card.className='listener-card'; card.dataset.id=id;
                // header
                const header = document.createElement('div'); header.className='listener-header';
                header.innerHTML = `<span class="listener-name">${config.name||listener.name||'Unnamed'}</span>`+
                    `<span class="listener-type">${config.protocol||listener.Protocol||listener.type||'?'}</span>`;
                card.appendChild(header);
                // details
                const details = document.createElement('div'); details.className='listener-details';
                details.innerHTML = `<div class="listener-id">ID: ${id}</div>`+
                    `<div>Host: ${config.host||listener.host||'?'}:${config.port||listener.port||'?'}</div>`+
                    `<div>Status: <span class="status-${(listener.status||'').toLowerCase()}">${listener.status||'?'}</span></div>`+
                    `${listener.error?`<div class="error-message">Error: ${listener.error}</div>`:''}`;
                card.appendChild(details);
                // actions
                const actions = document.createElement('div'); actions.className='listener-actions';
                const btn = document.createElement('button');
                if((listener.status||'').toLowerCase()==='stopped'){ btn.className='action-button success'; btn.textContent='Start'; btn.onclick=()=>listenerManager.startListener(id);
                } else { btn.className='action-button'; btn.textContent='Stop'; btn.onclick=()=>listenerManager.stopListener(id);}                
                const del = document.createElement('button'); del.className='action-button delete'; del.textContent='Delete'; del.onclick=()=>listenerManager.deleteListener(id, config.name||listener.name);
                actions.append(btn, del);
                card.appendChild(actions);
                frag.appendChild(card);
            });
            listenersList.textContent = '';
            listenersList.appendChild(frag);
        } catch (error) {
            console.error('Error fetching listeners:', error);
            listenersList.textContent = '';
            const err = document.createElement('div'); err.className='error-state'; err.textContent=`Error loading listeners: ${error.message}`;
            listenersList.appendChild(err);
        }
    }

    async stopListener(id) {
        if (!id || id === 'undefined') {
            this.showError('Invalid listener ID');
            console.error('Attempted to stop a listener with invalid ID:', id);
            return;
        }

        console.log(`Stopping listener with ID: ${id}`);
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = "Stopping listener...";
        statusMessage.className = "status-message loading";
        
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
                    const result = safeParseJson(responseText);
                    errorMsg = result.error || `Failed to stop listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to stop listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            statusMessage.textContent = "Listener stopped successfully";
            statusMessage.className = "status-message success";
            await this.fetchListenerList();
            
            setTimeout(() => {
                statusMessage.className = "status-message hidden";
            }, 3000);
        } catch (error) {
            console.error('Error stopping listener:', error);
            statusMessage.textContent = `Error: ${error.message}`;
            statusMessage.className = "status-message error";
        }
    }

    async deleteListener(id, name) {
        if (!id || id === 'undefined') {
            this.showError('Invalid listener ID');
            console.error('Attempted to delete a listener with invalid ID:', id);
            return;
        }

        if (!confirm(`Are you sure you want to delete ${name}?`)) return;
        
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = "Deleting listener...";
        statusMessage.className = "status-message loading";
        
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
                    const result = safeParseJson(responseText);
                    errorMsg = result.error || `Failed to delete listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to delete listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            statusMessage.textContent = `Listener "${name}" deleted successfully`;
            statusMessage.className = "status-message success";
            await this.fetchListenerList();
            
            setTimeout(() => {
                statusMessage.className = "status-message hidden";
            }, 3000);
        } catch (error) {
            console.error('Error deleting listener:', error);
            statusMessage.textContent = `Error: ${error.message}`;
            statusMessage.className = "status-message error";
        }
    }

    async startListener(id) {
        if (!id || id === 'undefined') {
            this.showError('Invalid listener ID');
            console.error('Attempted to start a listener with invalid ID:', id);
            return;
        }

        console.log(`Starting listener with ID: ${id}`);
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = "Starting listener...";
        statusMessage.className = "status-message loading";
        
        try {
            const response = await fetch(`/api/listeners/${id}/start`, { 
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (!response.ok) {
                // Special handling for Method Not Allowed - try the fallback method
                if (response.status === 405) {
                    console.log("Start endpoint not available, trying fallback method");
                    await this.handleStartListenerFallback(id);
                    return;
                }
                
                const responseText = await response.text();
                let errorMsg;
                try {
                    const result = safeParseJson(responseText);
                    errorMsg = result.error || `Failed to start listener (${response.status})`;
                } catch {
                    errorMsg = responseText || `Failed to start listener (${response.status})`;
                }
                throw new Error(errorMsg);
            }
            
            statusMessage.textContent = "Listener started successfully";
            statusMessage.className = "status-message success";
            await this.fetchListenerList();
            
            setTimeout(() => {
                statusMessage.className = "status-message hidden";
            }, 3000);
        } catch (error) {
            console.error('Error starting listener:', error);
            statusMessage.textContent = `Error: ${error.message}`;
            statusMessage.className = "status-message error";
        }
    }

    async handleStartListenerFallback(id) {
        const statusMessage = document.getElementById('status-message');
        
        try {
            // First get the listener configuration
            const response = await fetch(`/api/listeners/${id}`);
            if (!response.ok) {
                throw new Error(`Failed to get listener details (${response.status})`);
            }
            
            const listener = await response.json();
            console.log("Retrieved listener for recreation:", listener);
            
            // Extract the config from the listener
            const config = listener.config || listener;
            
            // Remove the ID as we're creating a new one
            const newConfig = {...config};
            delete newConfig.id;
            
            statusMessage.textContent = "Recreating listener...";
            
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
            
            statusMessage.textContent = "Listener started successfully (recreated)";
            statusMessage.className = "status-message success";
            await this.fetchListenerList();
            
            setTimeout(() => {
                statusMessage.className = "status-message hidden";
            }, 3000);
            
        } catch (error) {
            console.error("Error in fallback listener start:", error);
            statusMessage.textContent = `Error: ${error.message}`;
            statusMessage.className = "status-message error";
        }
    }

    showError(message) {
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = `Error: ${message}`;
        statusMessage.className = 'status-message error';
    }

    showSuccess(message) {
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = message;
        statusMessage.className = 'status-message success';
        setTimeout(() => {
            statusMessage.className = 'status-message hidden';
        }, 3000);
    }

    showLoading(message) {
        const statusMessage = document.getElementById('status-message');
        statusMessage.textContent = message;
        statusMessage.className = 'status-message loading';
    }

    startAutoRefresh() {
        // Server-Sent Events for live updates
        if (window.EventSource) {
            const es = new EventSource('/api/listeners/stream');
            es.onmessage = () => this.fetchListenerList();
            es.onerror = () => console.warn('Listeners SSE error, falling back to polling');
        } else {
            // fallback polling
            const interval = 30000;
            let timer = setInterval(() => this.refreshListenersList(), interval);
            document.addEventListener('visibilitychange', () => {
                if (document.hidden) clearInterval(timer);
                else { this.refreshListenersList(); timer = setInterval(() => this.refreshListenersList(), interval); }
            });
        }
    }

    refreshListenersList() {
        const listenersList = document.getElementById('active-listeners');
        if (!listenersList) {
            console.warn("Cannot refresh listeners: Element 'active-listeners' not found");
            return false;
        }
        
        return this.fetchListenerList().catch(error => {
            console.error("Error refreshing listeners list:", error);
            return false;
        });
    }
}

// Initialize the listener manager when the page loads
let listenerManager;
document.addEventListener('DOMContentLoaded', () => {
    listenerManager = new ListenerManager();
});
