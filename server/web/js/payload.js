class PayloadManager {
    constructor() {
        this.logSocket = null;
        this.isGeneratingPayload = false;
        this.currentPayloadId = null;
        this.logDisplay = document.getElementById('build-log-display');
        // The buildLogs element doesn't exist in the HTML, removing this reference
        this.autoScrollEnabled = true;
        this.wsReconnectAttempts = 0;
        this.MAX_RECONNECT_ATTEMPTS = 10;

        this.setupEventListeners();
        this.connectToLogStream();
        this.loadListeners();
    }

    setupEventListeners() {
        // DLL sideloading toggle
        document.getElementById('dllSideloading').addEventListener('change', function() {
            document.getElementById('sideloadingOptions').classList.toggle('hidden', !this.checked);
        });
        // SOCKS5 proxy toggle
        document.getElementById('socks5_enabled').addEventListener('change', function() {
            document.getElementById('socks5Options').classList.toggle('hidden', !this.checked);
        });

        // Architecture change handler
        document.getElementById('architecture').addEventListener('change', (e) => {
            this.updateAvailableFormats(e.target.value);
        });

        // Form submission handler
        document.getElementById('payloadForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.handleFormSubmission(e);
        });
    }

    connectToLogStream() {
        if (this.wsReconnectAttempts >= this.MAX_RECONNECT_ATTEMPTS) {
            this.addLogEntry('system', 'Maximum WebSocket reconnection attempts reached. Please refresh the page.', 'ERROR');
            return;
        }

        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}/ws/logs`;
        
        if (this.logSocket) {
            this.logSocket.close();
        }

        this.logSocket = new WebSocket(wsUrl);
        
        this.logSocket.onopen = () => {
            this.wsReconnectAttempts = 0;
            this.addLogEntry('system', 'Connected to server log stream', 'INFO');
        };
        
        this.logSocket.onmessage = (event) => {
            try {
                const logEntry = JSON.parse(event.data);
                this.processLogEntry(logEntry);
            } catch (error) {
                console.error('Error parsing log message:', error);
            }
        };
        
        this.logSocket.onclose = () => {
            console.log('Disconnected from log stream');
            setTimeout(() => this.connectToLogStream(), 3000);
        };
        
        this.logSocket.onerror = (error) => {
            console.error('WebSocket error:', error);
            this.addLogEntry('system', 'Error connecting to log stream', 'ERROR');
        };
    }

    processLogEntry(logEntry) {
        if (this.isGeneratingPayload && logEntry.message.includes('[INFO]') && 
            (logEntry.message.includes('payload') || 
             logEntry.message.includes('build') || 
             logEntry.message.includes('agent'))) {
            this.addLogToDisplay(logEntry);
        }
        this.addToBuildLogs(logEntry);
    }

    addLogToDisplay(logEntry) {
        const logElement = document.createElement('div');
        logElement.className = 'log-entry';
        
        const timestamp = new Date(logEntry.timestamp);
        const timeStr = timestamp.toLocaleTimeString();
        let message = logEntry.message.trim();
        let level = logEntry.level;

        if (message.includes('[INFO]')) {
            level = 'INFO';
            message = message.replace('[INFO]', '').trim();
        } else if (message.includes('[ERROR]')) {
            level = 'ERROR';
            message = message.replace('[ERROR]', '').trim();
        } else if (message.includes('[WARNING]')) {
            level = 'WARNING';
            message = message.replace('[WARNING]', '').trim();
        }
        
        logElement.innerHTML = `
            <span class="log-timestamp">${timeStr}</span>
            <span class="log-level-${level}">[${level}]</span>
            <span class="log-message log-message-payload">${message}</span>
        `;
        
        this.logDisplay.appendChild(logElement);
        
        if (this.autoScrollEnabled) {
            this.logDisplay.scrollTop = this.logDisplay.scrollHeight;
        }
    }

    addToBuildLogs(logEntry) {
        // Instead of using this.buildLogs which doesn't exist, use this.logDisplay
        const logElement = document.createElement('div');
        logElement.className = 'log-entry';
        
        const timestamp = new Date(logEntry.timestamp);
        const timeStr = timestamp.toLocaleTimeString();
        
        logElement.innerHTML = `
            <span class="log-timestamp">${timeStr}</span>
            <span class="log-level-${logEntry.level}">[${logEntry.level}]</span>
            <span class="log-message">${logEntry.message}</span>
        `;
        
        // Use this.logDisplay instead of this.buildLogs
        this.logDisplay.appendChild(logElement);
        
        if (this.autoScrollEnabled) {
            this.logDisplay.scrollTop = this.logDisplay.scrollHeight;
        }
    }

    async loadListeners() {
        try {
            const response = await fetch('/api/listeners/list');
            const listeners = await response.json();
            
            const listenerSelect = document.getElementById('listener');
            listenerSelect.innerHTML = '<option value="">Select a listener...</option>';
            
            listeners.forEach(listener => {
                const config = listener.config || {};
                const id = config.id || listener.id || '';
                const name = config.name || listener.name || 'Unnamed';
                const protocol = config.protocol || listener.Protocol || listener.type || 'Unknown';
                
                if (id) {
                    const option = document.createElement('option');
                    option.value = id;
                    option.textContent = `${name} (${protocol})`;
                    listenerSelect.appendChild(option);
                }
            });
            
            if (listenerSelect.options.length <= 1) {
                console.warn('No valid listeners found');
            }
        } catch (error) {
            console.error('Error loading listeners:', error);
            showError('Failed to load listeners');
        }
    }

    updateAvailableFormats(architecture) {
        const formatSelect = document.getElementById('format');
        const isWindows = ['x64', 'x86'].includes(architecture);
        
        formatSelect.innerHTML = '';
        
        if (isWindows) {
            const windowsFormats = [
                { value: 'windows_exe', label: 'Windows EXE' },
                { value: 'windows_dll', label: 'Windows DLL' },
                { value: 'windows_shellcode', label: 'Windows Shellcode' },
                { value: 'windows_service', label: 'Windows Service EXE' }
            ];
            
            windowsFormats.forEach(format => {
                const option = document.createElement('option');
                option.value = format.value;
                option.textContent = format.label;
                formatSelect.appendChild(option);
            });
        } else if (architecture === 'arm64') {
            [
                { value: 'linux_elf', label: 'Linux ELF' },
                { value: 'linux_arm_binary', label: 'Linux ARM Binary' }
            ].forEach(format => {
                const option = document.createElement('option');
                option.value = format.value;
                option.textContent = format.label;
                formatSelect.appendChild(option);
            });
        } else {
            const option = document.createElement('option');
            option.value = 'linux_elf';
            option.textContent = 'Linux ELF';
            formatSelect.appendChild(option);
        }
        
        formatSelect.dispatchEvent(new Event('change'));
    }

    async handleFormSubmission(e) {
        const formData = new FormData(e.target);
        const config = Object.fromEntries(formData);
        // Enforce listener selection
        if (!config.listener || config.listener === "") {
            alert("You must select a listener before generating a payload. Agents must connect to a valid listener port, not the web server port.");
            this.addLogEntry('payload', 'No listener selected. Payload generation aborted.', 'ERROR');
            return;
        }
        // Convert checkbox values to boolean
        config.indirectSyscall = config.indirectSyscall === 'on';
        config.dllSideloading = config.dllSideloading === 'on';
        config.socks5_enabled = config.socks5_enabled === 'on';
        config.socks5_host = String(config.socks5_host || '').trim();
        config.socks5_port = parseInt(config.socks5_port, 10) || 0;

        // ---  Parse OPSEC fields ---
        config.proc_scan_interval_secs = parseInt(config.proc_scan_interval_secs, 10) || 300;
        config.base_threshold_enter_full_opsec = parseFloat(config.base_threshold_enter_full_opsec) || 60.0;
        config.base_threshold_exit_full_opsec = parseFloat(config.base_threshold_exit_full_opsec) || 60.0;
        config.base_threshold_enter_reduced_activity = parseFloat(config.base_threshold_enter_reduced_activity) || 20.0;
        config.base_threshold_exit_reduced_activity = parseFloat(config.base_threshold_exit_reduced_activity) || 20.0;
        config.min_duration_full_opsec_secs = parseInt(config.min_duration_full_opsec_secs, 10) || 300;
        config.min_duration_reduced_activity_secs = parseInt(config.min_duration_reduced_activity_secs, 10) || 120;
        config.min_duration_background_opsec_secs = parseInt(config.min_duration_background_opsec_secs, 10) || 60;
        config.reduced_activity_sleep_secs = parseInt(config.reduced_activity_sleep_secs, 10) || 120;
        config.base_max_consecutive_c2_failures = parseInt(config.base_max_consecutive_c2_failures, 10) || 5;
        config.c2_failure_threshold_increase_factor = parseFloat(config.c2_failure_threshold_increase_factor) || 1.1;
        config.c2_failure_threshold_decrease_factor = parseFloat(config.c2_failure_threshold_decrease_factor) || 0.9;
        config.c2_threshold_adjust_interval_secs = parseInt(config.c2_threshold_adjust_interval_secs, 10) || 3600;
        config.c2_dynamic_threshold_max_multiplier = parseFloat(config.c2_dynamic_threshold_max_multiplier) || 2.0;
        // --- END NEW OPSEC FIELDS ---

        if (config.sleep) {
            config.sleep = parseInt(config.sleep, 10);
        }

        const downloadSection = document.getElementById('download-section');
        downloadSection.classList.add('hidden');

        this.clearLogDisplay();
        this.isGeneratingPayload = true;

        this.addLogEntry('payload', 'Starting payload generation...', 'INFO');
        this.addLogEntry('payload', `Payload configuration: ${JSON.stringify(config, null, 2)}`, 'INFO');

        try {
            const response = await fetch('/api/payload/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(config)
            });

            if (!response.ok) {
                throw new Error('Failed to generate payload');
            }

            const result = await response.json();
            this.currentPayloadId = result.id;
            
            this.addLogEntry('payload', `Successfully generated payload: ${result.filename} (${formatBytes(result.size)})`, 'INFO');
            if (result.mutation_seed) {
                this.addLogEntry('payload', `Mutation seed: ${result.mutation_seed} (record it with the git revision to reproduce mutation choices; enrollment remains unique per build)`, 'INFO');
            }
            
            downloadSection.classList.remove('hidden');
            
            const fileInfo = downloadSection.querySelector('.file-info');
            fileInfo.querySelector('.filename').textContent = result.filename;
            fileInfo.querySelector('.filesize').textContent = formatBytes(result.size);
            
            const downloadButton = downloadSection.querySelector('.download-button');
            downloadButton.onclick = () => {
                window.location.href = `/api/payload/download/${result.id}`;
            };
        } catch (error) {
            console.error('Error:', error);
            this.addLogEntry('payload', `Failed to generate payload: ${error.message}`, 'ERROR');
            alert('Failed to generate payload: ' + error.message);
        } finally {
            this.isGeneratingPayload = false;
        }
    }

    addLogEntry(source, message, level) {
        const entry = {
            timestamp: new Date().toISOString(),
            level: level || 'INFO',
            message: message
        };
        
        this.addToBuildLogs(entry);
        
        if (source === 'payload' && this.isGeneratingPayload) {
            this.addLogToDisplay(entry);
        }
    }

    clearLogDisplay() {
        if (this.logDisplay) {
            this.logDisplay.innerHTML = '';
        }
    }

    clearBuildLogs() {
        // Use this.logDisplay instead of this.buildLogs
        if (this.logDisplay) {
            this.logDisplay.innerHTML = '';
        }
    }

    toggleAutoScroll() {
        this.autoScrollEnabled = !this.autoScrollEnabled;
        const autoScrollBtn = document.getElementById('autoScrollLogsBtn');
        
        if (this.autoScrollEnabled) {
            autoScrollBtn.textContent = 'Auto-scroll: On';
            if (this.logDisplay) this.logDisplay.scrollTop = this.logDisplay.scrollHeight;
            if (this.logDisplay) this.logDisplay.scrollTop = this.logDisplay.scrollHeight;
        } else {
            autoScrollBtn.textContent = 'Auto-scroll: Off';
        }
    }
}

// Initialize the payload manager when the page loads
let payloadManager;
document.addEventListener('DOMContentLoaded', () => {
    payloadManager = new PayloadManager();
});
