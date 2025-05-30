class TerminalManager {
    constructor() {
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentWorkingDirectory = '~';
        this.terminalOutput = document.getElementById('terminal-output');
        this.terminalInput = document.getElementById('terminal-input');
        this.setupWebSocket();
        this.setupEventListeners();
        this.focusInput();
    }

    setupWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        this.ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/terminal`);

        this.ws.onmessage = (event) => {
            let response;
            try {
                response = JSON.parse(event.data);
            } catch (e) {
                console.error('Invalid JSON from terminal websocket:', e);
                return;
            }
            
            if (response.type === 'tab_completion') {
                this.handleTabCompletionResponse(response.completions);
                return;
            }
            
            if (response.cwd) {
                this.currentWorkingDirectory = response.cwd;
                this.updatePrompt();
            }
            if (response.output) {
                this.appendToTerminal(response.output, response.error);
            }
        };

        this.ws.onclose = () => {
            this.appendToTerminal('Connection to server closed. Attempting to reconnect...', true);
            setTimeout(() => this.setupWebSocket(), 5000);
        };
    }

    setupEventListeners() {
        this.terminalInput.addEventListener('keydown', (event) => this.handleKeyDown(event));

        // Focus input when clicking anywhere in terminal
        document.querySelector('.terminal-container').addEventListener('click', () => {
            if (window.getSelection().toString() === '') {
                this.terminalInput.focus();
            }
        });
    }

    handleKeyDown(e) {
        switch (e.key) {
            case 'Enter':
                this.handleEnterKey();
                break;
            case 'ArrowUp':
                this.handleArrowUp(e);
                break;
            case 'ArrowDown':
                this.handleArrowDown(e);
                break;
            case 'Tab':
                this.handleTab(e);
                break;
        }
    }

    handleEnterKey() {
        const command = this.terminalInput.value.trim();
        if (command) {
            this.appendCommand(command);
            this.ws.send(command);
            this.commandHistory.push(command);
            this.historyIndex = this.commandHistory.length;
            this.terminalInput.value = '';
        }
    }

    handleArrowUp(e) {
        e.preventDefault();
        if (this.historyIndex > 0) {
            this.historyIndex--;
            this.terminalInput.value = this.commandHistory[this.historyIndex];
            // Move cursor to end of input
            setTimeout(() => this.terminalInput.selectionStart = this.terminalInput.selectionEnd = this.terminalInput.value.length, 0);
        }
    }

    handleArrowDown(e) {
        e.preventDefault();
        if (this.historyIndex < this.commandHistory.length - 1) {
            this.historyIndex++;
            this.terminalInput.value = this.commandHistory[this.historyIndex];
        } else {
            this.historyIndex = this.commandHistory.length;
            this.terminalInput.value = '';
        }
    }

    handleTab(e) {
        e.preventDefault();
        // Send tab completion request
        this.ws.send(JSON.stringify({
            type: 'tab_completion',
            partial: this.terminalInput.value
        }));
    }

    handleTabCompletionResponse(completions) {
        if (!completions || completions.length === 0) {
            return;
        }

        const currentInput = this.terminalInput.value;
        const cursorPos = this.terminalInput.selectionStart;
        
        if (completions.length === 1) {
            // Single completion - auto-complete
            this.applySingleCompletion(completions[0], currentInput, cursorPos);
        } else {
            // Multiple completions - show options and apply common prefix
            this.handleMultipleCompletions(completions, currentInput, cursorPos);
        }
    }

    applySingleCompletion(completion, currentInput, cursorPos) {
        // Find the word boundary to replace
        const beforeCursor = currentInput.substring(0, cursorPos);
        const afterCursor = currentInput.substring(cursorPos);
        
        // Find the start of the current word
        const wordStart = Math.max(
            beforeCursor.lastIndexOf(' ') + 1,
            beforeCursor.lastIndexOf('\t') + 1,
            0
        );
        
        // Replace the current word with the completion
        const newInput = beforeCursor.substring(0, wordStart) + completion + afterCursor;
        this.terminalInput.value = newInput;
        
        // Position cursor at the end of the completion
        const newCursorPos = wordStart + completion.length;
        this.terminalInput.setSelectionRange(newCursorPos, newCursorPos);
    }

    handleMultipleCompletions(completions, currentInput, cursorPos) {
        // Show available completions
        this.showCompletionOptions(completions);
        
        // Find common prefix and apply it
        const commonPrefix = this.findCommonPrefix(completions);
        if (commonPrefix) {
            const beforeCursor = currentInput.substring(0, cursorPos);
            const afterCursor = currentInput.substring(cursorPos);
            
            // Find the start of the current word
            const wordStart = Math.max(
                beforeCursor.lastIndexOf(' ') + 1,
                beforeCursor.lastIndexOf('\t') + 1,
                0
            );
            
            const currentWord = beforeCursor.substring(wordStart);
            
            // Only apply if the common prefix is longer than current word
            if (commonPrefix.length > currentWord.length) {
                const newInput = beforeCursor.substring(0, wordStart) + commonPrefix + afterCursor;
                this.terminalInput.value = newInput;
                
                const newCursorPos = wordStart + commonPrefix.length;
                this.terminalInput.setSelectionRange(newCursorPos, newCursorPos);
            }
        }
    }

    findCommonPrefix(completions) {
        if (completions.length === 0) return '';
        if (completions.length === 1) return completions[0];
        
        let prefix = completions[0];
        for (let i = 1; i < completions.length; i++) {
            while (!completions[i].startsWith(prefix) && prefix.length > 0) {
                prefix = prefix.substring(0, prefix.length - 1);
            }
        }
        return prefix;
    }

    showCompletionOptions(completions) {
        // Display completions in the terminal output with special styling
        const outputDiv = document.createElement('div');
        outputDiv.className = 'completion-output';
        outputDiv.textContent = completions.join('  ');
        this.terminalOutput.appendChild(outputDiv);
        this.scrollToBottom();
        
        // Also show the current command line again
        this.appendCommand(this.terminalInput.value);
    }

    updatePrompt() {
        // Update the prompt in the input container
        const pathElement = document.querySelector('.terminal-input-container .prompt .path');
        if (pathElement) {
            pathElement.textContent = this.currentWorkingDirectory;
        }
    }

    appendToTerminal(text, isError = false) {
        if (text.trim()) {
            const outputDiv = document.createElement('div');
            outputDiv.className = isError ? 'command-output error-output' : 'command-output';
            outputDiv.textContent = text;
            this.terminalOutput.appendChild(outputDiv);
        }
        this.scrollToBottom();
    }

    appendCommand(command) {
        const cmdLine = document.createElement('div');
        cmdLine.className = 'command-line';
        cmdLine.innerHTML = `<span class="prompt"><span class="user">user@server</span>:<span class="path">${this.currentWorkingDirectory}</span>$</span> ${command}`;
        this.terminalOutput.appendChild(cmdLine);
        this.scrollToBottom();
    }

    scrollToBottom() {
        this.terminalOutput.scrollTop = this.terminalOutput.scrollHeight;
    }

    focusInput() {
        this.terminalInput.focus();
    }

    clear() {
        this.terminalOutput.innerHTML = '';
    }
}

// Initialize the terminal manager when the page loads
let terminalManager;
document.addEventListener('DOMContentLoaded', () => {
    terminalManager = new TerminalManager();
});