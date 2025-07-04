const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const { getCurrent } = window.__TAURI__.window;

class KindlyGuardShield {
    constructor() {
        this.statsInterval = null;
        this.wsConnection = null;
        this.init();
    }

    async init() {
        console.log('Initializing KindlyGuard Shield');
        
        // Set up event listeners
        this.setupEventListeners();
        
        // Set up Tauri event listeners
        await this.setupTauriListeners();
        
        // Initial stats update
        await this.updateStatistics();
        
        // Start periodic updates
        this.startPeriodicUpdates();
        
        // Try to connect to WebSocket
        this.connectWebSocket();
    }

    setupEventListeners() {
        // Toggle protection button
        document.getElementById('toggle-protection').addEventListener('click', async () => {
            try {
                const result = await invoke('toggle_protection');
                if (result.success) {
                    this.updateProtectionStatus(result.data);
                }
            } catch (error) {
                console.error('Failed to toggle protection:', error);
            }
        });

        // Clear threats button
        document.getElementById('clear-threats').addEventListener('click', async () => {
            try {
                const result = await invoke('clear_threats');
                if (result.success) {
                    this.clearThreatsList();
                }
            } catch (error) {
                console.error('Failed to clear threats:', error);
            }
        });

        // Minimize button
        document.getElementById('minimize').addEventListener('click', async () => {
            try {
                await invoke('hide_shield');
            } catch (error) {
                console.error('Failed to minimize:', error);
            }
        });
    }

    async setupTauriListeners() {
        // Listen for toggle protection event from tray
        await listen('toggle-protection', async () => {
            await document.getElementById('toggle-protection').click();
        });

        // Listen for show stats event
        await listen('show-stats', () => {
            // Scroll to stats or highlight them
            document.querySelector('.stats-container').scrollIntoView({ behavior: 'smooth' });
        });

        // Listen for show about event
        await listen('show-about', () => {
            this.showAboutDialog();
        });
    }

    startPeriodicUpdates() {
        // Update statistics every 5 seconds
        this.statsInterval = setInterval(() => {
            this.updateStatistics();
        }, 5000);
    }

    async updateStatistics() {
        try {
            const result = await invoke('get_statistics');
            if (result.success && result.data) {
                const stats = result.data;
                
                // Update values
                document.getElementById('threats-blocked').textContent = stats.threats_blocked;
                document.getElementById('threats-analyzed').textContent = stats.threats_analyzed;
                document.getElementById('uptime').textContent = this.formatUptime(stats.uptime_seconds);
                
                // Update protection status
                this.updateProtectionStatus(stats.protection_enabled);
            }
        } catch (error) {
            console.error('Failed to update statistics:', error);
        }
    }

    updateProtectionStatus(enabled) {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.querySelector('.status-text');
        
        if (enabled) {
            statusIndicator.classList.add('active');
            statusText.textContent = 'Protection Active';
        } else {
            statusIndicator.classList.remove('active');
            statusText.textContent = 'Protection Disabled';
        }
    }

    formatUptime(seconds) {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }

    connectWebSocket() {
        if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
            return;
        }

        try {
            this.wsConnection = new WebSocket('ws://localhost:9955');

            this.wsConnection.onopen = () => {
                console.log('Connected to WebSocket server');
                // Subscribe to threat updates
                this.wsConnection.send(JSON.stringify({ type: 'subscribe' }));
            };

            this.wsConnection.onmessage = (event) => {
                try {
                    const message = JSON.parse(event.data);
                    this.handleWebSocketMessage(message);
                } catch (error) {
                    console.error('Failed to parse WebSocket message:', error);
                }
            };

            this.wsConnection.onerror = (error) => {
                console.error('WebSocket error:', error);
            };

            this.wsConnection.onclose = () => {
                console.log('WebSocket connection closed');
                // Reconnect after 5 seconds
                setTimeout(() => this.connectWebSocket(), 5000);
            };
        } catch (error) {
            console.error('Failed to connect to WebSocket:', error);
        }
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'threat':
                if (message.threats) {
                    message.threats.forEach(threat => this.addThreatToList(threat));
                }
                break;
            case 'status':
                if (message.protection_enabled !== undefined) {
                    this.updateProtectionStatus(message.protection_enabled);
                }
                if (message.threats_blocked !== undefined) {
                    document.getElementById('threats-blocked').textContent = message.threats_blocked;
                }
                break;
            case 'heartbeat':
                // Keep connection alive
                break;
            case 'error':
                console.error('WebSocket error:', message.message);
                break;
        }
    }

    addThreatToList(threat) {
        const threatsList = document.getElementById('threats-list');
        
        // Remove "no threats" message if present
        const noThreats = threatsList.querySelector('.no-threats');
        if (noThreats) {
            noThreats.remove();
        }

        // Create threat element
        const threatElement = document.createElement('div');
        threatElement.className = 'threat-item';
        threatElement.innerHTML = `
            <div class="threat-header">
                <div class="threat-type">
                    <div class="threat-icon ${threat.severity.toLowerCase()}"></div>
                    <span class="threat-name">${this.formatThreatType(threat.threat_type)}</span>
                </div>
                <span class="threat-time">${this.formatTime(threat.timestamp)}</span>
            </div>
            <div class="threat-details">${threat.details}</div>
            <div class="threat-source">Source: ${threat.source}</div>
        `;

        // Add to top of list
        threatsList.insertBefore(threatElement, threatsList.firstChild);

        // Keep only last 50 threats
        const threats = threatsList.querySelectorAll('.threat-item');
        if (threats.length > 50) {
            threats[threats.length - 1].remove();
        }
    }

    formatThreatType(type) {
        const typeMap = {
            'UnicodeInvisible': 'Unicode Invisible',
            'UnicodeBiDi': 'Unicode BiDi',
            'UnicodeHomoglyph': 'Unicode Homoglyph',
            'InjectionAttempt': 'Injection Attempt',
            'PathTraversal': 'Path Traversal',
            'SuspiciousPattern': 'Suspicious Pattern',
            'RateLimitViolation': 'Rate Limit',
            'Unknown': 'Unknown Threat'
        };
        return typeMap[type] || type;
    }

    formatTime(timestamp) {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now - date;

        if (diff < 60000) {
            return 'Just now';
        } else if (diff < 3600000) {
            const minutes = Math.floor(diff / 60000);
            return `${minutes}m ago`;
        } else if (diff < 86400000) {
            const hours = Math.floor(diff / 3600000);
            return `${hours}h ago`;
        } else {
            return date.toLocaleDateString();
        }
    }

    clearThreatsList() {
        const threatsList = document.getElementById('threats-list');
        threatsList.innerHTML = '<div class="no-threats">No threats detected</div>';
    }

    showAboutDialog() {
        // Create a simple about dialog
        const dialog = document.createElement('div');
        dialog.style.cssText = `
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            z-index: 1000;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
        `;
        
        dialog.innerHTML = `
            <h2 style="margin-bottom: 20px;">KindlyGuard Shield</h2>
            <p style="color: var(--text-secondary); margin-bottom: 10px;">Version 0.1.0</p>
            <p style="color: var(--text-secondary); margin-bottom: 20px;">Advanced security protection for Claude Code</p>
            <button class="btn btn-primary" onclick="this.parentElement.remove()">Close</button>
        `;
        
        document.body.appendChild(dialog);
    }

    destroy() {
        if (this.statsInterval) {
            clearInterval(this.statsInterval);
        }
        if (this.wsConnection) {
            this.wsConnection.close();
        }
    }
}

// Initialize the shield
const shield = new KindlyGuardShield();

// Clean up on window unload
window.addEventListener('beforeunload', () => {
    shield.destroy();
});