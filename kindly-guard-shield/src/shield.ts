import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrent } from '@tauri-apps/api/window';

interface Threat {
    id: string;
    threat_type: string;
    severity: 'Low' | 'Medium' | 'High' | 'Critical';
    source: string;
    details: string;
    timestamp: string;
    blocked: boolean;
}

interface Statistics {
    threats_blocked: number;
    threats_analyzed: number;
    protection_enabled: boolean;
    uptime_seconds: number;
    last_threat_time?: string;
    threat_breakdown: ThreatBreakdown;
}

interface ThreatBreakdown {
    unicode_invisible: number;
    unicode_bidi: number;
    unicode_homoglyph: number;
    injection_attempt: number;
    path_traversal: number;
    suspicious_pattern: number;
    rate_limit_violation: number;
    unknown: number;
}

interface IpcResult<T> {
    success: boolean;
    data?: T;
    error?: string;
}

interface WsMessage {
    type: 'threat' | 'status' | 'heartbeat' | 'error';
    threats?: Threat[];
    protection_enabled?: boolean;
    threats_blocked?: number;
    message?: string;
}

class KindlyGuardShield {
    private statsInterval: number | null = null;
    private wsConnection: WebSocket | null = null;

    constructor() {
        this.init();
    }

    private async init(): Promise<void> {
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

    private setupEventListeners(): void {
        // Toggle protection button
        const toggleBtn = document.getElementById('toggle-protection');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', async () => {
                try {
                    const result = await invoke<IpcResult<boolean>>('toggle_protection');
                    if (result.success && result.data !== undefined) {
                        this.updateProtectionStatus(result.data);
                    }
                } catch (error) {
                    console.error('Failed to toggle protection:', error);
                }
            });
        }

        // Clear threats button
        const clearBtn = document.getElementById('clear-threats');
        if (clearBtn) {
            clearBtn.addEventListener('click', async () => {
                try {
                    const result = await invoke<IpcResult<void>>('clear_threats');
                    if (result.success) {
                        this.clearThreatsList();
                    }
                } catch (error) {
                    console.error('Failed to clear threats:', error);
                }
            });
        }

        // Minimize button
        const minimizeBtn = document.getElementById('minimize');
        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', async () => {
                try {
                    await invoke('hide_shield');
                } catch (error) {
                    console.error('Failed to minimize:', error);
                }
            });
        }
    }

    private async setupTauriListeners(): Promise<void> {
        // Listen for toggle protection event from tray
        await listen('toggle-protection', async () => {
            const toggleBtn = document.getElementById('toggle-protection') as HTMLButtonElement;
            if (toggleBtn) {
                toggleBtn.click();
            }
        });

        // Listen for show stats event
        await listen('show-stats', () => {
            const statsContainer = document.querySelector('.stats-container');
            if (statsContainer) {
                statsContainer.scrollIntoView({ behavior: 'smooth' });
            }
        });

        // Listen for show about event
        await listen('show-about', () => {
            this.showAboutDialog();
        });
    }

    private startPeriodicUpdates(): void {
        // Update statistics every 5 seconds
        this.statsInterval = window.setInterval(() => {
            this.updateStatistics();
        }, 5000);
    }

    private async updateStatistics(): Promise<void> {
        try {
            const result = await invoke<IpcResult<Statistics>>('get_statistics');
            if (result.success && result.data) {
                const stats = result.data;
                
                // Update values
                this.updateElement('threats-blocked', stats.threats_blocked.toString());
                this.updateElement('threats-analyzed', stats.threats_analyzed.toString());
                this.updateElement('uptime', this.formatUptime(stats.uptime_seconds));
                
                // Update protection status
                this.updateProtectionStatus(stats.protection_enabled);
            }
        } catch (error) {
            console.error('Failed to update statistics:', error);
        }
    }

    private updateElement(id: string, text: string): void {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = text;
        }
    }

    private updateProtectionStatus(enabled: boolean): void {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.querySelector('.status-text');
        
        if (statusIndicator && statusText) {
            if (enabled) {
                statusIndicator.classList.add('active');
                statusText.textContent = 'Protection Active';
            } else {
                statusIndicator.classList.remove('active');
                statusText.textContent = 'Protection Disabled';
            }
        }
    }

    private formatUptime(seconds: number): string {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }

    private connectWebSocket(): void {
        if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
            return;
        }

        try {
            this.wsConnection = new WebSocket('ws://localhost:9955');

            this.wsConnection.onopen = () => {
                console.log('Connected to WebSocket server');
                // Subscribe to threat updates
                this.wsConnection?.send(JSON.stringify({ type: 'subscribe' }));
            };

            this.wsConnection.onmessage = (event) => {
                try {
                    const message: WsMessage = JSON.parse(event.data);
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

    private handleWebSocketMessage(message: WsMessage): void {
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
                    this.updateElement('threats-blocked', message.threats_blocked.toString());
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

    private addThreatToList(threat: Threat): void {
        const threatsList = document.getElementById('threats-list');
        if (!threatsList) return;
        
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

    private formatThreatType(type: string): string {
        const typeMap: Record<string, string> = {
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

    private formatTime(timestamp: string): string {
        const date = new Date(timestamp);
        const now = new Date();
        const diff = now.getTime() - date.getTime();

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

    private clearThreatsList(): void {
        const threatsList = document.getElementById('threats-list');
        if (threatsList) {
            threatsList.innerHTML = '<div class="no-threats">No threats detected</div>';
        }
    }

    private showAboutDialog(): void {
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

    public destroy(): void {
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

// Export for module usage
export default KindlyGuardShield;