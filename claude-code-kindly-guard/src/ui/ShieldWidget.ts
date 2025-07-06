import { ShieldStatus, Threat } from '../types/shield';

export interface ClaudeCodeAPI {
  createFloatingWidget(options: WidgetOptions): Widget;
  showNotification(message: string, options?: NotificationOptions): void;
  registerCommand(command: string, callback: () => void): void;
}

export interface Widget {
  update(content: string): void;
  show(): void;
  hide(): void;
  dispose(): void;
}

export interface WidgetOptions {
  position: 'top-right' | 'bottom-right' | 'top-left' | 'bottom-left';
  width: number;
  height: number;
  transparent: boolean;
}

export interface NotificationOptions {
  type: 'info' | 'warning' | 'error';
  duration?: number;
  actions?: Array<{ label: string; callback: () => void }>;
}

export class ShieldWidget {
  private widget: Widget | null = null;
  private api: ClaudeCodeAPI;
  private status: ShieldStatus | null = null;
  private recentThreats: Threat[] = [];
  private maxRecentThreats = 5;

  constructor(api: ClaudeCodeAPI) {
    this.api = api;
  }

  initialize(): void {
    this.widget = this.api.createFloatingWidget({
      position: 'bottom-right',
      width: 280,
      height: 120,
      transparent: true
    });

    this.updateDisplay();
  }

  updateStatus(status: ShieldStatus): void {
    this.status = status;
    this.updateDisplay();
  }

  addThreat(threat: Threat): void {
    this.recentThreats.unshift(threat);
    if (this.recentThreats.length > this.maxRecentThreats) {
      this.recentThreats.pop();
    }
    this.updateDisplay();
    this.showThreatNotification(threat);
  }

  private updateDisplay(): void {
    if (!this.widget) return;

    const content = this.generateContent();
    this.widget.update(content);
  }

  private generateContent(): string {
    const statusIcon = this.getStatusIcon();
    const statusText = this.getStatusText();
    const statsText = this.getStatsText();
    
    return `
<div class="shield-widget">
  <div class="shield-header">
    <span class="shield-icon">${statusIcon}</span>
    <span class="shield-title">KindlyGuard</span>
  </div>
  <div class="shield-status">${statusText}</div>
  <div class="shield-stats">${statsText}</div>
  <div class="shield-actions">
    <a href="#" onclick="expandDetails()">Details</a>
  </div>
</div>

<style>
  .shield-widget {
    background: rgba(30, 30, 30, 0.95);
    border: 1px solid rgba(255, 255, 255, 0.1);
    border-radius: 8px;
    padding: 12px;
    font-family: system-ui, -apple-system, sans-serif;
    font-size: 12px;
    color: #ffffff;
  }
  
  .shield-header {
    display: flex;
    align-items: center;
    margin-bottom: 8px;
  }
  
  .shield-icon {
    font-size: 16px;
    margin-right: 6px;
  }
  
  .shield-title {
    font-weight: 600;
  }
  
  .shield-status {
    color: #00ff00;
    margin-bottom: 4px;
  }
  
  .shield-stats {
    color: #999;
    font-size: 11px;
  }
  
  .shield-actions {
    margin-top: 8px;
    text-align: right;
  }
  
  .shield-actions a {
    color: #4a9eff;
    text-decoration: none;
    font-size: 11px;
  }
</style>
    `;
  }

  private getStatusIcon(): string {
    if (!this.status?.connected) return '⚠️';
    switch (this.status.mode) {
      case 'active': return '🛡️';
      case 'passive': return '👁️';
      case 'learning': return '🧠';
      default: return '❓';
    }
  }

  private getStatusText(): string {
    if (!this.status?.connected) return 'Disconnected';
    return `Connected • ${this.status.mode} mode`;
  }

  private getStatsText(): string {
    if (!this.status?.connected) return '';
    const { threatsBlocked, requestsScanned } = this.status.stats;
    return `${threatsBlocked} threats blocked • ${requestsScanned} scanned`;
  }

  private showThreatNotification(threat: Threat): void {
    const emoji = this.getThreatEmoji(threat.severity);
    const message = `${emoji} ${threat.type}: ${threat.description}`;
    
    this.api.showNotification(message, {
      type: threat.severity === 'critical' ? 'error' : 'warning',
      duration: 5000,
      actions: [
        {
          label: 'View Details',
          callback: () => this.showThreatDetails(threat)
        }
      ]
    });
  }

  private getThreatEmoji(severity: string): string {
    switch (severity) {
      case 'critical': return '🚨';
      case 'high': return '⚠️';
      case 'medium': return '⚡';
      case 'low': return 'ℹ️';
      default: return '❓';
    }
  }

  private showThreatDetails(threat: Threat): void {
    // This would open a detailed view in Claude Code
    console.log('Show threat details:', threat);
  }

  show(): void {
    this.widget?.show();
  }

  hide(): void {
    this.widget?.hide();
  }

  dispose(): void {
    this.widget?.dispose();
    this.widget = null;
  }
}