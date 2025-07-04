import { ShieldClient } from './client/ShieldClient';
import { ShieldWidget, ClaudeCodeAPI } from './ui/ShieldWidget';
import { ShieldConfig, ShieldStatus, Threat } from './types/shield';

export class KindlyGuardExtension {
  private client: ShieldClient;
  private widget: ShieldWidget;
  private config: ShieldConfig;
  private isActive = false;

  constructor(private api: ClaudeCodeAPI) {
    this.config = this.loadConfiguration();
    this.client = new ShieldClient(this.config.shieldPort);
    this.widget = new ShieldWidget(api);
    
    this.setupEventHandlers();
    this.registerCommands();
  }

  async activate(): Promise<void> {
    console.log('KindlyGuard extension activating...');
    
    this.widget.initialize();
    
    if (this.config.autoConnect) {
      await this.connect();
    }
    
    this.isActive = true;
  }

  async deactivate(): Promise<void> {
    console.log('KindlyGuard extension deactivating...');
    
    this.client.disconnect();
    this.widget.dispose();
    this.isActive = false;
  }

  private async connect(): Promise<void> {
    try {
      await this.client.connect();
      console.log('Connected to KindlyGuard shield');
    } catch (error) {
      console.error('Failed to connect to shield:', error);
      
      // Show notification about connection failure
      this.api.showNotification(
        'Failed to connect to KindlyGuard shield. Make sure the shield app is running.',
        { type: 'warning' }
      );
    }
  }

  private setupEventHandlers(): void {
    // Handle shield client events
    this.client.on('connected', () => {
      this.widget.show();
      this.api.showNotification('Connected to KindlyGuard shield', { 
        type: 'info',
        duration: 2000 
      });
    });

    this.client.on('disconnected', () => {
      this.widget.updateStatus({
        connected: false,
        mode: 'passive',
        stats: { threatsBlocked: 0, requestsScanned: 0, activeSince: '' }
      });
    });

    this.client.on('status', (status: ShieldStatus) => {
      this.widget.updateStatus(status);
    });

    this.client.on('threat', (threat: Threat) => {
      this.handleThreat(threat);
    });

    this.client.on('error', (error: Error) => {
      console.error('Shield client error:', error);
    });
  }

  private registerCommands(): void {
    // Toggle shield visibility
    this.api.registerCommand('kindlyguard.toggleShield', () => {
      if (this.client.isConnected()) {
        this.widget.hide();
        this.client.disconnect();
      } else {
        this.connect();
      }
    });

    // Show security details
    this.api.registerCommand('kindlyguard.showDetails', () => {
      this.showSecurityDetails();
    });
  }

  private handleThreat(threat: Threat): void {
    // Check notification settings
    const shouldNotify = this.shouldNotifyForThreat(threat);
    
    if (shouldNotify) {
      this.widget.addThreat(threat);
    }
    
    // Log threat for debugging
    console.log('Threat detected:', threat);
  }

  private shouldNotifyForThreat(threat: Threat): boolean {
    switch (this.config.notificationLevel) {
      case 'all':
        return true;
      case 'threats':
        return threat.severity !== 'low';
      case 'critical':
        return threat.severity === 'critical';
      default:
        return true;
    }
  }

  private showSecurityDetails(): void {
    // This would open a detailed security panel in Claude Code
    console.log('Opening security details panel...');
    
    // For now, show a notification
    this.api.showNotification(
      'Security details panel coming soon!',
      { type: 'info' }
    );
  }

  private loadConfiguration(): ShieldConfig {
    // In a real implementation, this would load from Claude Code's settings
    return {
      autoConnect: true,
      notificationLevel: 'threats',
      shieldPort: 9955
    };
  }
}

// Extension entry point
export function activate(api: ClaudeCodeAPI): KindlyGuardExtension {
  const extension = new KindlyGuardExtension(api);
  extension.activate();
  return extension;
}

export function deactivate(extension: KindlyGuardExtension): void {
  extension.deactivate();
}