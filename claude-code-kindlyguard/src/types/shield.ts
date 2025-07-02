export interface ShieldStatus {
  connected: boolean;
  mode: 'active' | 'passive' | 'learning';
  stats: {
    threatsBlocked: number;
    requestsScanned: number;
    activeSince: string;
  };
}

export interface Threat {
  id: string;
  timestamp: string;
  type: 'unicode' | 'injection' | 'pattern' | 'suspicious';
  severity: 'low' | 'medium' | 'high' | 'critical';
  description: string;
  context?: {
    method?: string;
    params?: any;
    position?: number;
    pattern?: string;
  };
}

export interface ShieldMessage {
  type: 'status' | 'threat' | 'stats' | 'connected' | 'disconnected';
  data: any;
}

export interface ShieldConfig {
  autoConnect: boolean;
  notificationLevel: 'all' | 'threats' | 'critical';
  shieldPort: number;
}