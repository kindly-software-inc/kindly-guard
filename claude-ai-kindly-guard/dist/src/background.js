// Background service worker for KindlyGuard extension
// Manages WebSocket connection to local shield app

class ShieldConnection {
  constructor() {
    this.ws = null;
    this.reconnectTimer = null;
    this.connectionState = 'disconnected';
    this.reconnectDelay = 1000;
    this.maxReconnectDelay = 30000;
  }

  connect() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    try {
      // Connect to local KindlyGuard shield app
      this.ws = new WebSocket('ws://localhost:7890/shield');
      
      this.ws.onopen = () => {
        console.log('Connected to KindlyGuard shield');
        this.connectionState = 'connected';
        this.reconnectDelay = 1000;
        
        // Notify all tabs
        chrome.tabs.query({ url: 'https://claude.ai/*' }, (tabs) => {
          tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, {
              type: 'CONNECTION_STATUS',
              status: 'connected'
            });
          });
        });
      };

      this.ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        
        // Forward shield data to content scripts
        chrome.tabs.query({ url: 'https://claude.ai/*' }, (tabs) => {
          tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, {
              type: 'SHIELD_UPDATE',
              data: data
            });
          });
        });
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.connectionState = 'error';
      };

      this.ws.onclose = () => {
        console.log('Disconnected from KindlyGuard shield');
        this.connectionState = 'disconnected';
        
        // Notify tabs
        chrome.tabs.query({ url: 'https://claude.ai/*' }, (tabs) => {
          tabs.forEach(tab => {
            chrome.tabs.sendMessage(tab.id, {
              type: 'CONNECTION_STATUS',
              status: 'disconnected'
            });
          });
        });
        
        // Attempt reconnection
        this.scheduleReconnect();
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
      this.scheduleReconnect();
    }
  }

  scheduleReconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    
    this.reconnectTimer = setTimeout(() => {
      console.log('Attempting to reconnect...');
      this.connect();
      
      // Exponential backoff
      this.reconnectDelay = Math.min(
        this.reconnectDelay * 2,
        this.maxReconnectDelay
      );
    }, this.reconnectDelay);
  }

  disconnect() {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  sendMessage(message) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  }
}

// Initialize connection
const shieldConnection = new ShieldConnection();

// Connect when extension starts
chrome.runtime.onInstalled.addListener(() => {
  shieldConnection.connect();
});

// Connect when browser starts
chrome.runtime.onStartup.addListener(() => {
  shieldConnection.connect();
});

// Handle messages from content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'SCAN_TEXT':
      // Forward to shield app for scanning
      shieldConnection.sendMessage({
        type: 'scan',
        text: request.text,
        tabId: sender.tab.id
      });
      break;
      
    case 'GET_CONNECTION_STATUS':
      sendResponse({
        status: shieldConnection.connectionState
      });
      break;
      
    case 'RECONNECT':
      shieldConnection.connect();
      break;
  }
  
  return true; // Keep message channel open
});

// Keep service worker alive
chrome.alarms.create('keepAlive', { periodInMinutes: 0.25 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'keepAlive') {
    // Ensure connection is maintained
    if (shieldConnection.connectionState !== 'connected') {
      shieldConnection.connect();
    }
  }
});