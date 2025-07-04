// Content script for Claude.ai integration
// Injects KindlyGuard shield widget into the interface

class KindlyGuardShield {
  constructor() {
    this.shieldElement = null;
    this.isExpanded = false;
    this.connectionStatus = 'disconnected';
    this.shieldData = {
      status: 'idle',
      mode: 'standard',
      stats: {
        scanned: 0,
        blocked: 0,
        threats: []
      }
    };
    
    this.init();
  }

  init() {
    // Wait for Claude.ai to load
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', () => this.injectShield());
    } else {
      this.injectShield();
    }
    
    // Listen for messages from background
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      if (message.type === 'GET_STATS') {
        sendResponse({
          scanned: this.shieldData.stats.scanned,
          blocked: this.shieldData.stats.blocked,
          mode: this.shieldData.mode
        });
        return true;
      }
      this.handleMessage(message);
    });
    
    // Get initial connection status
    chrome.runtime.sendMessage({ type: 'GET_CONNECTION_STATUS' }, (response) => {
      if (response) {
        this.connectionStatus = response.status;
        this.updateShieldDisplay();
      }
    });
    
    // Monitor for text input
    this.setupTextMonitoring();
  }

  injectShield() {
    // Create shield container
    this.shieldElement = document.createElement('div');
    this.shieldElement.id = 'kindlyguard-shield';
    this.shieldElement.className = 'kg-shield';
    this.shieldElement.innerHTML = this.getShieldHTML();
    
    // Inject into page
    document.body.appendChild(this.shieldElement);
    
    // Setup event listeners
    this.setupEventListeners();
    
    // Apply initial state
    this.updateShieldDisplay();
  }

  getShieldHTML() {
    return `
      <div class="kg-shield-container">
        <div class="kg-shield-header" id="kg-shield-header">
          <div class="kg-shield-icon">
            <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
              <path d="M12 2L4 7V12C4 16.5 6.84 20.74 11 21.92C11.35 22.02 11.66 22.02 12 21.92C16.16 20.74 20 16.5 20 12V7L12 2Z" 
                    fill="currentColor" stroke="currentColor" stroke-width="1.5"/>
              <path d="M9 12L11 14L15 10" stroke="white" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>
          <div class="kg-shield-status">
            <div class="kg-status-text">KindlyGuard</div>
            <div class="kg-status-indicator"></div>
          </div>
        </div>
        
        <div class="kg-shield-body" id="kg-shield-body">
          <div class="kg-stats">
            <div class="kg-stat">
              <span class="kg-stat-value" id="kg-scanned">0</span>
              <span class="kg-stat-label">Scanned</span>
            </div>
            <div class="kg-stat">
              <span class="kg-stat-value" id="kg-blocked">0</span>
              <span class="kg-stat-label">Blocked</span>
            </div>
          </div>
          
          <div class="kg-mode" id="kg-mode">
            <span class="kg-mode-label">Mode:</span>
            <span class="kg-mode-value">Standard</span>
          </div>
          
          <div class="kg-threats" id="kg-threats">
            <div class="kg-threats-header">Recent Threats</div>
            <div class="kg-threats-list" id="kg-threats-list">
              <div class="kg-no-threats">No threats detected</div>
            </div>
          </div>
          
          <div class="kg-actions">
            <button class="kg-action-btn" id="kg-reconnect">
              Reconnect
            </button>
          </div>
        </div>
      </div>
    `;
  }

  setupEventListeners() {
    // Toggle expanded state
    const header = document.getElementById('kg-shield-header');
    header.addEventListener('click', () => {
      this.isExpanded = !this.isExpanded;
      this.shieldElement.classList.toggle('kg-expanded', this.isExpanded);
    });
    
    // Reconnect button
    const reconnectBtn = document.getElementById('kg-reconnect');
    reconnectBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      chrome.runtime.sendMessage({ type: 'RECONNECT' });
    });
  }

  setupTextMonitoring() {
    // Monitor Claude's text input
    const observer = new MutationObserver(() => {
      const textareas = document.querySelectorAll('textarea, [contenteditable="true"]');
      textareas.forEach(textarea => {
        if (!textarea.hasAttribute('data-kg-monitored')) {
          textarea.setAttribute('data-kg-monitored', 'true');
          
          // Debounced text scanning
          let scanTimer;
          const scanText = () => {
            const text = textarea.value || textarea.textContent;
            if (text && text.length > 0) {
              chrome.runtime.sendMessage({
                type: 'SCAN_TEXT',
                text: text
              });
            }
          };
          
          textarea.addEventListener('input', () => {
            clearTimeout(scanTimer);
            scanTimer = setTimeout(scanText, 300);
          });
        }
      });
    });
    
    observer.observe(document.body, {
      childList: true,
      subtree: true
    });
  }

  handleMessage(message) {
    switch (message.type) {
      case 'CONNECTION_STATUS':
        this.connectionStatus = message.status;
        this.updateShieldDisplay();
        break;
        
      case 'SHIELD_UPDATE':
        this.shieldData = message.data;
        this.updateShieldDisplay();
        break;
    }
  }

  updateShieldDisplay() {
    if (!this.shieldElement) return;
    
    // Update connection status
    const statusIndicator = this.shieldElement.querySelector('.kg-status-indicator');
    const statusText = this.shieldElement.querySelector('.kg-status-text');
    
    if (this.connectionStatus === 'connected') {
      statusIndicator.className = 'kg-status-indicator kg-connected';
      statusText.textContent = 'Protected';
      this.shieldElement.classList.remove('kg-disconnected');
    } else {
      statusIndicator.className = 'kg-status-indicator kg-disconnected';
      statusText.textContent = 'Disconnected';
      this.shieldElement.classList.add('kg-disconnected');
    }
    
    // Update stats
    document.getElementById('kg-scanned').textContent = 
      this.shieldData.stats.scanned.toLocaleString();
    document.getElementById('kg-blocked').textContent = 
      this.shieldData.stats.blocked.toLocaleString();
    
    // Update mode
    const modeElement = document.querySelector('.kg-mode-value');
    if (modeElement) {
      modeElement.textContent = this.shieldData.mode === 'enhanced' ? 'Enhanced' : 'Standard';
      if (this.shieldData.mode === 'enhanced') {
        this.shieldElement.classList.add('kg-enhanced');
      } else {
        this.shieldElement.classList.remove('kg-enhanced');
      }
    }
    
    // Update threats list
    this.updateThreatsList();
  }

  updateThreatsList() {
    const threatsList = document.getElementById('kg-threats-list');
    if (!threatsList) return;
    
    const threats = this.shieldData.stats.threats || [];
    
    if (threats.length === 0) {
      threatsList.innerHTML = '<div class="kg-no-threats">No threats detected</div>';
    } else {
      threatsList.innerHTML = threats.slice(-5).reverse().map(threat => `
        <div class="kg-threat-item">
          <span class="kg-threat-type">${this.getThreatTypeLabel(threat.type)}</span>
          <span class="kg-threat-time">${this.formatTime(threat.timestamp)}</span>
        </div>
      `).join('');
    }
  }

  getThreatTypeLabel(type) {
    const labels = {
      'unicode': 'Unicode Attack',
      'injection': 'Injection Attempt',
      'xss': 'XSS Pattern',
      'prompt': 'Prompt Injection',
      'encoding': 'Encoding Attack'
    };
    return labels[type] || 'Unknown Threat';
  }

  formatTime(timestamp) {
    if (!timestamp) return 'just now';
    const date = new Date(timestamp);
    const now = new Date();
    const diff = now - date;
    
    if (diff < 60000) return 'just now';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
    return date.toLocaleDateString();
  }
}

// Initialize shield
const shield = new KindlyGuardShield();