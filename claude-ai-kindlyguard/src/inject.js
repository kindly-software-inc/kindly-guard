// Injected script for deeper Claude.ai integration
// This script runs in the page context and can intercept API calls

(function() {
  'use strict';
  
  // Create a custom event bridge for communication
  const eventBridge = {
    send: (type, data) => {
      window.dispatchEvent(new CustomEvent('kindlyguard-event', {
        detail: { type, data }
      }));
    }
  };
  
  // Intercept fetch requests to monitor Claude API calls
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const [url, options] = args;
    
    // Check if this is a Claude API call
    if (typeof url === 'string' && url.includes('/api/')) {
      // Extract request body for scanning
      if (options?.body) {
        try {
          let body;
          if (typeof options.body === 'string') {
            body = options.body;
          } else if (options.body instanceof FormData) {
            // Handle FormData
            body = Array.from(options.body.entries())
              .map(([k, v]) => `${k}: ${v}`)
              .join('\n');
          }
          
          if (body) {
            eventBridge.send('API_REQUEST', {
              url: url,
              method: options.method || 'GET',
              body: body
            });
          }
        } catch (error) {
          console.error('KindlyGuard: Error parsing request:', error);
        }
      }
    }
    
    // Call original fetch
    const response = await originalFetch.apply(this, args);
    
    // Monitor responses
    if (url.includes('/api/') && response.ok) {
      try {
        // Clone response to read it without consuming
        const cloned = response.clone();
        const data = await cloned.json();
        
        eventBridge.send('API_RESPONSE', {
          url: url,
          status: response.status,
          data: data
        });
      } catch (error) {
        // Ignore parsing errors
      }
    }
    
    return response;
  };
  
  // Monitor WebSocket connections (if Claude uses them)
  const OriginalWebSocket = window.WebSocket;
  window.WebSocket = function(...args) {
    const ws = new OriginalWebSocket(...args);
    
    // Monitor messages
    const originalSend = ws.send;
    ws.send = function(data) {
      eventBridge.send('WS_MESSAGE', {
        type: 'outgoing',
        data: data
      });
      return originalSend.apply(this, arguments);
    };
    
    ws.addEventListener('message', (event) => {
      eventBridge.send('WS_MESSAGE', {
        type: 'incoming',
        data: event.data
      });
    });
    
    return ws;
  };
  
  // Monitor clipboard operations
  document.addEventListener('paste', (event) => {
    const text = event.clipboardData?.getData('text/plain');
    if (text) {
      eventBridge.send('CLIPBOARD_PASTE', {
        text: text,
        timestamp: Date.now()
      });
    }
  });
  
  // Monitor file uploads
  document.addEventListener('change', (event) => {
    if (event.target instanceof HTMLInputElement && event.target.type === 'file') {
      const files = Array.from(event.target.files || []);
      if (files.length > 0) {
        eventBridge.send('FILE_UPLOAD', {
          files: files.map(f => ({
            name: f.name,
            size: f.size,
            type: f.type
          })),
          timestamp: Date.now()
        });
      }
    }
  });
  
  // Add visual indicators for threat detection
  const addThreatIndicator = (element, threat) => {
    if (!element || element.hasAttribute('data-kg-marked')) return;
    
    element.setAttribute('data-kg-marked', 'true');
    element.style.position = 'relative';
    
    const indicator = document.createElement('div');
    indicator.className = 'kg-threat-indicator';
    indicator.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
        <path d="M8 1L1 14H15L8 1Z" fill="#DC2626" stroke="#DC2626"/>
        <path d="M8 6V9M8 11V11.5" stroke="white" stroke-width="1.5" stroke-linecap="round"/>
      </svg>
      <span class="kg-threat-tooltip">${threat}</span>
    `;
    
    // Style the indicator
    const style = document.createElement('style');
    style.textContent = `
      .kg-threat-indicator {
        position: absolute;
        top: -8px;
        right: -8px;
        z-index: 1000;
        cursor: help;
      }
      .kg-threat-tooltip {
        position: absolute;
        bottom: 100%;
        right: 0;
        background: #1F2937;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 12px;
        white-space: nowrap;
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.2s;
        margin-bottom: 4px;
      }
      .kg-threat-indicator:hover .kg-threat-tooltip {
        opacity: 1;
      }
    `;
    
    if (!document.querySelector('#kg-threat-styles')) {
      style.id = 'kg-threat-styles';
      document.head.appendChild(style);
    }
    
    element.appendChild(indicator);
  };
  
  // Listen for threat notifications from content script
  window.addEventListener('kindlyguard-threat', (event) => {
    const { element, threat } = event.detail;
    if (element) {
      addThreatIndicator(element, threat);
    }
  });
  
  // Notify content script that injection is complete
  eventBridge.send('INJECT_READY', {
    version: '1.0.0',
    features: ['fetch', 'websocket', 'clipboard', 'files']
  });
})();