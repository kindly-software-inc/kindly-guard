// Popup script for KindlyGuard extension

document.addEventListener('DOMContentLoaded', () => {
  // Get elements
  const elements = {
    shieldStatus: document.getElementById('shield-status'),
    protectionMode: document.getElementById('protection-mode'),
    statScanned: document.getElementById('stat-scanned'),
    statBlocked: document.getElementById('stat-blocked'),
    autoScan: document.getElementById('auto-scan'),
    showNotifications: document.getElementById('show-notifications'),
    openShield: document.getElementById('open-shield'),
    viewLogs: document.getElementById('view-logs'),
    helpLink: document.getElementById('help-link'),
    aboutLink: document.getElementById('about-link')
  };
  
  // Load settings
  chrome.storage.local.get(['autoScan', 'showNotifications'], (result) => {
    elements.autoScan.checked = result.autoScan !== false;
    elements.showNotifications.checked = result.showNotifications === true;
  });
  
  // Update status
  function updateStatus() {
    chrome.runtime.sendMessage({ type: 'GET_CONNECTION_STATUS' }, (response) => {
      if (response && response.status === 'connected') {
        elements.shieldStatus.textContent = 'Connected';
        elements.shieldStatus.className = 'status-value';
      } else {
        elements.shieldStatus.textContent = 'Disconnected';
        elements.shieldStatus.className = 'status-value disconnected';
      }
    });
    
    // Get stats from active tab
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0] && tabs[0].url.includes('claude.ai')) {
        chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_STATS' }, (response) => {
          if (response) {
            elements.statScanned.textContent = response.scanned || 0;
            elements.statBlocked.textContent = response.blocked || 0;
            elements.protectionMode.textContent = 
              response.mode === 'enhanced' ? 'Enhanced' : 'Standard';
          }
        });
      }
    });
  }
  
  // Initial update
  updateStatus();
  
  // Update every second
  setInterval(updateStatus, 1000);
  
  // Save settings
  elements.autoScan.addEventListener('change', () => {
    chrome.storage.local.set({ autoScan: elements.autoScan.checked });
  });
  
  elements.showNotifications.addEventListener('change', () => {
    chrome.storage.local.set({ showNotifications: elements.showNotifications.checked });
  });
  
  // Action buttons
  elements.openShield.addEventListener('click', () => {
    // Try to open the shield app
    chrome.tabs.create({ url: 'http://localhost:7890' });
  });
  
  elements.viewLogs.addEventListener('click', () => {
    chrome.tabs.create({ url: 'chrome://extensions/?id=' + chrome.runtime.id });
  });
  
  // Links
  elements.helpLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'https://github.com/kindlyguard/extension/wiki' });
  });
  
  elements.aboutLink.addEventListener('click', (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: 'https://github.com/kindlyguard/extension' });
  });
});