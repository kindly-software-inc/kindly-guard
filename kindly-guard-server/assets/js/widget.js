// KindlyGuard Shield Widget JavaScript

class ShieldWidget {
    constructor() {
        this.widget = document.getElementById('kindly-shield-widget');
        this.isExpanded = false;
        this.isEnhanced = false;
        this.threatCount = 0;
        this.uptime = 0;
        this.threats = [];
        
        this.init();
    }
    
    init() {
        this.setupEventListeners();
        this.startUpdates();
        this.checkEnhancedMode();
    }
    
    setupEventListeners() {
        // Toggle expanded/collapsed state
        const collapsed = this.widget.querySelector('.widget-collapsed');
        const closeBtn = this.widget.querySelector('.widget-close');
        
        collapsed.addEventListener('click', () => this.expand());
        closeBtn.addEventListener('click', () => this.collapse());
        
        // Action buttons
        const dashboardBtn = document.getElementById('open-dashboard');
        const toggleModeBtn = document.getElementById('toggle-mode');
        
        dashboardBtn?.addEventListener('click', () => this.openDashboard());
        toggleModeBtn?.addEventListener('click', () => this.toggleEnhancedMode());
    }
    
    expand() {
        this.isExpanded = true;
        this.widget.classList.add('expanded');
    }
    
    collapse() {
        this.isExpanded = false;
        this.widget.classList.remove('expanded');
    }
    
    toggleEnhancedMode() {
        this.isEnhanced = !this.isEnhanced;
        this.widget.classList.toggle('enhanced');
        this.updateShieldIcon();
        this.updateModeButton();
    }
    
    updateShieldIcon() {
        const icons = this.widget.querySelectorAll('.shield-icon, .shield-icon-large');
        const iconPath = this.isEnhanced ? 
            '../svg/shield-enhanced.svg' : 
            '../svg/shield-standard.svg';
        
        icons.forEach(icon => {
            icon.src = iconPath;
            icon.classList.toggle('shield-enhanced', this.isEnhanced);
            icon.classList.toggle('shield-standard', !this.isEnhanced);
        });
    }
    
    updateModeButton() {
        const btn = document.getElementById('toggle-mode');
        if (btn) {
            btn.textContent = this.isEnhanced ? 'Standard' : 'Enhanced';
        }
    }
    
    checkEnhancedMode() {
        // Check with server for enhanced mode status
        // This would normally be an API call
        fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                if (data.enhanced_mode) {
                    this.isEnhanced = true;
                    this.widget.classList.add('enhanced');
                    this.updateShieldIcon();
                }
            })
            .catch(() => {
                // Fallback for demo
                console.log('Running in demo mode');
            });
    }
    
    startUpdates() {
        // Update uptime
        setInterval(() => {
            this.uptime++;
            this.updateUptime();
        }, 1000);
        
        // Simulate threat detection (for demo)
        this.simulateThreats();
        
        // Update metrics
        setInterval(() => {
            this.updateMetrics();
        }, 2000);
    }
    
    updateUptime() {
        const uptimeEl = document.getElementById('uptime');
        if (uptimeEl) {
            uptimeEl.textContent = this.formatUptime(this.uptime);
        }
    }
    
    formatUptime(seconds) {
        if (seconds < 60) return `${seconds}s`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h`;
        return `${Math.floor(seconds / 86400)}d`;
    }
    
    simulateThreats() {
        const threatTypes = [
            { type: 'Unicode Attack', severity: 'medium' },
            { type: 'SQL Injection', severity: 'high' },
            { type: 'XSS Attempt', severity: 'critical' },
            { type: 'Path Traversal', severity: 'low' },
            { type: 'Command Injection', severity: 'high' }
        ];
        
        setInterval(() => {
            if (Math.random() > 0.7) {
                const threat = threatTypes[Math.floor(Math.random() * threatTypes.length)];
                this.addThreat(threat);
            }
        }, 5000);
    }
    
    addThreat(threat) {
        this.threatCount++;
        this.threats.unshift({
            ...threat,
            timestamp: new Date(),
            id: Date.now()
        });
        
        // Keep only last 10 threats
        if (this.threats.length > 10) {
            this.threats = this.threats.slice(0, 10);
        }
        
        this.updateThreatCounter();
        this.updateThreatFeed();
        this.showThreatNotification(threat);
    }
    
    updateThreatCounter() {
        const counter = this.widget.querySelector('.threat-counter');
        const threatsBlocked = document.getElementById('threats-blocked');
        
        if (counter) {
            counter.textContent = this.threatCount;
            counter.classList.add('active');
        }
        
        if (threatsBlocked) {
            threatsBlocked.textContent = this.threatCount;
        }
    }
    
    updateThreatFeed() {
        const ticker = document.getElementById('threat-ticker');
        if (!ticker) return;
        
        const content = ticker.querySelector('.ticker-content');
        content.innerHTML = '';
        
        if (this.threats.length === 0) {
            content.innerHTML = '<div class="no-threats">No recent threats detected</div>';
            return;
        }
        
        this.threats.forEach(threat => {
            const item = document.createElement('div');
            item.className = 'threat-item';
            item.innerHTML = `
                <span class="threat-type">${threat.type}</span>
                <span class="threat-time">${this.formatTime(threat.timestamp)}</span>
            `;
            content.appendChild(item);
        });
    }
    
    formatTime(date) {
        const now = new Date();
        const diff = Math.floor((now - date) / 1000);
        
        if (diff < 60) return 'just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        return `${Math.floor(diff / 3600)}h ago`;
    }
    
    showThreatNotification(threat) {
        // Flash the shield icon
        const icons = this.widget.querySelectorAll('.shield-icon, .shield-icon-large');
        icons.forEach(icon => {
            icon.classList.add('shield-threat-detected');
            setTimeout(() => {
                icon.classList.remove('shield-threat-detected');
            }, 500);
        });
        
        // Update status indicator
        const indicator = this.widget.querySelector('.status-indicator');
        if (indicator) {
            indicator.classList.add(threat.severity);
            setTimeout(() => {
                indicator.classList.remove(threat.severity);
            }, 2000);
        }
    }
    
    updateMetrics() {
        if (!this.isEnhanced) return;
        
        // Update scan rate
        const scanRate = document.getElementById('scan-rate');
        if (scanRate) {
            const rate = Math.floor(Math.random() * 1000 + 500);
            scanRate.textContent = `${rate}/s`;
        }
        
        // Update performance metrics
        this.updateProgressBar('pattern-recognition', 80, 95);
        this.updateProgressBar('threat-prediction', 85, 98);
        this.updateProgressBar('system-load', 15, 35);
    }
    
    updateProgressBar(className, min, max) {
        const bar = this.widget.querySelector(`.${className}`);
        if (bar) {
            const value = Math.floor(Math.random() * (max - min) + min);
            bar.style.width = `${value}%`;
        }
    }
    
    openDashboard() {
        window.open('/dashboard', '_blank');
    }
}

// Initialize widget when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new ShieldWidget();
});