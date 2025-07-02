#!/bin/bash

# KindlyGuard Ecosystem Shutdown Script
# Stops all running components cleanly

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to stop a process by PID file
stop_by_pidfile() {
    local pidfile="$1"
    local name="$2"
    
    if [ -f "$pidfile" ]; then
        PID=$(cat "$pidfile")
        if kill -0 $PID 2>/dev/null; then
            print_info "Stopping $name (PID: $PID)..."
            kill -TERM $PID
            
            # Wait for graceful shutdown
            local count=0
            while kill -0 $PID 2>/dev/null && [ $count -lt 10 ]; do
                sleep 1
                count=$((count + 1))
            done
            
            # Force kill if still running
            if kill -0 $PID 2>/dev/null; then
                print_warning "Force stopping $name..."
                kill -KILL $PID
            fi
            
            print_status "$name stopped"
        else
            print_info "$name not running (stale PID file)"
        fi
        rm -f "$pidfile"
    else
        print_info "No PID file for $name"
    fi
}

# Function to stop processes by name pattern
stop_by_pattern() {
    local pattern="$1"
    local name="$2"
    
    PIDS=$(pgrep -f "$pattern" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        print_info "Found $name processes: $PIDS"
        for PID in $PIDS; do
            print_info "Stopping $name (PID: $PID)..."
            kill -TERM $PID 2>/dev/null || true
        done
        
        # Wait for processes to stop
        sleep 2
        
        # Force kill any remaining
        REMAINING=$(pgrep -f "$pattern" 2>/dev/null)
        if [ -n "$REMAINING" ]; then
            print_warning "Force stopping remaining $name processes..."
            for PID in $REMAINING; do
                kill -KILL $PID 2>/dev/null || true
            done
        fi
        
        print_status "All $name processes stopped"
    else
        print_info "No $name processes found"
    fi
}

print_info "Stopping KindlyGuard ecosystem..."
echo

# Stop Shield first (it depends on server)
print_info "Stopping KindlyGuard Shield..."
stop_by_pidfile ".kindly-guard-shield.pid" "KindlyGuard Shield"
stop_by_pattern "kindly-guard-shield" "Shield"

# Stop any development shield processes
stop_by_pattern "npm.*tauri dev" "Shield Development"

# Kill any processes on Shield port
if command -v lsof >/dev/null 2>&1; then
    SHIELD_PORT_PID=$(lsof -ti:9100 2>/dev/null)
    if [ -n "$SHIELD_PORT_PID" ]; then
        print_info "Stopping process on port 9100 (PID: $SHIELD_PORT_PID)..."
        kill -TERM $SHIELD_PORT_PID 2>/dev/null || true
    fi
fi

echo

# Stop Server
print_info "Stopping KindlyGuard Server..."
stop_by_pidfile ".kindly-guard-server.pid" "KindlyGuard Server"
stop_by_pattern "kindly-guard.*--stdio" "Server"

# Stop any development server processes
stop_by_pattern "cargo.*run.*kindly-guard-server" "Server Development"

echo

# Stop Monitor/CLI
print_info "Stopping any monitor processes..."
stop_by_pattern "kindly-guard-cli.*monitor" "Monitor"

echo

# Clean up any remaining processes
print_info "Cleaning up any remaining processes..."
stop_by_pattern "kindly-guard" "KindlyGuard"

# Clean up log files if they're too large
for logfile in kindly-guard.log kindly-guard-shield.log kindly-guard-dev.log kindly-guard-shield-dev.log; do
    if [ -f "$logfile" ] && [ $(stat -f%z "$logfile" 2>/dev/null || stat -c%s "$logfile" 2>/dev/null) -gt 10485760 ]; then
        print_info "Rotating large log file: $logfile"
        mv "$logfile" "$logfile.old"
    fi
done

# Remove PID files
rm -f .kindly-guard-server.pid .kindly-guard-shield.pid

echo
print_status "KindlyGuard ecosystem stopped"
print_info "Run ./status.sh to verify all components are stopped"