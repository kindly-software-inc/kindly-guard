#!/bin/bash

# KindlyGuard Ecosystem Status Script
# Shows the current status of all components

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
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

print_header() {
    echo -e "${CYAN}=== $1 ===${NC}"
}

# Function to check if a process is running
check_process() {
    local pattern="$1"
    local name="$2"
    
    PIDS=$(pgrep -f "$pattern" 2>/dev/null)
    if [ -n "$PIDS" ]; then
        echo -e "${GREEN}● Running${NC} - $name"
        for PID in $PIDS; do
            # Get process details
            if command -v ps >/dev/null 2>&1; then
                DETAILS=$(ps -p $PID -o comm=,etime= 2>/dev/null | tail -1)
                if [ -n "$DETAILS" ]; then
                    echo "    PID: $PID, Uptime: $(echo $DETAILS | awk '{print $2}')"
                else
                    echo "    PID: $PID"
                fi
            else
                echo "    PID: $PID"
            fi
        done
        return 0
    else
        echo -e "${RED}● Stopped${NC} - $name"
        return 1
    fi
}

# Function to check port
check_port() {
    local port="$1"
    local service="$2"
    
    if command -v lsof >/dev/null 2>&1; then
        if lsof -i:$port >/dev/null 2>&1; then
            echo -e "    Port $port: ${GREEN}Open${NC} ($service)"
            return 0
        else
            echo -e "    Port $port: ${RED}Closed${NC} ($service)"
            return 1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -an | grep -q ":$port.*LISTEN"; then
            echo -e "    Port $port: ${GREEN}Open${NC} ($service)"
            return 0
        else
            echo -e "    Port $port: ${RED}Closed${NC} ($service)"
            return 1
        fi
    fi
    return 2
}

# Function to check file size
format_size() {
    local size=$1
    if [ $size -ge 1048576 ]; then
        echo "$((size / 1048576))MB"
    elif [ $size -ge 1024 ]; then
        echo "$((size / 1024))KB"
    else
        echo "${size}B"
    fi
}

# Header
echo
print_header "KindlyGuard Ecosystem Status"
echo "Time: $(date)"
echo

# Check Server
print_header "Server Status"
SERVER_RUNNING=false
if check_process "kindly-guard.*--stdio" "KindlyGuard Server"; then
    SERVER_RUNNING=true
    
    # Check for PID file
    if [ -f ".kindly-guard-server.pid" ]; then
        echo "    PID file: Found"
    else
        echo "    PID file: Missing"
    fi
    
    # Check log file
    if [ -f "kindly-guard.log" ]; then
        SIZE=$(stat -f%z "kindly-guard.log" 2>/dev/null || stat -c%s "kindly-guard.log" 2>/dev/null)
        echo "    Log file: $(format_size $SIZE)"
        
        # Show last few error lines if any
        ERRORS=$(grep -i "error" kindly-guard.log | tail -3 2>/dev/null)
        if [ -n "$ERRORS" ]; then
            echo "    Recent errors:"
            echo "$ERRORS" | while IFS= read -r line; do
                echo "      $line"
            done
        fi
    fi
fi

# Check development server
if check_process "cargo.*run.*kindly-guard-server" "Development Server"; then
    SERVER_RUNNING=true
fi

echo

# Check Shield
print_header "Shield Status"
SHIELD_RUNNING=false
if check_process "kindly-guard-shield" "KindlyGuard Shield"; then
    SHIELD_RUNNING=true
    
    # Check for PID file
    if [ -f ".kindly-guard-shield.pid" ]; then
        echo "    PID file: Found"
    else
        echo "    PID file: Missing"
    fi
    
    # Check WebSocket port
    check_port 9100 "WebSocket"
    
    # Check log file
    if [ -f "kindly-guard-shield.log" ]; then
        SIZE=$(stat -f%z "kindly-guard-shield.log" 2>/dev/null || stat -c%s "kindly-guard-shield.log" 2>/dev/null)
        echo "    Log file: $(format_size $SIZE)"
    fi
fi

# Check development shield
if check_process "npm.*tauri dev" "Development Shield"; then
    SHIELD_RUNNING=true
    check_port 1420 "Vite Dev Server"
fi

echo

# Check Monitor
print_header "Monitor Status"
check_process "kindly-guard-cli.*monitor" "KindlyGuard Monitor"

echo

# System Resources
print_header "System Resources"

# Memory usage
if command -v free >/dev/null 2>&1; then
    MEM_INFO=$(free -h | grep "^Mem:" | awk '{print "Total: " $2 ", Used: " $3 ", Free: " $4}')
    echo "Memory: $MEM_INFO"
elif command -v vm_stat >/dev/null 2>&1; then
    # macOS
    echo "Memory: Check Activity Monitor for details"
fi

# CPU load
if command -v uptime >/dev/null 2>&1; then
    LOAD=$(uptime | awk -F'load average:' '{print $2}')
    echo "Load average:$LOAD"
fi

echo

# Overall Status
print_header "Overall Status"

if [ "$SERVER_RUNNING" = true ] && [ "$SHIELD_RUNNING" = true ]; then
    print_status "All core components are running"
    echo
    print_info "Quick commands:"
    print_info "  View server logs: tail -f kindly-guard.log"
    print_info "  View shield logs: tail -f kindly-guard-shield.log"
    print_info "  Test a threat: ./demo/test_unicode_threat.py"
    print_info "  Stop all: ./stop-all.sh"
elif [ "$SERVER_RUNNING" = true ] || [ "$SHIELD_RUNNING" = true ]; then
    print_warning "Some components are not running"
    echo
    print_info "To start all components: ./start-all.sh"
    print_info "To start in dev mode: ./start-dev.sh"
else
    print_error "No components are running"
    echo
    print_info "To start all components: ./start-all.sh"
    print_info "To start in dev mode: ./start-dev.sh"
fi

# Check for common issues
echo
print_header "Health Checks"

# Check if binaries exist
if [ -f "target/release/kindly-guard" ]; then
    echo -e "Server binary: ${GREEN}Found${NC}"
else
    echo -e "Server binary: ${YELLOW}Not built${NC} (run: cargo build --release)"
fi

if [ -f "kindly-guard-shield/src-tauri/target/release/kindly-guard-shield" ]; then
    echo -e "Shield binary: ${GREEN}Found${NC}"
else
    echo -e "Shield binary: ${YELLOW}Not built${NC} (run: cd kindly-guard-shield && npm run tauri build)"
fi

# Check for config files
if [ -f "kindly-guard.toml" ]; then
    echo -e "Config file: ${GREEN}Found${NC}"
elif [ -f "kindly-guard.toml.example" ]; then
    echo -e "Config file: ${YELLOW}Using defaults${NC} (copy kindly-guard.toml.example to kindly-guard.toml to customize)"
else
    echo -e "Config file: ${RED}Missing${NC}"
fi

echo