#!/bin/bash
#
# KindlyGuard systemd uninstallation script
# This script removes KindlyGuard system service
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo -e "${GREEN}Running as root, uninstalling system-wide service${NC}"
   SYSTEM_UNINSTALL=true
else
   echo -e "${YELLOW}Not running as root, uninstalling user service${NC}"
   SYSTEM_UNINSTALL=false
fi

if $SYSTEM_UNINSTALL; then
    # System paths
    BINARY_PATH="/usr/local/bin/kindly-guard"
    CONFIG_DIR="/etc/kindly-guard"
    LOG_DIR="/var/log/kindly-guard"
    DATA_DIR="/var/lib/kindly-guard"
    SERVICE_FILE="/etc/systemd/system/kindly-guard.service"
    SOCKET_FILE="/etc/systemd/system/kindly-guard.socket"
else
    # User paths
    BINARY_PATH="$HOME/.local/bin/kindly-guard"
    CONFIG_DIR="$HOME/.config/kindly-guard"
    SERVICE_FILE="$HOME/.config/systemd/user/kindly-guard.service"
fi

echo "Uninstalling KindlyGuard..."

# Stop and disable service
if $SYSTEM_UNINSTALL; then
    if systemctl is-active --quiet kindly-guard; then
        echo -e "${YELLOW}Stopping kindly-guard service...${NC}"
        systemctl stop kindly-guard
    fi
    
    if systemctl is-enabled --quiet kindly-guard 2>/dev/null; then
        echo -e "${YELLOW}Disabling kindly-guard service...${NC}"
        systemctl disable kindly-guard
    fi
    
    if [ -f "$SOCKET_FILE" ]; then
        if systemctl is-active --quiet kindly-guard.socket; then
            systemctl stop kindly-guard.socket
        fi
        if systemctl is-enabled --quiet kindly-guard.socket 2>/dev/null; then
            systemctl disable kindly-guard.socket
        fi
    fi
else
    if systemctl --user is-active --quiet kindly-guard; then
        echo -e "${YELLOW}Stopping kindly-guard service...${NC}"
        systemctl --user stop kindly-guard
    fi
    
    if systemctl --user is-enabled --quiet kindly-guard 2>/dev/null; then
        echo -e "${YELLOW}Disabling kindly-guard service...${NC}"
        systemctl --user disable kindly-guard
    fi
fi

# Remove service files
echo -e "${GREEN}Removing service files...${NC}"
[ -f "$SERVICE_FILE" ] && rm -f "$SERVICE_FILE"
[ -f "$SOCKET_FILE" ] && rm -f "$SOCKET_FILE"

# Reload systemd
if $SYSTEM_UNINSTALL; then
    systemctl daemon-reload
else
    systemctl --user daemon-reload
fi

# Remove binary
if [ -f "$BINARY_PATH" ]; then
    echo -e "${GREEN}Removing binary...${NC}"
    rm -f "$BINARY_PATH"
fi

# Ask about config and data
echo ""
read -p "Remove configuration files? (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}Removing configuration...${NC}"
    rm -rf "$CONFIG_DIR"
    
    if $SYSTEM_UNINSTALL; then
        [ -d "$LOG_DIR" ] && rm -rf "$LOG_DIR"
        [ -d "$DATA_DIR" ] && rm -rf "$DATA_DIR"
    fi
else
    echo -e "${GREEN}Configuration preserved at: $CONFIG_DIR${NC}"
fi

# Remove user (system install only)
if $SYSTEM_UNINSTALL; then
    if id -u kindlyguard &>/dev/null; then
        echo ""
        read -p "Remove kindlyguard system user? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}Removing kindlyguard user...${NC}"
            userdel kindlyguard
        fi
    fi
fi

echo ""
echo -e "${GREEN}Uninstallation complete!${NC}"