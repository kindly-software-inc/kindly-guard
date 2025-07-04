#!/bin/bash
# KindlyGuard systemd service installation script
# Run with sudo: sudo ./install.sh

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
SERVICE_NAME="kindly-guard"
SERVICE_USER="kindlyguard"
BINARY_PATH="/usr/local/bin/kindly-guard"
CONFIG_DIR="/etc/kindly-guard"
DATA_DIR="/var/lib/kindly-guard"
LOG_DIR="/var/log/kindly-guard"

# Functions
print_step() {
    echo -e "${GREEN}[+]${NC} $1"
}

print_error() {
    echo -e "${RED}[!]${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}[*]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

create_user() {
    print_step "Creating service user..."
    if id "$SERVICE_USER" &>/dev/null; then
        print_warning "User $SERVICE_USER already exists"
    else
        useradd --system --no-create-home --shell /bin/false "$SERVICE_USER"
        print_step "Created user: $SERVICE_USER"
    fi
}

create_directories() {
    print_step "Creating directories..."
    
    # Create directories with proper permissions
    directories=("$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR")
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chown "$SERVICE_USER:$SERVICE_USER" "$dir"
            chmod 750 "$dir"
            print_step "Created directory: $dir"
        else
            print_warning "Directory already exists: $dir"
            chown "$SERVICE_USER:$SERVICE_USER" "$dir"
            chmod 750 "$dir"
        fi
    done
}

install_binary() {
    print_step "Installing binary..."
    
    # Check if binary exists in current directory or build it
    if [[ -f "../../target/release/kindly-guard" ]]; then
        cp "../../target/release/kindly-guard" "$BINARY_PATH"
    elif [[ -f "../../target/secure/kindly-guard" ]]; then
        cp "../../target/secure/kindly-guard" "$BINARY_PATH"
    else
        print_error "Binary not found. Please build the project first:"
        print_error "  cd ../.. && cargo build --profile=secure"
        exit 1
    fi
    
    chown root:root "$BINARY_PATH"
    chmod 755 "$BINARY_PATH"
    print_step "Installed binary: $BINARY_PATH"
}

install_config() {
    print_step "Installing configuration..."
    
    if [[ ! -f "$CONFIG_DIR/config.toml" ]]; then
        if [[ -f "../../config/production.toml" ]]; then
            cp "../../config/production.toml" "$CONFIG_DIR/config.toml"
        elif [[ -f "../../config/production.toml.example" ]]; then
            cp "../../config/production.toml.example" "$CONFIG_DIR/config.toml"
        else
            print_warning "No configuration file found, creating minimal config..."
            cat > "$CONFIG_DIR/config.toml" <<EOF
# KindlyGuard Production Configuration

[server]
host = "127.0.0.1"
port = 3000
max_connections = 1000

[scanner]
unicode_detection = true
injection_detection = true
path_traversal_detection = true
xss_detection = true
enhanced_mode = false
max_scan_depth = 10
max_content_size = 10485760  # 10MB

[shield]
enabled = false  # Disable TUI in production
update_interval_ms = 1000

[auth]
enabled = true
trusted_issuers = []

[rate_limit]
enabled = true
default_rpm = 120
default_burst = 20

[logging]
level = "info"
format = "json"
EOF
        fi
        
        chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/config.toml"
        chmod 640 "$CONFIG_DIR/config.toml"
        print_step "Installed configuration: $CONFIG_DIR/config.toml"
    else
        print_warning "Configuration already exists: $CONFIG_DIR/config.toml"
    fi
    
    # Create environment file
    if [[ ! -f "$CONFIG_DIR/environment" ]]; then
        cat > "$CONFIG_DIR/environment" <<EOF
# KindlyGuard environment variables
# KINDLY_GUARD__SERVER__HOST=0.0.0.0
# KINDLY_GUARD__SERVER__PORT=3000
EOF
        chmod 640 "$CONFIG_DIR/environment"
        chown "$SERVICE_USER:$SERVICE_USER" "$CONFIG_DIR/environment"
    fi
}

install_service() {
    print_step "Installing systemd service..."
    
    cp kindly-guard.service /etc/systemd/system/
    systemctl daemon-reload
    print_step "Installed service: $SERVICE_NAME"
}

setup_logging() {
    print_step "Setting up log rotation..."
    
    cat > /etc/logrotate.d/kindly-guard <<EOF
$LOG_DIR/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 $SERVICE_USER $SERVICE_USER
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME >/dev/null 2>&1 || true
    endscript
}
EOF
    
    print_step "Configured log rotation"
}

validate_installation() {
    print_step "Validating installation..."
    
    # Check binary
    if [[ ! -x "$BINARY_PATH" ]]; then
        print_error "Binary not executable: $BINARY_PATH"
        return 1
    fi
    
    # Validate configuration
    if ! sudo -u "$SERVICE_USER" "$BINARY_PATH" config validate --config "$CONFIG_DIR/config.toml" &>/dev/null; then
        print_error "Configuration validation failed"
        return 1
    fi
    
    print_step "Installation validated successfully"
}

print_completion() {
    echo
    echo "============================================"
    echo -e "${GREEN}Installation completed successfully!${NC}"
    echo "============================================"
    echo
    echo "Next steps:"
    echo "  1. Review and edit the configuration:"
    echo "     nano $CONFIG_DIR/config.toml"
    echo
    echo "  2. Start the service:"
    echo "     systemctl start $SERVICE_NAME"
    echo
    echo "  3. Enable automatic startup:"
    echo "     systemctl enable $SERVICE_NAME"
    echo
    echo "  4. Check service status:"
    echo "     systemctl status $SERVICE_NAME"
    echo
    echo "  5. View logs:"
    echo "     journalctl -u $SERVICE_NAME -f"
    echo
}

# Main installation
main() {
    print_step "Starting KindlyGuard installation..."
    
    check_root
    create_user
    create_directories
    install_binary
    install_config
    install_service
    setup_logging
    
    if validate_installation; then
        print_completion
    else
        print_error "Installation validation failed"
        exit 1
    fi
}

# Run main function
main