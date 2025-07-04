#!/bin/bash
# Code signing script for KindlyGuard binaries
# This script handles signing for macOS and Windows binaries

set -euo pipefail

# Configuration
MACOS_IDENTITY="${MACOS_SIGNING_IDENTITY:-}"
WINDOWS_CERT_PATH="${WINDOWS_CERT_PATH:-}"
WINDOWS_CERT_PASSWORD="${WINDOWS_CERT_PASSWORD:-}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Sign macOS binaries
sign_macos() {
    local binary="$1"
    
    if [[ -z "$MACOS_IDENTITY" ]]; then
        log_warn "MACOS_SIGNING_IDENTITY not set, skipping macOS signing"
        return 0
    fi
    
    log_info "Signing macOS binary: $binary"
    
    # Sign the binary
    codesign --force --verify --verbose \
        --sign "$MACOS_IDENTITY" \
        --options runtime \
        --entitlements macos/entitlements.plist \
        --timestamp \
        "$binary"
    
    # Verify the signature
    codesign --verify --verbose "$binary"
    
    log_info "Successfully signed: $binary"
}

# Sign Windows binaries
sign_windows() {
    local binary="$1"
    
    if [[ -z "$WINDOWS_CERT_PATH" ]] || [[ -z "$WINDOWS_CERT_PASSWORD" ]]; then
        log_warn "Windows signing credentials not set, skipping Windows signing"
        return 0
    fi
    
    log_info "Signing Windows binary: $binary"
    
    # Use signtool if available (Windows)
    if command -v signtool &> /dev/null; then
        signtool sign /f "$WINDOWS_CERT_PATH" \
            /p "$WINDOWS_CERT_PASSWORD" \
            /t http://timestamp.digicert.com \
            /fd sha256 \
            "$binary"
    # Use osslsigncode on Linux/macOS for cross-signing
    elif command -v osslsigncode &> /dev/null; then
        osslsigncode sign \
            -pkcs12 "$WINDOWS_CERT_PATH" \
            -pass "$WINDOWS_CERT_PASSWORD" \
            -t http://timestamp.digicert.com \
            -h sha256 \
            -in "$binary" \
            -out "${binary}.signed"
        mv "${binary}.signed" "$binary"
    else
        log_error "No Windows signing tool available (signtool or osslsigncode)"
        return 1
    fi
    
    log_info "Successfully signed: $binary"
}

# Notarize macOS binaries
notarize_macos() {
    local binary="$1"
    local bundle_id="${2:-com.kindlyguard.cli}"
    
    if [[ -z "$MACOS_NOTARIZATION_USER" ]] || [[ -z "$MACOS_NOTARIZATION_PASSWORD" ]]; then
        log_warn "macOS notarization credentials not set, skipping notarization"
        return 0
    fi
    
    log_info "Notarizing macOS binary: $binary"
    
    # Create a zip for notarization
    local zip_file="${binary}.zip"
    zip -j "$zip_file" "$binary"
    
    # Submit for notarization
    local request_uuid=$(xcrun notarytool submit "$zip_file" \
        --apple-id "$MACOS_NOTARIZATION_USER" \
        --password "$MACOS_NOTARIZATION_PASSWORD" \
        --team-id "$MACOS_TEAM_ID" \
        --wait \
        2>&1 | grep "id:" | awk '{print $2}')
    
    # Check notarization status
    xcrun notarytool info "$request_uuid" \
        --apple-id "$MACOS_NOTARIZATION_USER" \
        --password "$MACOS_NOTARIZATION_PASSWORD"
    
    # Staple the notarization ticket
    xcrun stapler staple "$binary"
    
    # Clean up
    rm -f "$zip_file"
    
    log_info "Successfully notarized: $binary"
}

# Main signing function
sign_binary() {
    local binary="$1"
    local platform="${2:-auto}"
    
    if [[ ! -f "$binary" ]]; then
        log_error "Binary not found: $binary"
        return 1
    fi
    
    # Auto-detect platform if needed
    if [[ "$platform" == "auto" ]]; then
        if [[ "$binary" =~ \.exe$ ]]; then
            platform="windows"
        elif file "$binary" | grep -q "Mach-O"; then
            platform="macos"
        else
            log_error "Could not detect platform for: $binary"
            return 1
        fi
    fi
    
    case "$platform" in
        macos)
            sign_macos "$binary"
            # Optionally notarize
            if [[ "${NOTARIZE:-false}" == "true" ]]; then
                notarize_macos "$binary"
            fi
            ;;
        windows)
            sign_windows "$binary"
            ;;
        *)
            log_error "Unknown platform: $platform"
            return 1
            ;;
    esac
}

# Process command line arguments
main() {
    if [[ $# -eq 0 ]]; then
        echo "Usage: $0 <binary-path> [platform]"
        echo "Platform can be: macos, windows, or auto (default)"
        echo ""
        echo "Environment variables:"
        echo "  MACOS_SIGNING_IDENTITY - Developer ID for macOS signing"
        echo "  MACOS_NOTARIZATION_USER - Apple ID for notarization"
        echo "  MACOS_NOTARIZATION_PASSWORD - App-specific password"
        echo "  MACOS_TEAM_ID - Apple Developer Team ID"
        echo "  WINDOWS_CERT_PATH - Path to Windows code signing certificate"
        echo "  WINDOWS_CERT_PASSWORD - Password for Windows certificate"
        echo "  NOTARIZE - Set to 'true' to notarize macOS binaries"
        exit 1
    fi
    
    local binary="$1"
    local platform="${2:-auto}"
    
    sign_binary "$binary" "$platform"
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi