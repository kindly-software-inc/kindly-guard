#!/bin/bash
#
# Simple Release Script for KindlyGuard
# Usage: ./scripts/release.sh VERSION
#
# This is a convenience wrapper that combines version update and release
# orchestration into a single command with sensible defaults.

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Default values
DRY_RUN=false
SKIP_CHECKS=false
AUTO_PUBLISH=false

# Help function
show_help() {
    cat << EOF
KindlyGuard Simple Release Script

USAGE:
    $0 VERSION [OPTIONS]

ARGUMENTS:
    VERSION         Version to release (e.g., 0.9.6, 1.0.0)

OPTIONS:
    --dry-run       Preview what would happen without making changes
    --skip-checks   Skip pre-release verification checks
    --auto-publish  Automatically publish packages without prompts
    -h, --help      Show this help message

EXAMPLES:
    # Standard release
    $0 0.9.6

    # Preview release
    $0 0.9.6 --dry-run

    # Fast release (skip checks, auto-publish)
    $0 0.9.6 --skip-checks --auto-publish

DESCRIPTION:
    This script provides a simple one-command release process:
    1. Verifies release setup and prerequisites
    2. Updates version numbers across all files
    3. Creates commit and tag
    4. Triggers GitHub Actions build
    5. Creates GitHub release
    6. Publishes packages to registries

    For more control, use:
    - ./scripts/update-version.sh --release VERSION
    - ./scripts/release-orchestrator.sh [options]

EOF
}

# Log functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1" >&2
}

# Progress indicator
show_progress() {
    local message="$1"
    echo -ne "${BLUE}⏳${NC} $message..."
}

complete_progress() {
    echo -e "\r${GREEN}✓${NC} $1"
}

# Parse arguments
if [ $# -eq 0 ]; then
    log_error "Error: Version argument required"
    echo
    show_help
    exit 1
fi

VERSION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --skip-checks)
            SKIP_CHECKS=true
            shift
            ;;
        --auto-publish)
            AUTO_PUBLISH=true
            shift
            ;;
        -*)
            log_error "Unknown option: $1"
            echo
            show_help
            exit 1
            ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="$1"
            else
                log_error "Multiple version arguments provided"
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate version format
if ! [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?$ ]]; then
    log_error "Invalid version format: $VERSION"
    log_info "Version must be in format: X.Y.Z or X.Y.Z-suffix"
    exit 1
fi

# Header
echo
echo "🚀 KindlyGuard Release v$VERSION"
echo "================================"
echo

# Dry run notice
if [ "$DRY_RUN" = true ]; then
    log_warning "DRY RUN MODE - No changes will be made"
    echo
fi

# Step 1: Verify setup
if [ "$SKIP_CHECKS" = false ]; then
    show_progress "Verifying release setup"
    if [ "$DRY_RUN" = false ]; then
        if ! "$SCRIPT_DIR/verify-release-setup.sh" > /dev/null 2>&1; then
            echo
            log_error "Release setup verification failed"
            log_info "Run './scripts/verify-release-setup.sh' for details"
            exit 1
        fi
    fi
    complete_progress "Release setup verified"
else
    log_warning "Skipping release setup verification"
fi

# Step 2: Check for uncommitted changes
show_progress "Checking repository status"
if [ "$DRY_RUN" = false ]; then
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo
        log_error "Uncommitted changes detected"
        log_info "Please commit or stash changes before releasing"
        exit 1
    fi
fi
complete_progress "Repository is clean"

# Step 3: Update version
echo
log_info "Updating version to $VERSION"
if [ "$DRY_RUN" = true ]; then
    "$SCRIPT_DIR/update-version.sh" "$VERSION" --dry-run
else
    # Use --release flag to trigger full release
    "$SCRIPT_DIR/update-version.sh" "$VERSION" --release
fi

# Step 4: Show summary
echo
echo "📋 Release Summary"
echo "=================="
echo "Version:        $VERSION"
echo "Branch:         $(git branch --show-current)"
echo "Last commit:    $(git log -1 --oneline)"
echo

# Step 5: Confirm release
if [ "$DRY_RUN" = false ] && [ "$AUTO_PUBLISH" = false ]; then
    read -p "Proceed with release? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_warning "Release cancelled"
        exit 0
    fi
fi

# Step 6: Wait for GitHub Actions
if [ "$DRY_RUN" = false ]; then
    echo
    log_info "Release tag pushed. GitHub Actions will now:"
    echo "  1. Build binaries for all platforms"
    echo "  2. Create GitHub release with assets"
    echo "  3. Generate checksums"
    echo
    log_info "Monitor progress at:"
    echo "  https://github.com/kindlysoftware/kindlyguard/actions"
    echo
    
    # Optional: Wait and publish
    if [ "$AUTO_PUBLISH" = true ]; then
        log_info "Auto-publishing enabled. Will publish packages after build completes."
        # The orchestrator handles the waiting and publishing
        "$SCRIPT_DIR/release-orchestrator.sh" \
            --version "$VERSION" \
            --auto-publish \
            --skip-version-update
    else
        log_info "After the build completes, run these commands to publish:"
        echo "  ./scripts/publish-crates.sh"
        echo "  ./scripts/publish-npm.sh"
        echo "  ./scripts/publish-docker.sh"
    fi
fi

# Success
echo
if [ "$DRY_RUN" = true ]; then
    log_success "Dry run completed successfully"
else
    log_success "Release v$VERSION initiated successfully! 🎉"
fi

# Final notes
if [ "$DRY_RUN" = false ]; then
    echo
    echo "📝 Next Steps:"
    echo "1. Monitor GitHub Actions build"
    echo "2. Verify release on GitHub"
    echo "3. Publish to package registries"
    echo "4. Announce the release"
    echo
    echo "If you encounter issues, see:"
    echo "  ./RELEASING.md - Troubleshooting section"
    echo "  ./docs/AUTOMATED_RELEASE_GUIDE.md"
fi