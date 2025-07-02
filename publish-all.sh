#!/bin/bash

# KindlyGuard NPM Publishing Script
# Publishes all platform packages and the main package to npm

set -e

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
NPM_DIR="$PROJECT_ROOT/npm-package"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging functions
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
    echo
    echo -e "${BLUE}==== $1 ====${NC}"
    echo
}

# Check npm authentication
check_npm_auth() {
    print_header "Checking NPM Authentication"
    
    if ! npm whoami &>/dev/null; then
        print_error "Not authenticated to npm"
        print_info "Please run: npm login"
        exit 1
    fi
    
    local npm_user=$(npm whoami)
    print_status "Authenticated as: $npm_user"
}

# Get package version
get_version() {
    if [ -f "$NPM_DIR/package.json" ]; then
        VERSION=$(node -p "require('$NPM_DIR/package.json').version")
    else
        VERSION="0.2.0"
    fi
    echo "$VERSION"
}

# Publish platform package
publish_platform_package() {
    local pkg_dir=$1
    local dry_run=$2
    
    if [ ! -f "$pkg_dir/package.json" ]; then
        print_error "No package.json found in $pkg_dir"
        return 1
    fi
    
    local pkg_name=$(node -p "require('$pkg_dir/package.json').name")
    local pkg_version=$(node -p "require('$pkg_dir/package.json').version")
    
    print_info "Publishing $pkg_name@$pkg_version"
    
    # Check if package exists
    if npm view "$pkg_name@$pkg_version" &>/dev/null; then
        print_warning "  Package already published"
        return 0
    fi
    
    # Validate package contents
    if [ ! -f "$pkg_dir/kindlyguard" ] && [ ! -f "$pkg_dir/kindlyguard.exe" ]; then
        print_error "  No binary found in package"
        return 1
    fi
    
    cd "$pkg_dir"
    
    if [ "$dry_run" = "true" ]; then
        print_info "  [DRY RUN] Would publish $pkg_name"
        npm publish --dry-run --access public
    else
        npm publish --access public
        print_status "  Published successfully"
    fi
    
    cd - >/dev/null
    return 0
}

# Publish all platform packages
publish_platform_packages() {
    local dry_run=$1
    print_header "Publishing Platform Packages"
    
    local npm_platforms_dir="$NPM_DIR/npm"
    
    if [ ! -d "$npm_platforms_dir" ]; then
        print_error "No platform packages found"
        return 1
    fi
    
    local published=0
    local failed=0
    
    for platform_dir in "$npm_platforms_dir"/*; do
        if [ -d "$platform_dir" ]; then
            if publish_platform_package "$platform_dir" "$dry_run"; then
                ((published++))
            else
                ((failed++))
            fi
            echo
        fi
    done
    
    print_info "Published: $published, Failed: $failed"
    
    if [ $failed -gt 0 ]; then
        return 1
    fi
    
    return 0
}

# Publish main package
publish_main_package() {
    local dry_run=$1
    print_header "Publishing Main Package"
    
    if [ ! -f "$NPM_DIR/package.json" ]; then
        print_error "Main package.json not found"
        return 1
    fi
    
    local pkg_name=$(node -p "require('$NPM_DIR/package.json').name")
    local pkg_version=$(node -p "require('$NPM_DIR/package.json').version")
    
    print_info "Publishing $pkg_name@$pkg_version"
    
    # Check if already published
    if npm view "$pkg_name@$pkg_version" &>/dev/null; then
        print_warning "Package already published"
        return 0
    fi
    
    cd "$NPM_DIR"
    
    if [ "$dry_run" = "true" ]; then
        print_info "[DRY RUN] Would publish $pkg_name"
        npm publish --dry-run
    else
        npm publish
        print_status "Published successfully"
    fi
    
    cd - >/dev/null
    return 0
}

# Verify published packages
verify_published_packages() {
    print_header "Verifying Published Packages"
    
    local version=$(get_version)
    local expected_packages=(
        "kindlyguard@$version"
        "@kindlyguard/linux-x64@$version"
        "@kindlyguard/linux-arm64@$version"
        "@kindlyguard/darwin-x64@$version"
        "@kindlyguard/darwin-arm64@$version"
        "@kindlyguard/win32-x64@$version"
    )
    
    local verified=0
    local missing=0
    
    for pkg in "${expected_packages[@]}"; do
        if npm view "$pkg" &>/dev/null; then
            print_status "$pkg - Published"
            ((verified++))
        else
            print_warning "$pkg - Not found"
            ((missing++))
        fi
    done
    
    print_info "Verified: $verified, Missing: $missing"
    
    if [ $missing -eq 0 ]; then
        print_status "All packages published successfully!"
        return 0
    else
        return 1
    fi
}

# Create git tag
create_git_tag() {
    local version=$1
    print_header "Creating Git Tag"
    
    if git rev-parse "v$version" &>/dev/null; then
        print_warning "Tag v$version already exists"
        return 0
    fi
    
    print_info "Creating tag v$version"
    git tag -a "v$version" -m "Release v$version"
    print_status "Tag created"
    
    print_info "Push tag with: git push origin v$version"
}

# Main execution
main() {
    print_header "KindlyGuard NPM Publishing"
    
    local dry_run=false
    local skip_auth=false
    local tag_only=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                dry_run=true
                print_warning "DRY RUN MODE - No packages will be published"
                ;;
            --skip-auth)
                skip_auth=true
                ;;
            --tag)
                tag_only=true
                ;;
            --help)
                echo "Usage: $0 [options]"
                echo "Options:"
                echo "  --dry-run    Run without actually publishing"
                echo "  --skip-auth  Skip npm authentication check"
                echo "  --tag        Create git tag only"
                echo "  --help       Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
        shift
    done
    
    # Get version
    VERSION=$(get_version)
    print_info "Version: $VERSION"
    
    # Tag only mode
    if [ "$tag_only" = true ]; then
        create_git_tag "$VERSION"
        exit 0
    fi
    
    # Check authentication
    if [ "$skip_auth" = false ]; then
        check_npm_auth
    fi
    
    # Check for built packages
    if [ ! -d "$NPM_DIR/npm" ]; then
        print_error "No npm packages found. Run build-binaries.sh first."
        exit 1
    fi
    
    # Publish platform packages
    if ! publish_platform_packages "$dry_run"; then
        print_error "Failed to publish some platform packages"
        exit 1
    fi
    
    # Wait a moment for npm registry to update
    if [ "$dry_run" = false ]; then
        print_info "Waiting for npm registry to update..."
        sleep 5
    fi
    
    # Publish main package
    if ! publish_main_package "$dry_run"; then
        print_error "Failed to publish main package"
        exit 1
    fi
    
    # Verify publications
    if [ "$dry_run" = false ]; then
        echo
        sleep 10  # Give npm registry time to fully update
        verify_published_packages
    fi
    
    # Success message
    print_header "Publishing Complete!"
    
    if [ "$dry_run" = false ]; then
        echo "All packages have been published to npm."
        echo
        echo "Next steps:"
        echo "  1. Create git tag: ./publish-all.sh --tag"
        echo "  2. Push to GitHub: git push origin v$VERSION"
        echo "  3. GitHub Actions will create the release"
        echo
        echo "Users can now install with:"
        echo "  npm install -g kindlyguard"
    else
        echo "Dry run complete. Run without --dry-run to actually publish."
    fi
}

# Run main function
main "$@"