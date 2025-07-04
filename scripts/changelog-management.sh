#!/bin/bash

# KindlyGuard Changelog Management Script
# Uses git-cliff for automated changelog generation

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CLIFF_CONFIG="$PROJECT_ROOT/.cliff.toml"
CHANGELOG_FILE="$PROJECT_ROOT/CHANGELOG.md"

# Functions
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if git-cliff is installed
check_git_cliff() {
    if ! command -v git-cliff &> /dev/null; then
        print_error "git-cliff is not installed"
        print_info "Install with: cargo install git-cliff"
        print_info "Or visit: https://github.com/orhun/git-cliff"
        return 1
    fi
    return 0
}

# Show usage
usage() {
    cat << EOF
Usage: $0 [COMMAND] [OPTIONS]

Commands:
  generate    Generate/update the changelog
  preview     Preview unreleased changes
  validate    Validate commit messages
  install     Install git-cliff

Options:
  --tag TAG   Generate changelog up to specified tag
  --from TAG  Generate changelog from specified tag
  --help      Show this help message

Examples:
  $0 generate              # Update changelog with all changes
  $0 generate --tag v1.0.0 # Generate changelog for v1.0.0 release
  $0 preview               # Show unreleased changes
  $0 validate              # Check recent commits for compliance
  $0 install               # Install git-cliff

EOF
}

# Install git-cliff
install_git_cliff() {
    print_info "Installing git-cliff..."
    
    if cargo install git-cliff; then
        print_success "git-cliff installed successfully"
    else
        print_error "Failed to install git-cliff"
        print_info "Try: cargo install git-cliff --locked"
        return 1
    fi
}

# Generate changelog
generate_changelog() {
    local tag=""
    local from=""
    
    # Parse options
    while [[ $# -gt 0 ]]; do
        case $1 in
            --tag)
                tag="$2"
                shift 2
                ;;
            --from)
                from="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    
    print_info "Generating changelog..."
    
    # Backup existing changelog
    if [[ -f "$CHANGELOG_FILE" ]]; then
        cp "$CHANGELOG_FILE" "$CHANGELOG_FILE.bak"
    fi
    
    # Build git-cliff command
    local cmd="git-cliff --config $CLIFF_CONFIG"
    
    if [[ -n "$tag" ]]; then
        cmd="$cmd --tag $tag"
    fi
    
    if [[ -n "$from" ]]; then
        cmd="$cmd --from $from"
    fi
    
    # Generate changelog
    if $cmd --output "$CHANGELOG_FILE"; then
        print_success "Changelog generated successfully"
        
        # Show summary
        if [[ -f "$CHANGELOG_FILE.bak" ]]; then
            local added=$(diff "$CHANGELOG_FILE.bak" "$CHANGELOG_FILE" 2>/dev/null | grep '^>' | wc -l)
            print_info "Added $added new lines to changelog"
            rm -f "$CHANGELOG_FILE.bak"
        fi
    else
        print_error "Failed to generate changelog"
        
        # Restore backup
        if [[ -f "$CHANGELOG_FILE.bak" ]]; then
            mv "$CHANGELOG_FILE.bak" "$CHANGELOG_FILE"
        fi
        return 1
    fi
}

# Preview unreleased changes
preview_unreleased() {
    print_info "Previewing unreleased changes..."
    
    if git-cliff --config "$CLIFF_CONFIG" --unreleased; then
        print_success "Preview complete"
    else
        print_warning "No unreleased changes found or error occurred"
    fi
}

# Validate recent commits
validate_commits() {
    print_info "Validating recent commits..."
    
    local invalid_count=0
    local total_count=0
    
    # Get recent commits
    while IFS= read -r commit; do
        ((total_count++))
        
        # Extract commit message
        local msg=$(git log -1 --pretty=%s "$commit")
        
        # Check if it matches conventional commit format
        if [[ ! "$msg" =~ ^(security|vuln|cve|audit|feat|fix|perf|docs|test|refactor|build|ci|deps|chore)(\([a-zA-Z0-9-]+\))?!?:\ .+ ]]; then
            print_warning "Invalid commit: $commit - $msg"
            ((invalid_count++))
        fi
    done < <(git rev-list --max-count=20 HEAD)
    
    if [[ $invalid_count -eq 0 ]]; then
        print_success "All $total_count recent commits are valid"
    else
        print_error "$invalid_count out of $total_count commits are invalid"
        print_info "See CONTRIBUTING.md for commit message guidelines"
        return 1
    fi
}

# Main function
main() {
    # Check if in git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi
    
    # Parse command
    case "${1:-}" in
        generate)
            check_git_cliff || exit 1
            shift
            generate_changelog "$@"
            ;;
        preview)
            check_git_cliff || exit 1
            preview_unreleased
            ;;
        validate)
            validate_commits
            ;;
        install)
            install_git_cliff
            ;;
        --help|-h|"")
            usage
            ;;
        *)
            print_error "Unknown command: $1"
            usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"