#!/bin/bash

# KindlyGuard Release Rollback Script
# This script provides controlled rollback of releases by:
# - Showing what will be rolled back
# - Executing rollback with confirmation
# - Generating a detailed rollback report
#
# Usage: ./scripts/rollback-release.sh <version> [options]
#
# Arguments:
#   version    The version to rollback (e.g., 0.9.1)
#
# Options:
#   --dry-run       Show what would be rolled back without executing
#   --force         Skip confirmation prompts
#   --skip-npm      Skip NPM rollback (since unpublishing has restrictions)
#   --skip-docker   Skip Docker image removal
#   --skip-github   Skip GitHub release deletion
#   --report-only   Generate report of current state without rollback
#   --help          Show this help message
#
# Examples:
#   ./scripts/rollback-release.sh 0.9.1 --dry-run
#   ./scripts/rollback-release.sh 0.9.1 --skip-npm
#   ./scripts/rollback-release.sh 0.9.1 --force

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
ROLLBACK_REPORT="$PROJECT_ROOT/rollback-report-$(date +%Y%m%d-%H%M%S).md"

# Default options
DRY_RUN=false
FORCE=false
SKIP_NPM=false
SKIP_DOCKER=false
SKIP_GITHUB=false
REPORT_ONLY=false
VERSION=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --skip-npm)
            SKIP_NPM=true
            shift
            ;;
        --skip-docker)
            SKIP_DOCKER=true
            shift
            ;;
        --skip-github)
            SKIP_GITHUB=true
            shift
            ;;
        --report-only)
            REPORT_ONLY=true
            shift
            ;;
        --help)
            grep "^#" "$0" | grep -E "^# (KindlyGuard|This script|Usage:|Arguments:|Options:|Examples:)" | sed 's/^# //'
            exit 0
            ;;
        -*)
            echo -e "${RED}Error: Unknown option $1${NC}"
            exit 1
            ;;
        *)
            VERSION="$1"
            shift
            ;;
    esac
done

# Validate version argument
if [[ -z "$VERSION" ]]; then
    echo -e "${RED}Error: Version argument is required${NC}"
    echo "Usage: $0 <version> [options]"
    exit 1
fi

# Validate version format
if ! echo "$VERSION" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$' > /dev/null; then
    echo -e "${RED}Error: Invalid version format: $VERSION${NC}"
    echo "Expected format: X.Y.Z or X.Y.Z-prerelease"
    exit 1
fi

# Helper functions
echo_header() {
    echo -e "\n${BLUE}==== $1 ====${NC}"
}

echo_success() {
    echo -e "${GREEN}✓${NC} $1"
}

echo_error() {
    echo -e "${RED}✗${NC} $1"
}

echo_warning() {
    echo -e "${YELLOW}!${NC} $1"
}

echo_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

echo_action() {
    if [[ "$DRY_RUN" == true ]]; then
        echo -e "${MAGENTA}[DRY RUN]${NC} Would execute: $1"
    else
        echo -e "${GREEN}➜${NC} Executing: $1"
    fi
}

# Initialize rollback report
init_report() {
    cat > "$ROLLBACK_REPORT" << EOF
# KindlyGuard Release Rollback Report

**Date:** $(date -u +"%Y-%m-%d %H:%M:%S UTC")  
**Version:** $VERSION  
**Operator:** $(git config user.name) <$(git config user.email)>  
**Mode:** $(if [[ "$DRY_RUN" == true ]]; then echo "Dry Run"; else echo "Live Rollback"; fi)

## Summary

This report documents the rollback of KindlyGuard version $VERSION.

## Pre-Rollback State

EOF
}

# Add section to report
add_to_report() {
    echo -e "$1" >> "$ROLLBACK_REPORT"
}

# Check component status
check_git_tag() {
    echo_header "Checking Git Tags"
    
    local tag_exists=false
    if git tag -l "v$VERSION" | grep -q "v$VERSION"; then
        tag_exists=true
        echo_success "Git tag v$VERSION exists"
        
        # Get tag information
        local tag_date=$(git log -1 --format=%ai "v$VERSION")
        local tag_commit=$(git rev-list -n 1 "v$VERSION")
        local tag_author=$(git log -1 --format='%an <%ae>' "v$VERSION")
        
        add_to_report "### Git Tag

- **Tag:** v$VERSION
- **Commit:** $tag_commit
- **Date:** $tag_date
- **Author:** $tag_author
- **Status:** Exists
"
    else
        echo_warning "Git tag v$VERSION not found"
        add_to_report "### Git Tag

- **Tag:** v$VERSION
- **Status:** Not found
"
    fi
    
    return $(if [[ "$tag_exists" == true ]]; then echo 0; else echo 1; fi)
}

check_github_release() {
    echo_header "Checking GitHub Release"
    
    local release_exists=false
    if gh release view "v$VERSION" &> /dev/null; then
        release_exists=true
        echo_success "GitHub release v$VERSION exists"
        
        # Get release information
        local release_info=$(gh release view "v$VERSION" --json name,author,createdAt,assets)
        local release_author=$(echo "$release_info" | jq -r '.author.login')
        local release_date=$(echo "$release_info" | jq -r '.createdAt')
        local asset_count=$(echo "$release_info" | jq '.assets | length')
        
        add_to_report "### GitHub Release

- **Release:** v$VERSION
- **Author:** $release_author
- **Date:** $release_date
- **Assets:** $asset_count files
- **URL:** https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/v$VERSION
- **Status:** Published
"
    else
        echo_warning "GitHub release v$VERSION not found"
        add_to_report "### GitHub Release

- **Release:** v$VERSION
- **Status:** Not found
"
    fi
    
    return $(if [[ "$release_exists" == true ]]; then echo 0; else echo 1; fi)
}

check_crates_io() {
    echo_header "Checking Crates.io"
    
    add_to_report "### Crates.io Packages

| Package | Version | Status | Note |
|---------|---------|--------|------|"
    
    local crates_found=0
    for crate in kindly-guard-server kindly-guard-cli kindlyguard; do
        if cargo search "$crate" --limit 1 | grep -q "^$crate = \"$VERSION\""; then
            echo_success "$crate v$VERSION is published"
            add_to_report "| $crate | $VERSION | Published | ⚠️ Cannot be unpublished |"
            ((crates_found++))
        else
            echo_info "$crate v$VERSION not found on crates.io"
            add_to_report "| $crate | $VERSION | Not found | - |"
        fi
    done
    
    if [[ $crates_found -gt 0 ]]; then
        echo_warning "Note: Crates.io does not allow unpublishing versions"
        echo_info "Published crates will remain available but can be yanked"
    fi
    
    add_to_report ""
    return $crates_found
}

check_npm() {
    echo_header "Checking NPM Registry"
    
    local npm_exists=false
    local package_name="@kindlyops/kindly-guard"
    
    if npm view "$package_name@$VERSION" version &> /dev/null; then
        npm_exists=true
        echo_success "$package_name@$VERSION is published"
        
        # Get package information
        local publish_time=$(npm view "$package_name@$VERSION" time."$VERSION" 2>/dev/null || echo "unknown")
        
        add_to_report "### NPM Package

- **Package:** $package_name
- **Version:** $VERSION
- **Published:** $publish_time
- **Status:** Published
- **Note:** NPM has strict unpublishing policies
"
    else
        echo_warning "$package_name@$VERSION not found on NPM"
        add_to_report "### NPM Package

- **Package:** $package_name
- **Version:** $VERSION
- **Status:** Not found
"
    fi
    
    return $(if [[ "$npm_exists" == true ]]; then echo 0; else echo 1; fi)
}

check_docker_images() {
    echo_header "Checking Docker Images"
    
    local images_found=0
    local docker_repo="kindlyops/kindly-guard"
    
    add_to_report "### Docker Images

| Tag | Status | Platforms |
|-----|--------|-----------|"
    
    # Check Docker Hub for version tag
    if docker manifest inspect "$docker_repo:v$VERSION" &> /dev/null; then
        echo_success "Docker image $docker_repo:v$VERSION exists"
        add_to_report "| v$VERSION | Published | linux/amd64, linux/arm64 |"
        ((images_found++))
    else
        echo_info "Docker image $docker_repo:v$VERSION not found"
        add_to_report "| v$VERSION | Not found | - |"
    fi
    
    # Check if this version is tagged as latest
    if docker manifest inspect "$docker_repo:latest" &> /dev/null; then
        # Try to determine if latest points to this version
        echo_info "Docker image $docker_repo:latest exists (version unknown)"
        add_to_report "| latest | Published | Check if points to v$VERSION |"
    fi
    
    add_to_report ""
    return $images_found
}

# Rollback functions
rollback_git_tag() {
    echo_header "Rolling Back Git Tag"
    
    if git tag -l "v$VERSION" | grep -q "v$VERSION"; then
        echo_action "git tag -d v$VERSION"
        if [[ "$DRY_RUN" == false ]]; then
            git tag -d "v$VERSION"
            echo_success "Deleted local tag v$VERSION"
            
            echo_action "git push origin :refs/tags/v$VERSION"
            if git push origin ":refs/tags/v$VERSION" 2>/dev/null; then
                echo_success "Deleted remote tag v$VERSION"
                add_to_report "

## Rollback Actions

### Git Tag
- ✅ Deleted local tag v$VERSION
- ✅ Deleted remote tag v$VERSION"
            else
                echo_error "Failed to delete remote tag"
                add_to_report "

## Rollback Actions

### Git Tag
- ✅ Deleted local tag v$VERSION
- ❌ Failed to delete remote tag v$VERSION"
            fi
        fi
    else
        echo_info "Tag v$VERSION not found, nothing to rollback"
    fi
}

rollback_github_release() {
    echo_header "Rolling Back GitHub Release"
    
    if [[ "$SKIP_GITHUB" == true ]]; then
        echo_warning "Skipping GitHub release rollback (--skip-github)"
        return
    fi
    
    if gh release view "v$VERSION" &> /dev/null; then
        echo_action "gh release delete v$VERSION"
        if [[ "$DRY_RUN" == false ]]; then
            if [[ "$FORCE" == true ]]; then
                gh release delete "v$VERSION" -y
            else
                gh release delete "v$VERSION"
            fi
            echo_success "Deleted GitHub release v$VERSION"
            add_to_report "
### GitHub Release
- ✅ Deleted release v$VERSION and associated assets"
        fi
    else
        echo_info "GitHub release v$VERSION not found, nothing to rollback"
    fi
}

rollback_npm() {
    echo_header "Rolling Back NPM Package"
    
    if [[ "$SKIP_NPM" == true ]]; then
        echo_warning "Skipping NPM rollback (--skip-npm)"
        return
    fi
    
    local package_name="@kindlyops/kindly-guard"
    
    if npm view "$package_name@$VERSION" version &> /dev/null; then
        echo_warning "NPM package $package_name@$VERSION is published"
        echo_info "NPM unpublishing policy:"
        echo_info "- Packages published < 72 hours ago can be unpublished"
        echo_info "- No other packages depend on it"
        echo_info "- Weekly download count is low"
        
        if [[ "$DRY_RUN" == false ]]; then
            echo ""
            if [[ "$FORCE" == true ]] || confirm "Attempt to unpublish from NPM?"; then
                echo_action "npm unpublish $package_name@$VERSION"
                if npm unpublish "$package_name@$VERSION" 2>/dev/null; then
                    echo_success "Unpublished $package_name@$VERSION"
                    add_to_report "
### NPM Package
- ✅ Unpublished $package_name@$VERSION"
                else
                    echo_error "Failed to unpublish (may exceed NPM's unpublishing policy)"
                    echo_info "Consider deprecating instead: npm deprecate $package_name@$VERSION \"Deprecated due to issues\""
                    add_to_report "
### NPM Package
- ❌ Failed to unpublish $package_name@$VERSION
- ℹ️ May need to deprecate instead"
                fi
            else
                echo_info "Skipping NPM unpublish"
            fi
        fi
    else
        echo_info "NPM package not found, nothing to rollback"
    fi
}

rollback_docker() {
    echo_header "Rolling Back Docker Images"
    
    if [[ "$SKIP_DOCKER" == true ]]; then
        echo_warning "Skipping Docker rollback (--skip-docker)"
        return
    fi
    
    local docker_repo="kindlyops/kindly-guard"
    
    echo_warning "Docker Hub image deletion requires:"
    echo_info "1. Login to Docker Hub web interface"
    echo_info "2. Navigate to repository settings"
    echo_info "3. Delete specific tags"
    echo ""
    echo_info "Repository: https://hub.docker.com/r/$docker_repo/tags"
    echo_info "Tags to delete: v$VERSION"
    
    add_to_report "
### Docker Images
- ⚠️ Manual deletion required via Docker Hub web interface
- Repository: https://hub.docker.com/r/$docker_repo/tags
- Tag to delete: v$VERSION"
    
    if [[ "$DRY_RUN" == false ]]; then
        echo ""
        echo_info "Opening Docker Hub in browser..."
        if command -v xdg-open > /dev/null; then
            xdg-open "https://hub.docker.com/r/$docker_repo/tags" 2>/dev/null || true
        elif command -v open > /dev/null; then
            open "https://hub.docker.com/r/$docker_repo/tags" 2>/dev/null || true
        fi
    fi
}

rollback_crates() {
    echo_header "Handling Crates.io Packages"
    
    echo_warning "Crates.io does not allow unpublishing"
    echo_info "However, you can yank versions to prevent new dependencies"
    
    local crates_to_yank=()
    for crate in kindly-guard-server kindly-guard-cli kindlyguard; do
        if cargo search "$crate" --limit 1 | grep -q "^$crate = \"$VERSION\""; then
            crates_to_yank+=("$crate")
        fi
    done
    
    if [[ ${#crates_to_yank[@]} -gt 0 ]]; then
        echo ""
        echo_info "Crates that can be yanked:"
        for crate in "${crates_to_yank[@]}"; do
            echo "  - $crate@$VERSION"
        done
        
        if [[ "$DRY_RUN" == false ]]; then
            echo ""
            if [[ "$FORCE" == true ]] || confirm "Yank these crates?"; then
                for crate in "${crates_to_yank[@]}"; do
                    echo_action "cargo yank --version $VERSION $crate"
                    if cargo yank --version "$VERSION" "$crate" 2>/dev/null; then
                        echo_success "Yanked $crate@$VERSION"
                        add_to_report "
### Crates.io
- ✅ Yanked $crate@$VERSION"
                    else
                        echo_error "Failed to yank $crate@$VERSION"
                        add_to_report "
### Crates.io
- ❌ Failed to yank $crate@$VERSION"
                    fi
                done
            else
                echo_info "Skipping crate yanking"
            fi
        fi
    else
        echo_info "No crates found to yank"
    fi
}

# Confirmation helper
confirm() {
    local prompt="$1"
    local response
    
    echo -n -e "${YELLOW}$prompt [y/N] ${NC}"
    read -r response
    
    case "$response" in
        [yY][eE][sS]|[yY])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Main rollback process
main() {
    echo -e "${BLUE}KindlyGuard Release Rollback${NC}"
    echo -e "${BLUE}============================${NC}"
    echo ""
    echo -e "Version to rollback: ${YELLOW}$VERSION${NC}"
    echo -e "Mode: $(if [[ "$DRY_RUN" == true ]]; then echo "${MAGENTA}DRY RUN${NC}"; else echo "${RED}LIVE${NC}"; fi)"
    
    # Initialize report
    init_report
    
    # Check current state
    echo_header "Checking Current State"
    
    local has_components=false
    
    check_git_tag && has_components=true
    check_github_release && has_components=true
    check_crates_io > /dev/null && has_components=true
    check_npm && has_components=true
    check_docker_images > /dev/null && has_components=true
    
    if [[ "$has_components" == false ]]; then
        echo ""
        echo_warning "No components found for version $VERSION"
        echo_info "Nothing to rollback"
        exit 0
    fi
    
    # Report only mode
    if [[ "$REPORT_ONLY" == true ]]; then
        echo ""
        echo_success "Report generated: $ROLLBACK_REPORT"
        exit 0
    fi
    
    # Confirmation
    if [[ "$DRY_RUN" == false ]] && [[ "$FORCE" == false ]]; then
        echo ""
        echo -e "${YELLOW}⚠️  WARNING: This will rollback release $VERSION${NC}"
        echo "This action will:"
        echo "  • Delete git tag v$VERSION (local and remote)"
        echo "  • Delete GitHub release v$VERSION"
        echo "  • Attempt to unpublish NPM package (if allowed)"
        echo "  • Yank crates.io packages (cannot unpublish)"
        echo "  • Provide instructions for Docker image removal"
        echo ""
        
        if ! confirm "Continue with rollback?"; then
            echo_info "Rollback cancelled"
            exit 0
        fi
    fi
    
    # Execute rollback
    echo ""
    echo_header "Executing Rollback"
    
    rollback_git_tag
    rollback_github_release
    rollback_npm
    rollback_docker
    rollback_crates
    
    # Final summary
    echo ""
    echo_header "Rollback Summary"
    
    add_to_report "
## Summary

Rollback of version $VERSION completed with the above actions.

### Next Steps

1. **Version Management**: Decide on next version number
2. **Code Updates**: Fix issues that caused the rollback
3. **Communication**: Notify team and users if needed
4. **Re-release**: Follow standard release process when ready

### Rollback Checklist

- [ ] Git tags removed
- [ ] GitHub release deleted
- [ ] NPM package handled (unpublished or deprecated)
- [ ] Crates yanked (if applicable)
- [ ] Docker images removed manually
- [ ] Team notified
- [ ] Issues documented

---

Generated by: \`$0 $VERSION\`  
Date: $(date -u +"%Y-%m-%d %H:%M:%S UTC")"
    
    echo_success "Rollback complete!"
    echo_info "Report saved to: $ROLLBACK_REPORT"
    
    if [[ "$DRY_RUN" == true ]]; then
        echo ""
        echo_warning "This was a dry run. No actual changes were made."
        echo_info "Run without --dry-run to execute the rollback."
    else
        echo ""
        echo_warning "Important post-rollback tasks:"
        echo "1. Review the rollback report"
        echo "2. Manually remove Docker images if needed"
        echo "3. Update version numbers in codebase if re-releasing"
        echo "4. Notify team members about the rollback"
    fi
}

# Run main function
main