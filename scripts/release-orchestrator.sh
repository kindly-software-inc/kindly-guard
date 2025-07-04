#!/bin/bash

# Release Orchestrator for KindlyGuard
# Manages the entire release process with state management, monitoring, and rollback capabilities

set -euo pipefail

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# Configuration
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly STATE_FILE="$PROJECT_ROOT/.release-state.json"
readonly CONFIG_FILE="$PROJECT_ROOT/release-config.yml"
readonly LOG_DIR="$PROJECT_ROOT/.release-logs"
readonly LOCK_FILE="$PROJECT_ROOT/.release.lock"

# Default configuration
INTERACTIVE=${INTERACTIVE:-true}
SKIP_CONFIRMATION=${SKIP_CONFIRMATION:-false}
RETRY_ATTEMPTS=${RETRY_ATTEMPTS:-3}
RETRY_DELAY=${RETRY_DELAY:-5}
WORKFLOW_TIMEOUT=${WORKFLOW_TIMEOUT:-1800} # 30 minutes

# Stages
readonly STAGES=(
    "pre_flight"
    "version_update"
    "git_operations"
    "github_release"
    "verification"
    "notification"
)

# Create log directory
mkdir -p "$LOG_DIR"

# Logging functions
log() {
    local level=$1
    shift
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${timestamp} [${level}] $*" | tee -a "$LOG_DIR/release-$(date +%Y%m%d).log"
}

log_info() {
    echo -e "${BLUE}ℹ${NC} $*"
    log "INFO" "$*"
}

log_success() {
    echo -e "${GREEN}✓${NC} $*"
    log "SUCCESS" "$*"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $*"
    log "WARNING" "$*"
}

log_error() {
    echo -e "${RED}✗${NC} $*" >&2
    log "ERROR" "$*"
}

log_step() {
    echo -e "\n${BOLD}${CYAN}▶ $*${NC}"
    log "STEP" "$*"
}

# Progress indicator
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    
    printf "\r["
    printf "%${completed}s" | tr ' ' '='
    printf "%$((width - completed))s" | tr ' ' '-'
    printf "] %3d%% " "$percentage"
}

# Spinner for long operations
spin() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while kill -0 "$pid" 2>/dev/null; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# State management
save_state() {
    local version=$1
    local stage=$2
    local status=$3
    local error_msg=${4:-""}
    
    cat > "$STATE_FILE" <<EOF
{
    "version": "$version",
    "stage": "$stage",
    "status": "$status",
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "error": "$error_msg",
    "stages_completed": $(get_completed_stages)
}
EOF
}

load_state() {
    if [[ -f "$STATE_FILE" ]]; then
        cat "$STATE_FILE"
    else
        echo "{}"
    fi
}

get_state_field() {
    local field=$1
    load_state | jq -r ".$field // empty"
}

get_completed_stages() {
    local completed=$(load_state | jq -r '.stages_completed // []')
    if [[ "$completed" == "[]" || -z "$completed" ]]; then
        echo "[]"
    else
        echo "$completed"
    fi
}

mark_stage_complete() {
    local stage=$1
    local current_state=$(load_state)
    local completed=$(echo "$current_state" | jq ".stages_completed // []")
    local updated=$(echo "$completed" | jq ". + [\"$stage\"] | unique")
    
    echo "$current_state" | jq ".stages_completed = $updated" > "$STATE_FILE"
}

is_stage_complete() {
    local stage=$1
    local completed=$(get_completed_stages)
    echo "$completed" | jq -e ".[] | select(. == \"$stage\")" > /dev/null 2>&1
}

# Lock file management
acquire_lock() {
    local pid=$$
    if [[ -f "$LOCK_FILE" ]]; then
        local lock_pid=$(cat "$LOCK_FILE")
        if kill -0 "$lock_pid" 2>/dev/null; then
            log_error "Another release process is running (PID: $lock_pid)"
            return 1
        else
            log_warning "Removing stale lock file"
            rm -f "$LOCK_FILE"
        fi
    fi
    echo "$pid" > "$LOCK_FILE"
}

release_lock() {
    rm -f "$LOCK_FILE"
}

# Cleanup on exit
cleanup() {
    local exit_code=$?
    release_lock
    if [[ $exit_code -ne 0 ]]; then
        log_error "Release process failed with exit code: $exit_code"
    fi
}

trap cleanup EXIT

# Configuration loading
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading configuration from $CONFIG_FILE"
        # Parse YAML config (simplified - in production use yq or similar)
        while IFS=: read -r key value; do
            key=$(echo "$key" | tr -d ' ')
            value=$(echo "$value" | sed 's/^ *//;s/ *$//')
            case "$key" in
                interactive) INTERACTIVE="$value" ;;
                skip_confirmation) SKIP_CONFIRMATION="$value" ;;
                retry_attempts) RETRY_ATTEMPTS="$value" ;;
                retry_delay) RETRY_DELAY="$value" ;;
                workflow_timeout) WORKFLOW_TIMEOUT="$value" ;;
            esac
        done < "$CONFIG_FILE"
    fi
    
    # Environment variable overrides
    INTERACTIVE=${RELEASE_INTERACTIVE:-$INTERACTIVE}
    SKIP_CONFIRMATION=${RELEASE_SKIP_CONFIRMATION:-$SKIP_CONFIRMATION}
}

# Confirmation helper
confirm() {
    local prompt=$1
    if [[ "$SKIP_CONFIRMATION" == "true" ]]; then
        return 0
    fi
    
    echo -en "${YELLOW}${prompt} [y/N] ${NC}"
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY]) return 0 ;;
        *) return 1 ;;
    esac
}

# Tool validation
check_tool() {
    local tool=$1
    local version_flag=${2:-"--version"}
    
    if ! command -v "$tool" &> /dev/null; then
        log_error "$tool is not installed"
        return 1
    fi
    
    local version=$("$tool" $version_flag 2>&1 | head -n1)
    log_success "$tool: $version"
}

# Environment validation
validate_environment() {
    log_step "Validating environment"
    
    local failed=false
    
    # Check required tools
    log_info "Checking required tools..."
    check_tool "git" || failed=true
    check_tool "gh" || failed=true
    check_tool "cargo" || failed=true
    check_tool "npm" || failed=true
    check_tool "docker" || failed=true
    check_tool "jq" || failed=true
    
    # Check authentication
    log_info "Checking authentication..."
    
    # GitHub
    if ! gh auth status &> /dev/null; then
        log_error "Not authenticated with GitHub CLI"
        log_info "Run: gh auth login"
        failed=true
    else
        log_success "GitHub authentication valid"
    fi
    
    # NPM
    if ! npm whoami &> /dev/null; then
        log_error "Not authenticated with npm"
        log_info "Run: npm login"
        failed=true
    else
        local npm_user=$(npm whoami)
        log_success "npm authenticated as: $npm_user"
    fi
    
    # Cargo/crates.io
    if [[ ! -f "$HOME/.cargo/credentials.toml" ]] && [[ -z "$CARGO_REGISTRY_TOKEN" ]]; then
        log_error "No crates.io token found"
        log_info "Run: cargo login"
        failed=true
    else
        log_success "crates.io token found"
    fi
    
    # Docker Hub
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running"
        failed=true
    elif ! docker system info 2>&1 | grep -q "Username"; then
        log_warning "Not logged in to Docker Hub"
        log_info "Run: docker login"
    else
        log_success "Docker Hub authenticated"
    fi
    
    # Check git status
    log_info "Checking git repository..."
    if ! git diff --quiet || ! git diff --cached --quiet; then
        log_error "Uncommitted changes in repository"
        git status --short
        failed=true
    else
        log_success "Working directory clean"
    fi
    
    # Check remote
    if ! git remote get-url origin &> /dev/null; then
        log_error "No git remote 'origin' configured"
        failed=true
    else
        local remote=$(git remote get-url origin)
        log_success "Git remote: $remote"
    fi
    
    if [[ "$failed" == "true" ]]; then
        return 1
    fi
}

# Version update stage
run_version_update() {
    local version=$1
    log_step "Updating version to $version"
    
    if ! [[ -x "$SCRIPT_DIR/update-version.sh" ]]; then
        log_error "update-version.sh not found or not executable"
        return 1
    fi
    
    # Run version update script
    if ! "$SCRIPT_DIR/update-version.sh" "$version"; then
        log_error "Version update failed"
        return 1
    fi
    
    log_success "Version updated successfully"
}

# Git operations stage
run_git_operations() {
    local version=$1
    log_step "Performing git operations"
    
    # Commit changes
    log_info "Committing version changes..."
    git add -A
    git commit -m "chore: Release v$version

- Update version to $version across all packages
- Prepare for release

[skip ci]"
    
    # Create and push tag
    log_info "Creating git tag v$version..."
    git tag -a "v$version" -m "Release v$version"
    
    if confirm "Push changes and tag to origin?"; then
        git push origin main
        git push origin "v$version"
        log_success "Changes and tag pushed successfully"
    else
        log_warning "Skipping push - remember to push manually"
    fi
}

# GitHub release stage with monitoring
run_github_release() {
    local version=$1
    log_step "Creating GitHub release and monitoring workflow"
    
    # Check if release already exists
    if gh release view "v$version" &> /dev/null; then
        log_warning "Release v$version already exists"
        if confirm "Delete existing release and recreate?"; then
            gh release delete "v$version" --yes
        else
            return 0
        fi
    fi
    
    # Create release to trigger workflow
    log_info "Creating GitHub release..."
    gh release create "v$version" \
        --title "KindlyGuard v$version" \
        --notes "See [CHANGELOG.md](https://github.com/ultrathinkteam/kindly-guard/blob/main/CHANGELOG.md) for details." \
        --prerelease
    
    # Monitor workflow
    log_info "Waiting for release workflow to start..."
    sleep 5
    
    # Find the workflow run
    local run_id
    local attempts=0
    while [[ -z "$run_id" ]] && [[ $attempts -lt 10 ]]; do
        run_id=$(gh run list --workflow=release.yml --limit 1 --json databaseId,headBranch \
            | jq -r '.[] | select(.headBranch == "refs/tags/v'$version'") | .databaseId')
        if [[ -z "$run_id" ]]; then
            sleep 3
            ((attempts++))
        fi
    done
    
    if [[ -z "$run_id" ]]; then
        log_error "Could not find workflow run for release"
        return 1
    fi
    
    log_info "Monitoring workflow run #$run_id..."
    
    # Monitor with visual progress
    local start_time=$(date +%s)
    while true; do
        local status=$(gh run view "$run_id" --json status -q .status)
        local conclusion=$(gh run view "$run_id" --json conclusion -q .conclusion)
        local elapsed=$(($(date +%s) - start_time))
        
        printf "\r⏱  Elapsed: %02d:%02d | Status: %-15s" $((elapsed/60)) $((elapsed%60)) "$status"
        
        case "$status" in
            completed)
                echo
                if [[ "$conclusion" == "success" ]]; then
                    log_success "Workflow completed successfully!"
                    
                    # Show job summary
                    log_info "Job summary:"
                    gh run view "$run_id" --json jobs -q '.jobs[] | "\(.name): \(.conclusion)"'
                    return 0
                else
                    log_error "Workflow failed with conclusion: $conclusion"
                    
                    # Show failed jobs
                    log_error "Failed jobs:"
                    gh run view "$run_id" --json jobs -q '.jobs[] | select(.conclusion != "success") | "\(.name): \(.conclusion)"'
                    
                    # Offer to view logs
                    if confirm "View workflow logs?"; then
                        gh run view "$run_id" --log-failed
                    fi
                    return 1
                fi
                ;;
            *)
                if [[ $elapsed -gt $WORKFLOW_TIMEOUT ]]; then
                    echo
                    log_error "Workflow timeout after $((elapsed/60)) minutes"
                    return 1
                fi
                sleep 5
                ;;
        esac
    done
}

# Verification stage
run_verification() {
    local version=$1
    log_step "Verifying release artifacts"
    
    local all_good=true
    
    # Check crates.io
    log_info "Checking crates.io..."
    if curl -s "https://crates.io/api/v1/crates/kindly-guard" | jq -e ".crate.max_version == \"$version\"" > /dev/null; then
        log_success "kindly-guard $version found on crates.io"
    else
        log_warning "kindly-guard $version not yet available on crates.io"
        all_good=false
    fi
    
    # Check npm
    log_info "Checking npm registry..."
    if npm view "@kindly-guard/shield@$version" version &> /dev/null; then
        log_success "@kindly-guard/shield@$version found on npm"
    else
        log_warning "@kindly-guard/shield@$version not yet available on npm"
        all_good=false
    fi
    
    # Check Docker Hub
    log_info "Checking Docker Hub..."
    if docker manifest inspect "kindlyguard/kindly-guard:$version" &> /dev/null; then
        log_success "kindlyguard/kindly-guard:$version found on Docker Hub"
    else
        log_warning "kindlyguard/kindly-guard:$version not yet available on Docker Hub"
        all_good=false
    fi
    
    # Check GitHub release assets
    log_info "Checking GitHub release assets..."
    local assets=$(gh release view "v$version" --json assets -q '.assets[].name')
    local expected_assets=(
        "kindly-guard-linux-x64.tar.gz"
        "kindly-guard-macos-x64.tar.gz"
        "kindly-guard-macos-arm64.tar.gz"
        "kindly-guard-windows-x64.zip"
    )
    
    for asset in "${expected_assets[@]}"; do
        if echo "$assets" | grep -q "$asset"; then
            log_success "Found asset: $asset"
        else
            log_warning "Missing asset: $asset"
            all_good=false
        fi
    done
    
    if [[ "$all_good" != "true" ]]; then
        log_warning "Some artifacts are not yet available"
        if confirm "Continue anyway?"; then
            return 0
        else
            return 1
        fi
    fi
}

# Notification stage
run_notification() {
    local version=$1
    log_step "Sending notifications"
    
    # Create summary
    local summary="Release v$version completed successfully!"
    local details=""
    
    # Add links
    details+="📦 Crates.io: https://crates.io/crates/kindly-guard/$version\n"
    details+="📦 npm: https://www.npmjs.com/package/@kindly-guard/shield/v/$version\n"
    details+="🐳 Docker Hub: https://hub.docker.com/r/kindlyguard/kindly-guard/tags\n"
    details+="📋 GitHub Release: https://github.com/ultrathinkteam/kindly-guard/releases/tag/v$version\n"
    
    echo -e "\n${GREEN}${BOLD}$summary${NC}"
    echo -e "$details"
    
    # Save summary to file
    cat > "$LOG_DIR/release-$version-summary.txt" <<EOF
Release Summary: v$version
========================
Date: $(date)
Duration: $(get_release_duration)

Artifacts Published:
- Crates.io: ✓
- npm Registry: ✓
- Docker Hub: ✓
- GitHub Release: ✓

Release Notes:
https://github.com/ultrathinkteam/kindly-guard/releases/tag/v$version

CHANGELOG:
https://github.com/ultrathinkteam/kindly-guard/blob/main/CHANGELOG.md
EOF
    
    log_success "Release v$version completed!"
}

# Get release duration
get_release_duration() {
    local start_time=$(get_state_field "timestamp")
    if [[ -n "$start_time" ]]; then
        local start_epoch=$(date -d "$start_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$start_time" +%s 2>/dev/null || echo 0)
        local now_epoch=$(date +%s)
        local duration=$((now_epoch - start_epoch))
        printf "%02d:%02d:%02d" $((duration/3600)) $((duration%3600/60)) $((duration%60))
    else
        echo "unknown"
    fi
}

# Execute a stage with retry logic
execute_stage() {
    local stage=$1
    local version=$2
    local attempt=1
    
    while [[ $attempt -le $RETRY_ATTEMPTS ]]; do
        log_info "Executing stage: $stage (attempt $attempt/$RETRY_ATTEMPTS)"
        
        case "$stage" in
            pre_flight)
                if validate_environment; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            version_update)
                if run_version_update "$version"; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            git_operations)
                if run_git_operations "$version"; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            github_release)
                if run_github_release "$version"; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            verification)
                if run_verification "$version"; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            notification)
                if run_notification "$version"; then
                    mark_stage_complete "$stage"
                    return 0
                fi
                ;;
            *)
                log_error "Unknown stage: $stage"
                return 1
                ;;
        esac
        
        if [[ $attempt -lt $RETRY_ATTEMPTS ]]; then
            log_warning "Stage failed, retrying in $RETRY_DELAY seconds..."
            sleep "$RETRY_DELAY"
        fi
        
        ((attempt++))
    done
    
    log_error "Stage $stage failed after $RETRY_ATTEMPTS attempts"
    return 1
}

# Start new release
start_release() {
    local version=$1
    
    if [[ -z "$version" ]]; then
        log_error "Version not specified"
        echo "Usage: $0 start <version>"
        exit 1
    fi
    
    # Validate version format
    if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
        log_error "Invalid version format: $version"
        echo "Expected format: X.Y.Z or X.Y.Z-suffix"
        exit 1
    fi
    
    # Check for existing state
    if [[ -f "$STATE_FILE" ]]; then
        local existing_version=$(get_state_field "version")
        if [[ "$existing_version" == "$version" ]]; then
            log_warning "Release $version already in progress"
            if confirm "Resume existing release?"; then
                resume_release
                return
            else
                if confirm "Start fresh (will delete existing state)?"; then
                    rm -f "$STATE_FILE"
                else
                    exit 1
                fi
            fi
        else
            log_warning "Found incomplete release for version $existing_version"
            if ! confirm "Abandon and start new release?"; then
                exit 1
            fi
            rm -f "$STATE_FILE"
        fi
    fi
    
    log_info "Starting release process for version $version"
    save_state "$version" "pre_flight" "in_progress" ""
    
    # Execute stages
    for stage in "${STAGES[@]}"; do
        if is_stage_complete "$stage"; then
            log_info "Stage already complete: $stage"
            continue
        fi
        
        # Show progress
        local stage_index=$(printf '%s\n' "${STAGES[@]}" | grep -n "^$stage$" | cut -d: -f1)
        local total_stages=${#STAGES[@]}
        show_progress "$stage_index" "$total_stages"
        echo " $stage"
        
        # Confirm before proceeding (except for pre_flight)
        if [[ "$INTERACTIVE" == "true" ]] && [[ "$stage" != "pre_flight" ]]; then
            if ! confirm "Proceed with $stage?"; then
                log_warning "Release paused at stage: $stage"
                save_state "$version" "$stage" "paused" "User paused release"
                exit 0
            fi
        fi
        
        save_state "$version" "$stage" "in_progress" ""
        
        if ! execute_stage "$stage" "$version"; then
            save_state "$version" "$stage" "failed" "Stage execution failed"
            log_error "Release failed at stage: $stage"
            exit 1
        fi
        
        save_state "$version" "$stage" "completed" ""
    done
    
    save_state "$version" "completed" "success" ""
    log_success "Release $version completed successfully!"
}

# Resume release
resume_release() {
    if [[ ! -f "$STATE_FILE" ]]; then
        log_error "No release in progress"
        exit 1
    fi
    
    local version=$(get_state_field "version")
    local last_stage=$(get_state_field "stage")
    local status=$(get_state_field "status")
    
    log_info "Resuming release $version from stage: $last_stage (status: $status)"
    
    # Find next stage
    local start_from=""
    local found=false
    for stage in "${STAGES[@]}"; do
        if [[ "$found" == "true" ]] || [[ "$stage" == "$last_stage" ]]; then
            if ! is_stage_complete "$stage"; then
                start_from="$stage"
                break
            fi
            found=true
        fi
    done
    
    if [[ -z "$start_from" ]]; then
        log_error "All stages completed or no valid stage found"
        exit 1
    fi
    
    # Resume from the appropriate stage
    found=false
    for stage in "${STAGES[@]}"; do
        if [[ "$stage" == "$start_from" ]]; then
            found=true
        fi
        
        if [[ "$found" == "true" ]]; then
            if is_stage_complete "$stage"; then
                log_info "Stage already complete: $stage"
                continue
            fi
            
            save_state "$version" "$stage" "in_progress" ""
            
            if ! execute_stage "$stage" "$version"; then
                save_state "$version" "$stage" "failed" "Stage execution failed"
                log_error "Release failed at stage: $stage"
                exit 1
            fi
            
            save_state "$version" "$stage" "completed" ""
        fi
    done
    
    save_state "$version" "completed" "success" ""
    log_success "Release $version completed successfully!"
}

# Show release status
show_status() {
    if [[ ! -f "$STATE_FILE" ]]; then
        log_info "No release in progress"
        return
    fi
    
    local state=$(load_state)
    echo -e "\n${BOLD}Release Status${NC}"
    echo "═══════════════════════════════════════"
    echo -e "Version:    $(echo "$state" | jq -r .version)"
    echo -e "Stage:      $(echo "$state" | jq -r .stage)"
    echo -e "Status:     $(echo "$state" | jq -r .status)"
    echo -e "Started:    $(echo "$state" | jq -r .timestamp)"
    echo -e "Duration:   $(get_release_duration)"
    
    echo -e "\n${BOLD}Stage Progress:${NC}"
    for stage in "${STAGES[@]}"; do
        if is_stage_complete "$stage"; then
            echo -e "  ${GREEN}✓${NC} $stage"
        else
            local current_stage=$(echo "$state" | jq -r .stage)
            if [[ "$stage" == "$current_stage" ]]; then
                local status=$(echo "$state" | jq -r .status)
                case "$status" in
                    in_progress) echo -e "  ${BLUE}●${NC} $stage (in progress)" ;;
                    failed) echo -e "  ${RED}✗${NC} $stage (failed)" ;;
                    paused) echo -e "  ${YELLOW}‖${NC} $stage (paused)" ;;
                    *) echo -e "  ${YELLOW}○${NC} $stage" ;;
                esac
            else
                echo -e "  ○ $stage"
            fi
        fi
    done
    
    local error=$(echo "$state" | jq -r '.error // empty')
    if [[ -n "$error" ]]; then
        echo -e "\n${RED}Last Error:${NC} $error"
    fi
}

# Rollback release
rollback_release() {
    local version=$1
    
    if [[ -z "$version" ]]; then
        log_error "Version not specified"
        echo "Usage: $0 rollback <version>"
        exit 1
    fi
    
    log_warning "This will rollback release v$version"
    echo "Actions to be performed:"
    echo "  • Delete git tag v$version (local and remote)"
    echo "  • Convert GitHub release to draft"
    echo "  • Generate rollback instructions for registries"
    
    if ! confirm "Proceed with rollback?"; then
        exit 0
    fi
    
    log_step "Rolling back release v$version"
    
    # Delete git tag
    log_info "Deleting git tag..."
    if git tag -l | grep -q "^v$version$"; then
        git tag -d "v$version"
        log_success "Local tag deleted"
    fi
    
    if git ls-remote --tags origin | grep -q "refs/tags/v$version$"; then
        if confirm "Delete remote tag?"; then
            git push origin --delete "v$version"
            log_success "Remote tag deleted"
        fi
    fi
    
    # Convert release to draft
    log_info "Converting GitHub release to draft..."
    if gh release view "v$version" &> /dev/null; then
        gh release edit "v$version" --draft
        log_success "GitHub release converted to draft"
    else
        log_warning "GitHub release not found"
    fi
    
    # Generate rollback instructions
    log_info "Generating rollback instructions..."
    cat > "$LOG_DIR/rollback-$version-instructions.md" <<EOF
# Rollback Instructions for v$version

## Automated Actions Completed:
- ✓ Git tag deleted (local and remote)
- ✓ GitHub release converted to draft

## Manual Actions Required:

### 1. Crates.io
Crates.io does not support unpublishing versions.
- Consider publishing a patch version with fixes
- Add deprecation notice: \`cargo yank --version $version\`

### 2. npm Registry
Within 72 hours of publishing:
\`\`\`bash
npm unpublish @kindly-guard/shield@$version
\`\`\`

After 72 hours:
\`\`\`bash
npm deprecate @kindly-guard/shield@$version "This version has been rolled back"
\`\`\`

### 3. Docker Hub
Remove the image tag:
\`\`\`bash
# Note: Requires appropriate permissions
curl -X DELETE https://hub.docker.com/v2/repositories/kindlyguard/kindly-guard/tags/$version/
\`\`\`

### 4. Git Repository
If commits need to be reverted:
\`\`\`bash
git revert <commit-hash>
git push origin main
\`\`\`

## Verification:
- [ ] Check that v$version is not the latest on crates.io
- [ ] Verify npm shows deprecation warning
- [ ] Confirm Docker image is removed/untagged
- [ ] Ensure documentation reflects the rollback

## Communication:
- [ ] Update changelog to note the rollback
- [ ] Notify users if they've already upgraded
- [ ] Create issue explaining the rollback reason
EOF
    
    log_success "Rollback instructions saved to: $LOG_DIR/rollback-$version-instructions.md"
    
    # Clean up state file if it matches
    if [[ -f "$STATE_FILE" ]]; then
        local state_version=$(get_state_field "version")
        if [[ "$state_version" == "$version" ]]; then
            rm -f "$STATE_FILE"
            log_info "Cleaned up release state"
        fi
    fi
    
    log_success "Rollback completed. See instructions for manual steps."
}

# Main function
main() {
    cd "$PROJECT_ROOT"
    
    # Load configuration
    load_config
    
    # Acquire lock
    if ! acquire_lock; then
        exit 1
    fi
    
    # Parse command
    case "${1:-}" in
        start)
            start_release "${2:-}"
            ;;
        resume)
            resume_release
            ;;
        status)
            show_status
            ;;
        rollback)
            rollback_release "${2:-}"
            ;;
        *)
            echo "Release Orchestrator for KindlyGuard"
            echo
            echo "Usage:"
            echo "  $0 start <version>     Start new release"
            echo "  $0 resume              Resume failed/paused release"
            echo "  $0 status              Show current release status"
            echo "  $0 rollback <version>  Rollback a release"
            echo
            echo "Examples:"
            echo "  $0 start 0.9.6"
            echo "  $0 resume"
            echo "  $0 status"
            echo "  $0 rollback 0.9.6"
            echo
            echo "Environment Variables:"
            echo "  INTERACTIVE=false          Disable interactive prompts"
            echo "  SKIP_CONFIRMATION=true     Skip all confirmations"
            echo "  RETRY_ATTEMPTS=5           Number of retry attempts"
            echo "  WORKFLOW_TIMEOUT=3600      Workflow timeout in seconds"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"