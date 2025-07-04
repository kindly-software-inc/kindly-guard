#!/bin/bash

# KindlyGuard Version Update Script
# Updates version numbers across all project files

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Script configuration
SCRIPT_NAME=$(basename "$0")
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_STATE_FILE="$PROJECT_ROOT/.release-state.json"

# Default options
DRY_RUN=false
COMMIT=false
TAG=false
RELEASE=false
RELEASE_DRY_RUN=false
NO_PUSH=false

# Spinner characters
SPINNER_CHARS="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
SPINNER_PID=""

# Function to print colored output
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

print_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_progress() {
    echo -e "${MAGENTA}[PROGRESS]${NC} $1"
}

# Function to start spinner
start_spinner() {
    local msg="${1:-Working...}"
    (
        while true; do
            for (( i=0; i<${#SPINNER_CHARS}; i++ )); do
                echo -ne "\r${CYAN}[${SPINNER_CHARS:$i:1}]${NC} $msg"
                sleep 0.1
            done
        done
    ) &
    SPINNER_PID=$!
}

# Function to stop spinner
stop_spinner() {
    if [[ -n "$SPINNER_PID" ]]; then
        kill "$SPINNER_PID" 2>/dev/null || true
        wait "$SPINNER_PID" 2>/dev/null || true
        SPINNER_PID=""
        echo -ne "\r\033[K" # Clear the line
    fi
}

# Function to save release state
save_release_state() {
    local state=$1
    local version=$2
    local data=$3
    
    cat > "$RELEASE_STATE_FILE" << EOF
{
    "version": "$version",
    "state": "$state",
    "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
    "data": $data
}
EOF
}

# Function to load release state
load_release_state() {
    if [[ -f "$RELEASE_STATE_FILE" ]]; then
        cat "$RELEASE_STATE_FILE"
    else
        echo "{}"
    fi
}

# Function to clean up release state
cleanup_release_state() {
    rm -f "$RELEASE_STATE_FILE"
}

# Function to display usage
usage() {
    cat << EOF
Usage: $SCRIPT_NAME VERSION [OPTIONS]

Updates version numbers across all KindlyGuard project files.

Arguments:
  VERSION    The new version number (e.g., 0.9.6, 1.0.0)

Options:
  --dry-run         Show what would be changed without making changes
  --commit          Create a git commit with the changes
  --tag             Create a git tag for the version (implies --commit)
  --release         Trigger full automated release process
  --release-dry-run Show what the release process would do without executing
  --no-push         Update versions and tag but don't push (for testing)
  -h, --help        Display this help message

Release Options:
  The --release flag triggers a complete automated release:
  - Validates git state and prerequisites
  - Updates all version files
  - Creates commit and tag
  - Pushes to trigger GitHub Actions workflow
  - Monitors workflow progress

Examples:
  $SCRIPT_NAME 0.9.6
  $SCRIPT_NAME 1.0.0 --dry-run
  $SCRIPT_NAME 0.9.7 --commit --tag
  $SCRIPT_NAME 1.0.0 --release
  $SCRIPT_NAME 1.0.0 --release-dry-run

EOF
}

# Function to validate semantic version
validate_version() {
    local version=$1
    if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
        print_error "Invalid version format: $version"
        print_error "Version must follow semantic versioning (e.g., 1.0.0, 0.9.6-beta.1)"
        return 1
    fi
    return 0
}

# Function to compare versions
version_greater_than() {
    local v1=$1
    local v2=$2
    
    # Special handling for test versions - they're always considered "older"
    if [[ "$v2" == *"-test"* ]] || [[ "$v2" == "9.9.9"* ]]; then
        return 0  # New version is always greater than test version
    fi
    
    # Remove pre-release and build metadata for comparison
    v1=${v1%%-*}
    v2=${v2%%-*}
    
    # Split versions into components
    IFS='.' read -ra v1_parts <<< "$v1"
    IFS='.' read -ra v2_parts <<< "$v2"
    
    # Compare major, minor, patch
    for i in 0 1 2; do
        local part1=${v1_parts[$i]:-0}
        local part2=${v2_parts[$i]:-0}
        
        if ((part1 > part2)); then
            return 0
        elif ((part1 < part2)); then
            return 1
        fi
    done
    
    # Versions are equal
    return 1
}

# Function to get current version from Cargo.toml
get_current_version() {
    local cargo_file="$PROJECT_ROOT/Cargo.toml"
    if [[ ! -f "$cargo_file" ]]; then
        print_error "Workspace Cargo.toml not found at $cargo_file"
        return 1
    fi
    
    local current_version=$(grep -E '^version\s*=\s*"[^"]*"' "$cargo_file" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')
    if [[ -z "$current_version" ]]; then
        print_error "Could not extract current version from $cargo_file"
        return 1
    fi
    
    echo "$current_version"
}

# Function to update a Cargo.toml file
update_cargo_toml() {
    local file=$1
    local new_version=$2
    
    if [[ ! -f "$file" ]]; then
        print_warning "File not found: $file"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would update $file"
        grep -n '^version\s*=' "$file" | head -5 || true
        return 0
    fi
    
    # Update version in Cargo.toml
    sed -i.bak -E "s/^version\s*=\s*\"[^\"]*\"/version = \"$new_version\"/" "$file"
    
    # Remove backup file
    rm -f "$file.bak"
    
    print_success "Updated $file"
}

# Function to update a package.json file
update_package_json() {
    local file=$1
    local new_version=$2
    
    if [[ ! -f "$file" ]]; then
        print_warning "File not found: $file"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would update $file"
        grep -n '"version"' "$file" | head -1 || true
        return 0
    fi
    
    # Update version in package.json using sed
    # This handles both formats: "version": "x.y.z" and "version":"x.y.z"
    sed -i.bak -E 's/"version":\s*"[^"]*"/"version": "'"$new_version"'"/' "$file"
    
    # Remove backup file
    rm -f "$file.bak"
    
    print_success "Updated $file"
}

# Function to update README.md
update_readme() {
    local file="$PROJECT_ROOT/README.md"
    local new_version=$1
    
    if [[ ! -f "$file" ]]; then
        print_warning "README.md not found at $file"
        return 1
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would update README.md"
        grep -n "Current Release" "$file" || true
        return 0
    fi
    
    # Update the Current Release line
    sed -i.bak -E 's/### v[0-9]+\.[0-9]+\.[0-9]+[^ ]* \(Current Release\)/### v'"$new_version"' (Current Release)/' "$file"
    
    # Remove backup file
    rm -f "$file.bak"
    
    print_success "Updated README.md"
}

# Function to update CHANGELOG.md using git-cliff
update_changelog() {
    local new_version=$1
    local changelog_file="$PROJECT_ROOT/CHANGELOG.md"
    
    # Check if git-cliff is installed
    if ! command -v git-cliff &> /dev/null; then
        print_warning "git-cliff not found. Skipping changelog generation."
        print_info "Install git-cliff: cargo install git-cliff"
        return 0
    fi
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would update CHANGELOG.md using git-cliff"
        return 0
    fi
    
    print_step "Generating changelog with git-cliff..."
    
    # Create a backup of the current changelog
    if [[ -f "$changelog_file" ]]; then
        cp "$changelog_file" "$changelog_file.bak"
    fi
    
    # Generate the changelog
    # Using --tag to set the version we're releasing
    if git-cliff --config "$PROJECT_ROOT/.cliff.toml" \
                 --output "$changelog_file" \
                 --tag "v$new_version" \
                 --prepend; then
        print_success "Updated CHANGELOG.md"
        
        # Remove backup if successful
        rm -f "$changelog_file.bak"
    else
        print_error "Failed to generate changelog"
        
        # Restore backup if it exists
        if [[ -f "$changelog_file.bak" ]]; then
            mv "$changelog_file.bak" "$changelog_file"
        fi
        
        # Don't fail the release for changelog generation
        return 0
    fi
}

# Function to create git commit
create_commit() {
    local new_version=$1
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would create git commit for version $new_version"
        return 0
    fi
    
    # Check if there are changes to commit
    if git diff --quiet && git diff --cached --quiet; then
        print_warning "No changes to commit"
        return 1
    fi
    
    # Add all version-related files
    git add -A
    
    # Create commit
    git commit -m "chore: bump version to $new_version" -m "Updated version in all project files"
    
    print_success "Created git commit for version $new_version"
}

# Function to create git tag
create_tag() {
    local new_version=$1
    
    if [[ "$DRY_RUN" == "true" ]]; then
        print_info "[DRY RUN] Would create git tag v$new_version"
        return 0
    fi
    
    # Create annotated tag
    git tag -a "v$new_version" -m "Release version $new_version"
    
    print_success "Created git tag v$new_version"
}

# Function to check if git is clean
check_git_clean() {
    if ! git diff --quiet || ! git diff --cached --quiet; then
        return 1
    fi
    
    # Check for untracked files (excluding .release-state.json)
    local untracked=$(git ls-files --others --exclude-standard | grep -v "^.release-state.json$" || true)
    if [[ -n "$untracked" ]]; then
        return 1
    fi
    
    return 0
}

# Function to get current git branch
get_current_branch() {
    git rev-parse --abbrev-ref HEAD
}

# Function to check if on main/master branch
check_main_branch() {
    local branch=$(get_current_branch)
    if [[ "$branch" == "main" ]] || [[ "$branch" == "master" ]]; then
        return 0
    fi
    return 1
}

# Function to check if GitHub CLI is installed
check_gh_cli() {
    if command -v gh &> /dev/null; then
        return 0
    fi
    return 1
}

# Function to check if GitHub CLI is authenticated
check_gh_auth() {
    if gh auth status &> /dev/null; then
        return 0
    fi
    return 1
}

# Function to get repository info
get_repo_info() {
    local origin_url=$(git config --get remote.origin.url || echo "")
    if [[ -z "$origin_url" ]]; then
        return 1
    fi
    
    # Extract owner/repo from URL
    local repo_info=""
    if [[ "$origin_url" =~ github\.com[:/]([^/]+)/([^/]+)(\.git)?$ ]]; then
        repo_info="${BASH_REMATCH[1]}/${BASH_REMATCH[2]%.git}"
    fi
    
    if [[ -n "$repo_info" ]]; then
        echo "$repo_info"
        return 0
    fi
    
    return 1
}

# Function to check if tag exists locally
tag_exists_local() {
    local tag=$1
    git rev-parse "refs/tags/$tag" &> /dev/null
}

# Function to check if tag exists on remote
tag_exists_remote() {
    local tag=$1
    git ls-remote --tags origin | grep -q "refs/tags/$tag"
}

# Function to perform pre-release checks
perform_pre_release_checks() {
    local new_version=$1
    local errors=()
    
    print_info "Performing pre-release checks..."
    
    # Check 1: Git repository clean
    print_step "Checking git status..."
    if ! check_git_clean; then
        errors+=("Git repository has uncommitted changes. Please commit or stash them first.")
        print_error "Git repository is not clean"
    else
        print_success "Git repository is clean"
    fi
    
    # Check 2: On main/master branch
    print_step "Checking current branch..."
    if ! check_main_branch; then
        local current_branch=$(get_current_branch)
        errors+=("Not on main/master branch (current: $current_branch). Please switch to main/master.")
        print_error "Not on main/master branch"
    else
        print_success "On $(get_current_branch) branch"
    fi
    
    # Check 3: Validate versions consistency
    print_step "Validating version consistency..."
    start_spinner "Running validate-versions.sh"
    
    local validate_script="$SCRIPT_DIR/validate-versions.sh"
    if [[ -x "$validate_script" ]]; then
        if ! "$validate_script" > /dev/null 2>&1; then
            stop_spinner
            errors+=("Version inconsistency detected. Run './scripts/validate-versions.sh' to see details.")
            print_error "Version validation failed"
        else
            stop_spinner
            print_success "All versions are consistent"
        fi
    else
        stop_spinner
        print_warning "validate-versions.sh not found or not executable"
    fi
    
    # Check 4: GitHub CLI installed
    print_step "Checking GitHub CLI..."
    if ! check_gh_cli; then
        errors+=("GitHub CLI (gh) is not installed. Install it from https://cli.github.com")
        print_error "GitHub CLI not found"
    else
        print_success "GitHub CLI is installed"
        
        # Check 5: GitHub CLI authenticated
        if ! check_gh_auth; then
            errors+=("GitHub CLI is not authenticated. Run 'gh auth login' to authenticate.")
            print_error "GitHub CLI not authenticated"
        else
            print_success "GitHub CLI is authenticated"
        fi
    fi
    
    # Check 6: Repository info available
    print_step "Checking repository info..."
    local repo_info=$(get_repo_info)
    if [[ -z "$repo_info" ]]; then
        errors+=("Could not determine GitHub repository. Ensure origin remote is set correctly.")
        print_error "Repository info not found"
    else
        print_success "Repository: $repo_info"
    fi
    
    # Check 7: Tag doesn't already exist
    print_step "Checking if tag v$new_version exists..."
    if tag_exists_local "v$new_version"; then
        errors+=("Tag v$new_version already exists locally. Remove it with 'git tag -d v$new_version'")
        print_error "Tag already exists locally"
    elif tag_exists_remote "v$new_version"; then
        errors+=("Tag v$new_version already exists on remote. Choose a different version.")
        print_error "Tag already exists on remote"
    else
        print_success "Tag v$new_version is available"
    fi
    
    # Summary
    echo
    if [[ ${#errors[@]} -gt 0 ]]; then
        print_error "Pre-release checks failed with ${#errors[@]} error(s):"
        for error in "${errors[@]}"; do
            echo "  - $error"
        done
        return 1
    else
        print_success "All pre-release checks passed!"
        return 0
    fi
}

# Function to push tag and monitor workflow
push_and_monitor_release() {
    local new_version=$1
    local tag="v$new_version"
    
    if [[ "$NO_PUSH" == "true" ]]; then
        print_warning "Skipping push due to --no-push flag"
        return 0
    fi
    
    # Get repository info
    local repo_info=$(get_repo_info)
    if [[ -z "$repo_info" ]]; then
        print_error "Could not determine repository info"
        return 1
    fi
    
    print_step "Pushing tag $tag to trigger release..."
    
    # Push the tag
    if ! git push origin "$tag"; then
        print_error "Failed to push tag"
        return 1
    fi
    
    print_success "Tag pushed successfully"
    
    # Wait a moment for GitHub to register the push
    sleep 3
    
    print_step "Monitoring release workflow..."
    
    # Get the workflow run
    start_spinner "Waiting for workflow to start"
    
    local max_attempts=30
    local attempt=0
    local run_id=""
    
    while [[ $attempt -lt $max_attempts ]]; do
        # Try to find the workflow run for this tag
        run_id=$(gh run list \
            --repo "$repo_info" \
            --workflow "release.yml" \
            --limit 5 \
            --json databaseId,headBranch,status \
            --jq ".[] | select(.headBranch == \"$tag\") | .databaseId" \
            2>/dev/null | head -1)
        
        if [[ -n "$run_id" ]]; then
            stop_spinner
            print_success "Found workflow run: $run_id"
            break
        fi
        
        ((attempt++))
        sleep 2
    done
    
    if [[ -z "$run_id" ]]; then
        stop_spinner
        print_warning "Could not find workflow run. You can check manually at:"
        print_info "https://github.com/$repo_info/actions"
        return 0
    fi
    
    # Monitor the workflow
    print_info "Monitoring workflow progress..."
    print_info "View in browser: https://github.com/$repo_info/actions/runs/$run_id"
    echo
    
    # Watch the workflow
    gh run watch "$run_id" --repo "$repo_info" --exit-status
    
    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        print_success "Release workflow completed successfully!"
        print_info "View release at: https://github.com/$repo_info/releases/tag/$tag"
    else
        print_error "Release workflow failed with exit code: $exit_code"
        print_info "Check the logs at: https://github.com/$repo_info/actions/runs/$run_id"
        return 1
    fi
    
    return 0
}

# Function to perform release dry run
perform_release_dry_run() {
    local new_version=$1
    
    print_info "=== RELEASE DRY RUN ==="
    echo
    
    print_info "The following steps would be performed:"
    echo
    
    echo "1. Pre-release checks:"
    echo "   - Verify git repository is clean"
    echo "   - Verify on main/master branch"
    echo "   - Run validate-versions.sh"
    echo "   - Check GitHub CLI is installed and authenticated"
    echo "   - Verify tag v$new_version doesn't exist"
    echo
    
    echo "2. Version update:"
    echo "   - Update all Cargo.toml files to $new_version"
    echo "   - Update all package.json files to $new_version"
    echo "   - Update README.md to $new_version"
    echo
    
    echo "3. Git operations:"
    echo "   - Create commit: 'chore: bump version to $new_version'"
    echo "   - Create tag: v$new_version"
    echo
    
    if [[ "$NO_PUSH" != "true" ]]; then
        echo "4. Release:"
        echo "   - Push tag to origin"
        echo "   - Monitor GitHub Actions release workflow"
        echo "   - Wait for workflow completion"
    else
        echo "4. Release:"
        echo "   - Skip push (--no-push flag set)"
    fi
    echo
    
    print_info "No changes have been made."
}

# Main function
main() {
    # Parse arguments
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi
    
    local NEW_VERSION=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --commit)
                COMMIT=true
                shift
                ;;
            --tag)
                TAG=true
                COMMIT=true  # Tag implies commit
                shift
                ;;
            --release)
                RELEASE=true
                TAG=true
                COMMIT=true  # Release implies tag and commit
                shift
                ;;
            --release-dry-run)
                RELEASE_DRY_RUN=true
                shift
                ;;
            --no-push)
                NO_PUSH=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                print_error "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                if [[ -z "$NEW_VERSION" ]]; then
                    NEW_VERSION=$1
                else
                    print_error "Multiple version numbers provided"
                    usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Validate version
    if [[ -z "$NEW_VERSION" ]]; then
        print_error "Version number is required"
        usage
        exit 1
    fi
    
    if ! validate_version "$NEW_VERSION"; then
        exit 1
    fi
    
    # Handle release dry run
    if [[ "$RELEASE_DRY_RUN" == "true" ]]; then
        perform_release_dry_run "$NEW_VERSION"
        exit 0
    fi
    
    # Get current version
    CURRENT_VERSION=$(get_current_version) || exit 1
    print_info "Current version: $CURRENT_VERSION"
    print_info "New version: $NEW_VERSION"
    
    # Compare versions
    if ! version_greater_than "$NEW_VERSION" "$CURRENT_VERSION"; then
        print_warning "New version ($NEW_VERSION) is not greater than current version ($CURRENT_VERSION)"
        if [[ "$RELEASE" != "true" ]]; then
            read -p "Continue anyway? [y/N] " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                print_info "Aborted"
                exit 0
            fi
        else
            print_error "Cannot release: new version must be greater than current version"
            exit 1
        fi
    fi
    
    # Perform pre-release checks if --release is set
    if [[ "$RELEASE" == "true" ]]; then
        echo
        print_info "=== AUTOMATED RELEASE PROCESS ==="
        echo
        
        # Save initial state
        save_release_state "started" "$NEW_VERSION" "{}"
        
        # Perform pre-release checks
        if ! perform_pre_release_checks "$NEW_VERSION"; then
            print_error "Pre-release checks failed. Please fix the issues and try again."
            cleanup_release_state
            exit 1
        fi
        
        echo
        print_info "Ready to proceed with release v$NEW_VERSION"
        read -p "Continue? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Release cancelled"
            cleanup_release_state
            exit 0
        fi
        
        save_release_state "updating_versions" "$NEW_VERSION" "{}"
    fi
    
    # Check git status for non-release flows
    if [[ "$RELEASE" != "true" ]] && ([[ "$COMMIT" == "true" ]] || [[ "$TAG" == "true" ]]); then
        if ! git rev-parse --git-dir > /dev/null 2>&1; then
            print_error "Not in a git repository"
            exit 1
        fi
        
        # Check for uncommitted changes
        if ! git diff --quiet || ! git diff --cached --quiet; then
            print_warning "You have uncommitted changes"
            if [[ "$DRY_RUN" == "false" ]]; then
                read -p "Continue anyway? [y/N] " -n 1 -r
                echo
                if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                    print_info "Aborted"
                    exit 0
                fi
            fi
        fi
    fi
    
    print_info "Starting version update..."
    
    # Update Cargo.toml files
    local cargo_files=(
        "$PROJECT_ROOT/Cargo.toml"
        "$PROJECT_ROOT/kindly-guard-server/Cargo.toml"
        "$PROJECT_ROOT/kindly-guard-cli/Cargo.toml"
        "$PROJECT_ROOT/kindly-guard-shield/Cargo.toml"
        "$PROJECT_ROOT/crates-io-package/kindlyguard/Cargo.toml"
    )
    
    for cargo_file in "${cargo_files[@]}"; do
        update_cargo_toml "$cargo_file" "$NEW_VERSION"
    done
    
    # Update package.json files
    local package_files=(
        "$PROJECT_ROOT/npm-package/package.json"
        "$PROJECT_ROOT/npm-package/npm/kindlyguard-darwin-arm64/package.json"
        "$PROJECT_ROOT/npm-package/npm/kindlyguard-darwin-x64/package.json"
        "$PROJECT_ROOT/npm-package/npm/kindlyguard-linux-x64/package.json"
        "$PROJECT_ROOT/npm-package/npm/kindlyguard-win32-x64/package.json"
        "$PROJECT_ROOT/npm-package/npm/linux-x64/package.json"
    )
    
    # Check for root package.json
    if [[ -f "$PROJECT_ROOT/package.json" ]]; then
        package_files+=("$PROJECT_ROOT/package.json")
    fi
    
    # Check for shield package.json
    if [[ -f "$PROJECT_ROOT/kindly-guard-shield/package.json" ]]; then
        package_files+=("$PROJECT_ROOT/kindly-guard-shield/package.json")
    fi
    
    for package_file in "${package_files[@]}"; do
        update_package_json "$package_file" "$NEW_VERSION"
    done
    
    # Update README.md
    update_readme "$NEW_VERSION"
    
    # Update CHANGELOG.md using git-cliff
    update_changelog "$NEW_VERSION"
    
    # Update shield's Cargo.toml in src-tauri if it exists
    if [[ -f "$PROJECT_ROOT/kindly-guard-shield/src-tauri/Cargo.toml" ]]; then
        update_cargo_toml "$PROJECT_ROOT/kindly-guard-shield/src-tauri/Cargo.toml" "$NEW_VERSION"
    fi
    
    print_info "Version update complete!"
    
    # Create commit if requested
    if [[ "$COMMIT" == "true" ]]; then
        create_commit "$NEW_VERSION"
    fi
    
    # Create tag if requested
    if [[ "$TAG" == "true" ]]; then
        create_tag "$NEW_VERSION"
    fi
    
    # Handle release process
    if [[ "$RELEASE" == "true" ]]; then
        save_release_state "git_operations" "$NEW_VERSION" "{}"
        
        # Push and monitor release
        print_step "Initiating release workflow..."
        
        if push_and_monitor_release "$NEW_VERSION"; then
            print_success "Release v$NEW_VERSION completed successfully!"
            cleanup_release_state
        else
            print_error "Release process encountered an error"
            print_info "The version has been updated and tagged locally."
            print_info "You can manually push the tag with: git push origin v$NEW_VERSION"
            
            # Save failed state for potential retry
            save_release_state "failed" "$NEW_VERSION" '{"step": "push_and_monitor"}'
            
            exit 1
        fi
    else
        # Summary for non-release mode
        echo
        print_success "Version updated to $NEW_VERSION"
        
        if [[ "$DRY_RUN" == "true" ]]; then
            print_warning "This was a dry run. No files were actually modified."
        else
            print_info "All project files have been updated."
            
            if [[ "$COMMIT" == "true" ]]; then
                print_info "Changes have been committed to git."
            else
                print_info "Remember to commit these changes:"
                print_info "  git add -A && git commit -m \"chore: bump version to $NEW_VERSION\""
            fi
            
            if [[ "$TAG" == "true" ]]; then
                print_info "Git tag v$NEW_VERSION has been created."
                print_info "To push the tag: git push origin v$NEW_VERSION"
            elif [[ "$COMMIT" == "true" ]]; then
                print_info "To create a tag: git tag -a v$NEW_VERSION -m \"Release version $NEW_VERSION\""
            fi
        fi
    fi
}

# Cleanup function for script exit
cleanup_on_exit() {
    stop_spinner
}

# Set up trap to ensure cleanup
trap cleanup_on_exit EXIT

# Run main function
main "$@"