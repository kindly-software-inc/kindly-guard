#!/bin/bash

# validate-versions.sh - Check version consistency across the KindlyGuard project
# Usage: ./validate-versions.sh [--fix]

set -euo pipefail

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
FIX_MODE=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --fix)
            FIX_MODE=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--fix] [--verbose]"
            echo "  --fix      Offer to run update-version.sh with the most common version"
            echo "  --verbose  Show detailed output"
            echo "  --help     Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Arrays to store version information
declare -A version_files
declare -A version_counts
versions_found=()

# Helper functions
log() {
    if [[ "$VERBOSE" == true ]]; then
        echo -e "$1"
    fi
}

print_header() {
    echo -e "\n${BOLD}${BLUE}KindlyGuard Version Validation${NC}"
    echo -e "${BLUE}================================${NC}\n"
}

print_summary() {
    local total_files=$1
    local matched_files=$2
    local mismatched_files=$3
    
    echo -e "\n${BOLD}Summary:${NC}"
    echo -e "  Total files checked: ${BOLD}$total_files${NC}"
    echo -e "  Files with correct version: ${GREEN}$matched_files${NC}"
    echo -e "  Files with mismatched versions: ${RED}$mismatched_files${NC}"
}

# Extract version from Cargo.toml files
extract_cargo_versions() {
    log "${YELLOW}Checking Cargo.toml files...${NC}"
    
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            local version=$(grep -E '^version = ".*"' "$file" | head -1 | sed 's/version = "\(.*\)"/\1/')
            if [[ -n "$version" ]]; then
                local rel_path="${file#$PROJECT_ROOT/}"
                version_files["$rel_path"]="$version"
                
                # Track version counts
                if [[ -z "${version_counts[$version]:-}" ]]; then
                    version_counts["$version"]=1
                    versions_found+=("$version")
                else
                    ((version_counts["$version"]++))
                fi
                
                log "  Found version $version in $rel_path"
            fi
        fi
    done < <(find "$PROJECT_ROOT" -name "Cargo.toml" -type f -not -path "*/target/*" -not -path "*/node_modules/*" -print0 2>/dev/null)
}

# Extract version from package.json files
extract_package_json_versions() {
    log "${YELLOW}Checking package.json files...${NC}"
    
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            local version=""
            
            # Try to use jq if available
            if command -v jq &> /dev/null; then
                version=$(jq -r '.version // empty' "$file" 2>/dev/null || true)
            else
                # Fallback to grep/sed
                version=$(grep -E '"version":\s*"[^"]*"' "$file" | head -1 | sed 's/.*"version":\s*"\([^"]*\)".*/\1/' || true)
            fi
            
            if [[ -n "$version" ]]; then
                local rel_path="${file#$PROJECT_ROOT/}"
                version_files["$rel_path"]="$version"
                
                # Track version counts
                if [[ -z "${version_counts[$version]:-}" ]]; then
                    version_counts["$version"]=1
                    versions_found+=("$version")
                else
                    ((version_counts["$version"]++))
                fi
                
                log "  Found version $version in $rel_path"
            fi
        fi
    done < <(find "$PROJECT_ROOT" -name "package.json" -type f -not -path "*/node_modules/*" -not -path "*/target/*" -print0 2>/dev/null)
}

# Extract version from README.md
extract_readme_version() {
    log "${YELLOW}Checking README.md...${NC}"
    
    local readme="$PROJECT_ROOT/README.md"
    if [[ -f "$readme" ]]; then
        # Look for patterns like "Current Release: v1.0.0" or "Version: 1.0.0"
        local version=$(grep -E -i '(current release|version):\s*(v?[0-9]+\.[0-9]+\.[0-9]+)' "$readme" | head -1 | sed -E 's/.*(current release|version):\s*(v?)([0-9]+\.[0-9]+\.[0-9]+).*/\3/i' || true)
        
        if [[ -n "$version" ]]; then
            version_files["README.md"]="$version"
            
            # Track version counts
            if [[ -z "${version_counts[$version]:-}" ]]; then
                version_counts["$version"]=1
                versions_found+=("$version")
            else
                ((version_counts["$version"]++))
            fi
            
            log "  Found version $version in README.md"
        fi
    fi
}

# Extract versions from other files (e.g., VERSION file, docs)
extract_other_versions() {
    log "${YELLOW}Checking other version files...${NC}"
    
    # Check VERSION file if it exists
    if [[ -f "$PROJECT_ROOT/VERSION" ]]; then
        local version=$(cat "$PROJECT_ROOT/VERSION" | tr -d '\n' | tr -d '\r')
        if [[ -n "$version" ]]; then
            version_files["VERSION"]="$version"
            
            # Track version counts
            if [[ -z "${version_counts[$version]:-}" ]]; then
                version_counts["$version"]=1
                versions_found+=("$version")
            else
                ((version_counts["$version"]++))
            fi
            
            log "  Found version $version in VERSION"
        fi
    fi
    
    # Check for version in docs
    while IFS= read -r -d '' file; do
        if [[ -f "$file" ]]; then
            local version=$(grep -E 'version\s*(=|:)\s*"?v?([0-9]+\.[0-9]+\.[0-9]+)"?' "$file" | head -1 | sed -E 's/.*version\s*(=|:)\s*"?v?([0-9]+\.[0-9]+\.[0-9]+)"?.*/\2/' || true)
            
            if [[ -n "$version" ]]; then
                local rel_path="${file#$PROJECT_ROOT/}"
                version_files["$rel_path"]="$version"
                
                # Track version counts
                if [[ -z "${version_counts[$version]:-}" ]]; then
                    version_counts["$version"]=1
                    versions_found+=("$version")
                else
                    ((version_counts["$version"]++))
                fi
                
                log "  Found version $version in $rel_path"
            fi
        fi
    done < <(find "$PROJECT_ROOT/docs" -name "*.md" -o -name "*.txt" 2>/dev/null | head -20 | tr '\n' '\0')
}

# Find the most common version
find_most_common_version() {
    local max_count=0
    local most_common=""
    
    for version in "${versions_found[@]}"; do
        if [[ ${version_counts[$version]} -gt $max_count ]]; then
            max_count=${version_counts[$version]}
            most_common=$version
        fi
    done
    
    echo "$most_common"
}

# Validate versions
validate_versions() {
    local most_common=$(find_most_common_version)
    local total_files=${#version_files[@]}
    local matched_files=0
    local mismatched_files=0
    local all_match=true
    
    if [[ -z "$most_common" ]]; then
        echo -e "${RED}Error: No versions found in the project${NC}"
        return 1
    fi
    
    echo -e "${BOLD}Checking version consistency...${NC}"
    echo -e "Most common version: ${BOLD}$most_common${NC} (found in ${version_counts[$most_common]} files)\n"
    
    # Check each file
    for file in "${!version_files[@]}"; do
        local version="${version_files[$file]}"
        
        if [[ "$version" == "$most_common" ]]; then
            echo -e "  ${GREEN}✅${NC} $file: ${GREEN}$version${NC}"
            ((matched_files++))
        else
            echo -e "  ${RED}❌${NC} $file: ${RED}$version${NC} (expected: $most_common)"
            ((mismatched_files++))
            all_match=false
        fi
    done
    
    print_summary "$total_files" "$matched_files" "$mismatched_files"
    
    if [[ "$all_match" == true ]]; then
        echo -e "\n${GREEN}✅ All versions match!${NC}"
        return 0
    else
        echo -e "\n${RED}❌ Version mismatch detected!${NC}"
        
        # Show version distribution
        echo -e "\n${BOLD}Version distribution:${NC}"
        for version in "${versions_found[@]}"; do
            echo -e "  $version: ${version_counts[$version]} files"
        done
        
        # Offer to fix if --fix flag is provided
        if [[ "$FIX_MODE" == true ]]; then
            echo -e "\n${YELLOW}Would you like to update all versions to ${BOLD}$most_common${NC}${YELLOW}?${NC}"
            echo -n "Type 'yes' to proceed: "
            read -r response
            
            if [[ "$response" == "yes" ]]; then
                local update_script="$SCRIPT_DIR/update-version.sh"
                if [[ -x "$update_script" ]]; then
                    echo -e "\n${BLUE}Running update-version.sh with version $most_common...${NC}"
                    "$update_script" "$most_common"
                    
                    # Re-validate after update
                    echo -e "\n${BLUE}Re-validating versions...${NC}"
                    # Clear arrays for re-validation
                    version_files=()
                    version_counts=()
                    versions_found=()
                    
                    # Re-run extraction
                    extract_cargo_versions
                    extract_package_json_versions
                    extract_readme_version
                    extract_other_versions
                    
                    # Check if all match now
                    local new_most_common=$(find_most_common_version)
                    local still_mismatch=false
                    
                    for file in "${!version_files[@]}"; do
                        if [[ "${version_files[$file]}" != "$new_most_common" ]]; then
                            still_mismatch=true
                            break
                        fi
                    done
                    
                    if [[ "$still_mismatch" == false ]]; then
                        echo -e "\n${GREEN}✅ All versions now match!${NC}"
                        return 0
                    else
                        echo -e "\n${RED}Some versions still don't match. Manual intervention may be required.${NC}"
                        return 1
                    fi
                else
                    echo -e "${RED}Error: update-version.sh not found or not executable${NC}"
                    return 1
                fi
            else
                echo -e "${YELLOW}Fix cancelled.${NC}"
                return 1
            fi
        else
            echo -e "\n${YELLOW}Tip: Run with --fix flag to automatically update versions${NC}"
            return 1
        fi
    fi
}

# Main execution
main() {
    print_header
    
    # Extract versions from all sources
    extract_cargo_versions
    extract_package_json_versions
    extract_readme_version
    extract_other_versions
    
    # Check if any versions were found
    if [[ ${#version_files[@]} -eq 0 ]]; then
        echo -e "${RED}Error: No version information found in any files${NC}"
        echo -e "${YELLOW}Make sure you're running this script from the KindlyGuard project root${NC}"
        exit 1
    fi
    
    # Validate versions
    if validate_versions; then
        exit 0
    else
        exit 1
    fi
}

# Run main function
main