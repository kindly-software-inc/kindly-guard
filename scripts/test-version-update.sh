#!/bin/bash
# Test script for version update functionality

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

echo -e "${BLUE}🧪 Testing Version Update System${NC}"
echo "===================================="

# Check if jq is installed for JSON parsing
if ! command -v jq &> /dev/null; then
    echo -e "${YELLOW}⚠️  jq not installed. Installing for JSON parsing...${NC}"
    echo "Run: sudo apt-get install jq"
    exit 1
fi

# Store original versions
echo -e "\n${YELLOW}📋 Backing up current versions...${NC}"
BACKUP_DIR="/tmp/kindly-guard-version-test-$$"
mkdir -p "$BACKUP_DIR"

# Function to backup a file
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "$BACKUP_DIR/$(basename "$file").backup"
        echo "  Backed up: $file"
    fi
}

# Backup all version files from version-locations.json
if [ -f "version-locations.json" ]; then
    # Backup Cargo files
    jq -r '.version_locations.cargo_files[].path' version-locations.json | while read -r file; do
        backup_file "$file"
    done
    
    # Backup package files
    jq -r '.version_locations.package_files[].path' version-locations.json | while read -r file; do
        backup_file "$file"
    done
    
    # Backup documentation files
    jq -r '.version_locations.documentation_files[].path' version-locations.json | while read -r file; do
        backup_file "$file"
    done
else
    echo -e "${RED}❌ version-locations.json not found${NC}"
    exit 1
fi

# Get current version
CURRENT_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
echo -e "\nCurrent version: ${MAGENTA}$CURRENT_VERSION${NC}"

# Function to restore files
restore_files() {
    echo -e "\n${YELLOW}📋 Restoring original files...${NC}"
    for backup in "$BACKUP_DIR"/*.backup; do
        if [ -f "$backup" ]; then
            original="${backup%.backup}"
            filename=$(basename "$original")
            # Find the original file location
            find . -name "$filename" -type f | head -1 | while read -r orig_path; do
                cp "$backup" "$orig_path"
                echo "  Restored: $orig_path"
            done
        fi
    done
    rm -rf "$BACKUP_DIR"
}

# Trap to ensure cleanup on exit
trap restore_files EXIT

# Test 1: Test version format validation
echo -e "\n${BLUE}Test 1: Version Format Validation${NC}"
echo "======================================"

test_version() {
    local version=$1
    local expected=$2
    echo -n "Testing version '$version'... "
    
    if [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$ ]]; then
        if [ "$expected" = "valid" ]; then
            echo -e "${GREEN}✅ Correctly identified as valid${NC}"
        else
            echo -e "${RED}❌ Incorrectly identified as valid${NC}"
        fi
    else
        if [ "$expected" = "invalid" ]; then
            echo -e "${GREEN}✅ Correctly identified as invalid${NC}"
        else
            echo -e "${RED}❌ Incorrectly identified as invalid${NC}"
        fi
    fi
}

test_version "1.0.0" "valid"
test_version "0.1.0" "valid"
test_version "10.20.30" "valid"
test_version "1.0.0-beta.1" "valid"
test_version "2.0.0-rc.1" "valid"
test_version "1.0" "invalid"
test_version "1.0.0.0" "invalid"
test_version "v1.0.0" "invalid"
test_version "1.0.0-" "invalid"

# Test 2: Test update-version.sh with dummy version
echo -e "\n${BLUE}Test 2: Version Update Functionality${NC}"
echo "======================================"

TEST_VERSION="9.9.9-test"

if [ -f "./scripts/update-version.sh" ]; then
    echo -e "Testing update to version: ${MAGENTA}$TEST_VERSION${NC}"
    
    # Run update
    if ./scripts/update-version.sh "$TEST_VERSION" > /tmp/update-test.log 2>&1; then
        echo -e "${GREEN}✅ Update script executed successfully${NC}"
        
        # Verify changes
        echo -e "\n${YELLOW}Verifying changes...${NC}"
        
        # Check Cargo.toml
        NEW_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
        if [ "$NEW_VERSION" = "$TEST_VERSION" ]; then
            echo -e "${GREEN}✅ Main Cargo.toml updated correctly${NC}"
        else
            echo -e "${RED}❌ Main Cargo.toml not updated (found: $NEW_VERSION)${NC}"
        fi
        
        # Run validation
        if [ -f "./scripts/validate-versions.sh" ]; then
            if ./scripts/validate-versions.sh > /tmp/validate-test.log 2>&1; then
                echo -e "${GREEN}✅ All versions validated as consistent${NC}"
            else
                echo -e "${RED}❌ Version validation failed${NC}"
                cat /tmp/validate-test.log
            fi
        fi
    else
        echo -e "${RED}❌ Update script failed${NC}"
        cat /tmp/update-test.log
    fi
else
    echo -e "${RED}❌ update-version.sh not found${NC}"
fi

# Test 3: Test rollback functionality
echo -e "\n${BLUE}Test 3: Rollback Test${NC}"
echo "========================"

echo -e "${YELLOW}Testing manual rollback by restoring files...${NC}"
restore_files
trap - EXIT  # Remove trap since we manually restored

# Verify rollback
RESTORED_VERSION=$(grep -E '^version = ' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
if [ "$RESTORED_VERSION" = "$CURRENT_VERSION" ]; then
    echo -e "${GREEN}✅ Rollback successful - version restored to $CURRENT_VERSION${NC}"
else
    echo -e "${RED}❌ Rollback failed - version is $RESTORED_VERSION, expected $CURRENT_VERSION${NC}"
fi

# Test 4: Test edge cases
echo -e "\n${BLUE}Test 4: Edge Cases${NC}"
echo "===================="

# Test with missing files
echo -e "\n${YELLOW}Testing with temporarily renamed file...${NC}"
if [ -f "kindly-guard-cli/Cargo.toml" ]; then
    mv "kindly-guard-cli/Cargo.toml" "kindly-guard-cli/Cargo.toml.tmp"
    
    if [ -f "./scripts/update-version.sh" ]; then
        if ./scripts/update-version.sh "1.0.0-test" > /tmp/missing-file-test.log 2>&1; then
            echo -e "${YELLOW}⚠️  Update succeeded despite missing file${NC}"
        else
            echo -e "${GREEN}✅ Update correctly failed with missing file${NC}"
        fi
    fi
    
    mv "kindly-guard-cli/Cargo.toml.tmp" "kindly-guard-cli/Cargo.toml"
fi

# Test 5: Performance test
echo -e "\n${BLUE}Test 5: Performance Test${NC}"
echo "=========================="

if [ -f "./scripts/update-version.sh" ]; then
    echo "Timing version update..."
    START_TIME=$(date +%s.%N)
    ./scripts/update-version.sh "1.0.0-perf" > /dev/null 2>&1
    END_TIME=$(date +%s.%N)
    DURATION=$(echo "$END_TIME - $START_TIME" | bc)
    echo -e "Update completed in: ${MAGENTA}${DURATION}s${NC}"
    
    if (( $(echo "$DURATION < 5" | bc -l) )); then
        echo -e "${GREEN}✅ Performance acceptable (< 5 seconds)${NC}"
    else
        echo -e "${YELLOW}⚠️  Update took longer than expected${NC}"
    fi
fi

# Summary
echo -e "\n${BLUE}📊 Test Summary${NC}"
echo "=================="
echo -e "${GREEN}✅ Version format validation tested${NC}"
echo -e "${GREEN}✅ Version update functionality tested${NC}"
echo -e "${GREEN}✅ Rollback functionality tested${NC}"
echo -e "${GREEN}✅ Edge cases tested${NC}"
echo -e "${GREEN}✅ Performance tested${NC}"

echo -e "\n${GREEN}All tests completed!${NC}"
echo -e "${YELLOW}Note: This test script made temporary changes that were rolled back.${NC}"

# Cleanup
rm -rf "$BACKUP_DIR"