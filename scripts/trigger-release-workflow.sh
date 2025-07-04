#!/bin/bash
set -e

# Trigger GitHub Release Workflow
# This script helps trigger the automated release workflow

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 --version <version>"
            echo ""
            echo "Triggers the GitHub Actions release workflow"
            echo ""
            echo "Options:"
            echo "  --version <version>    Version to release (required)"
            echo ""
            echo "Example:"
            echo "  $0 --version 0.9.2"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Validate inputs
if [ -z "$VERSION" ]; then
    echo -e "${RED}❌ Error: Version is required. Use --version <version>${NC}"
    exit 1
fi

echo -e "${BLUE}🚀 Triggering Release Workflow for v${VERSION}${NC}"
echo "==========================================="
echo ""

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ Error: GitHub CLI (gh) is not installed${NC}"
    echo "Install it from: https://cli.github.com/"
    exit 1
fi

# Check authentication
if ! gh auth status &> /dev/null; then
    echo -e "${RED}❌ Error: Not authenticated with GitHub${NC}"
    echo "Run: gh auth login"
    exit 1
fi

# Get repository info
REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || echo "")
if [ -z "$REPO" ]; then
    echo -e "${YELLOW}⚠️  Could not detect repository. Using default...${NC}"
    REPO="kindlysoftware/kindlyguard"
fi

echo -e "${BLUE}📋 Release Configuration:${NC}"
echo "  Repository: $REPO"
echo "  Version: $VERSION"
echo "  Workflow: create-release.yml"
echo ""

# Confirm before proceeding
echo -n "Do you want to trigger the release workflow? (y/N) "
read -r response
if [[ ! "$response" =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# Trigger the workflow
echo -e "${YELLOW}🔧 Triggering workflow...${NC}"
if gh workflow run create-release.yml \
    -R "$REPO" \
    -f version="$VERSION" \
    -f draft=false \
    -f prerelease=false; then
    echo -e "${GREEN}✅ Workflow triggered successfully!${NC}"
else
    echo -e "${RED}❌ Failed to trigger workflow${NC}"
    exit 1
fi

# Get workflow run URL
echo ""
echo -e "${YELLOW}⏳ Waiting for workflow to start...${NC}"
sleep 5

# Try to get the latest run
LATEST_RUN=$(gh run list \
    -R "$REPO" \
    --workflow=create-release.yml \
    --limit=1 \
    --json url,status,conclusion \
    -q '.[0]' 2>/dev/null || echo "{}")

if [ "$LATEST_RUN" != "{}" ]; then
    RUN_URL=$(echo "$LATEST_RUN" | jq -r .url)
    RUN_STATUS=$(echo "$LATEST_RUN" | jq -r .status)
    
    echo -e "${GREEN}✅ Workflow started!${NC}"
    echo "  URL: $RUN_URL"
    echo "  Status: $RUN_STATUS"
else
    echo -e "${YELLOW}⚠️  Could not fetch workflow status${NC}"
fi

echo ""
echo -e "${BLUE}📋 Next Steps:${NC}"
echo "  1. Monitor the workflow at: https://github.com/$REPO/actions"
echo "  2. Once complete, check the release at: https://github.com/$REPO/releases"
echo "  3. Test the binary downloads"
echo "  4. Publish to package registries if needed"
echo ""

# Option to watch the workflow
echo -n "Do you want to watch the workflow progress? (y/N) "
read -r watch_response
if [[ "$watch_response" =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}⏳ Watching workflow (press Ctrl+C to stop)...${NC}"
    gh run watch -R "$REPO" --exit-status
fi