#!/bin/bash
set -e

echo "🚀 KindlyGuard Release 0.9.1"
echo "=========================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check version is correct
VERSION="0.9.1"
CARGO_VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)

if [ "$CARGO_VERSION" != "$VERSION" ]; then
    echo -e "${RED}❌ Error: Cargo.toml version ($CARGO_VERSION) doesn't match expected version ($VERSION)${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Version check passed: $VERSION${NC}"
echo ""

# Function to run a step
run_step() {
    local step_name=$1
    local command=$2
    
    echo -e "${YELLOW}🔧 $step_name...${NC}"
    if eval "$command"; then
        echo -e "${GREEN}✅ $step_name completed${NC}"
    else
        echo -e "${RED}❌ $step_name failed${NC}"
        return 1
    fi
    echo ""
}

# 1. Build all binaries
echo "📦 Phase 1: Building Binaries"
echo "============================="
run_step "Building release binaries" "cargo build --release --all"

# 2. Run tests
echo "🧪 Phase 2: Running Tests"
echo "========================"
run_step "Running unit tests" "cargo test --release"

# 3. Package crates.io releases
echo "📦 Phase 3: Crates.io Packages"
echo "=============================="
run_step "Building kindlyguard placeholder" "cd crates-io-package/kindlyguard && cargo build --release && cd ../.."
run_step "Building kindly-guard-server" "cd kindly-guard-server && cargo build --release && cd .."
run_step "Building kindly-guard-cli" "cd kindly-guard-cli && cargo build --release && cd .."

# 4. Package NPM releases
echo "📦 Phase 4: NPM Packages"
echo "======================="
run_step "Building NPM package" "cd npm-package && npm run build && cd .."

# Copy binaries to NPM packages
echo "📋 Copying binaries to platform packages..."
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    cp target/release/kindlyguard npm-package/npm/linux-x64/
    cp target/release/kindlyguard-cli npm-package/npm/linux-x64/
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ $(uname -m) == "arm64" ]]; then
        cp target/release/kindlyguard npm-package/npm/kindlyguard-darwin-arm64/
        cp target/release/kindlyguard-cli npm-package/npm/kindlyguard-darwin-arm64/
    else
        cp target/release/kindlyguard npm-package/npm/kindlyguard-darwin-x64/
        cp target/release/kindlyguard-cli npm-package/npm/kindlyguard-darwin-x64/
    fi
fi

# 5. Docker images
echo "🐳 Phase 5: Docker Images"
echo "========================"
if command -v docker &> /dev/null && docker buildx version &> /dev/null; then
    run_step "Building multi-platform Docker images" "./scripts/build-docker-multiplatform.sh --platforms linux/amd64,linux/arm64"
else
    echo -e "${YELLOW}⚠️  Docker buildx not available. Run ./scripts/install-docker-buildx.sh first${NC}"
fi

# 6. Create release artifacts
echo "📦 Phase 6: Creating Release Artifacts"
echo "====================================="
mkdir -p release-artifacts/0.9.1

# Binary archives
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    tar -czf release-artifacts/0.9.1/kindlyguard-$VERSION-linux-x64.tar.gz \
        -C target/release kindlyguard kindlyguard-cli
elif [[ "$OSTYPE" == "darwin"* ]]; then
    if [[ $(uname -m) == "arm64" ]]; then
        tar -czf release-artifacts/0.9.1/kindlyguard-$VERSION-darwin-arm64.tar.gz \
            -C target/release kindlyguard kindlyguard-cli
    else
        tar -czf release-artifacts/0.9.1/kindlyguard-$VERSION-darwin-x64.tar.gz \
            -C target/release kindlyguard kindlyguard-cli
    fi
fi

# Generate checksums
cd release-artifacts/0.9.1
shasum -a 256 *.tar.gz > checksums.txt
cd ../..

echo ""
echo "🎉 Release 0.9.1 Preparation Complete!"
echo "===================================="
echo ""
echo "📋 Next Steps:"
echo "1. Review the release artifacts in release-artifacts/0.9.1/"
echo "2. Test the packages locally"
echo "3. When ready to publish:"
echo "   - Crates.io: ./scripts/publish-crates.sh"
echo "   - NPM: ./scripts/publish-npm.sh"
echo "   - Docker: ./scripts/publish-docker.sh"
echo "   - Or all at once: ./scripts/publish-all.sh"
echo ""
echo "📦 Release Contents:"
echo "- Version: $VERSION"
echo "- Crates: kindlyguard, kindly-guard-server, kindly-guard-cli"
echo "- NPM: @kindlyguard/kindlyguard with platform packages"
echo "- Docker: kindlysoftware/kindly-guard:$VERSION"
echo ""