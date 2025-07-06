#!/bin/bash
set -e

# Build script for KindlyGuard using cross for cross-compilation
# This builds all targets for release

echo "🚀 Building KindlyGuard for all targets using cross..."

# Define targets
TARGETS=(
    "x86_64-unknown-linux-gnu"
    "x86_64-pc-windows-gnu"
    "aarch64-unknown-linux-gnu"
    "x86_64-apple-darwin"
    "aarch64-apple-darwin"
)

# Binary names to build
BINARIES=(
    "kindly-guard-server"
    "kindly-guard-shield" 
    "kindly-tools"
)

# Create output directory
OUTPUT_DIR="target/release-binaries"
mkdir -p "$OUTPUT_DIR"

# Function to check if we should use cross
should_use_cross() {
    local target=$1
    local host_target=$(rustc -vV | sed -n 's/host: \(.*\)/\1/p')
    
    # Use cross for all non-host targets
    if [ "$target" != "$host_target" ]; then
        return 0
    else
        return 1
    fi
}

# Build each target
for target in "${TARGETS[@]}"; do
    echo ""
    echo "📦 Building for $target..."
    
    # Determine build command
    if should_use_cross "$target"; then
        BUILD_CMD="cross"
        echo "  Using cross for cross-compilation"
    else
        BUILD_CMD="cargo"
        echo "  Using cargo for native compilation"
    fi
    
    # Check if target is installed
    if ! rustup target list --installed | grep -q "$target"; then
        echo "  Installing target $target..."
        rustup target add "$target"
    fi
    
    # Build each binary
    for binary_pkg in "${BINARIES[@]}"; do
        echo "  Building $binary_pkg..."
        
        # Determine actual binary name
        case "$binary_pkg" in
            "kindly-guard-server")
                BINARY_NAME="kindly-guard-server"
                ;;
            "kindly-guard-shield")
                BINARY_NAME="kindly-guard-shield"
                ;;
            "kindly-tools")
                BINARY_NAME="kindly-tools"
                ;;
        esac
        
        # Build the binary
        if $BUILD_CMD build --target "$target" --release --package "$binary_pkg" --bin "$BINARY_NAME"; then
            # Determine file extension based on target
            if [[ "$target" == *"windows"* ]]; then
                EXT=".exe"
            else
                EXT=""
            fi
            
            # Copy to output directory with target suffix
            SRC="target/$target/release/$BINARY_NAME$EXT"
            DST="$OUTPUT_DIR/${BINARY_NAME}-${target}$EXT"
            
            if [ -f "$SRC" ]; then
                cp "$SRC" "$DST"
                echo "  ✅ Copied $BINARY_NAME to $DST"
                
                # Make executable on Unix targets
                if [[ "$target" != *"windows"* ]]; then
                    chmod +x "$DST"
                fi
            else
                echo "  ⚠️  Warning: Binary not found at $SRC"
            fi
        else
            echo "  ❌ Failed to build $binary_pkg for $target"
        fi
    done
done

echo ""
echo "✨ Build complete! Binaries are in $OUTPUT_DIR"
echo ""
echo "Available binaries:"
ls -la "$OUTPUT_DIR"