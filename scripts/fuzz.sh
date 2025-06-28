#!/bin/bash
set -e

# KindlyGuard Fuzzing Script
# This script manages fuzzing operations for security testing

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
FUZZ_DIR="$PROJECT_ROOT/fuzz"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
FUZZ_TARGET=""
FUZZ_TIME="3600" # 1 hour default
FUZZ_JOBS="$(nproc)"
CORPUS_DIR=""

usage() {
    echo -e "${BLUE}KindlyGuard Fuzzing Tool${NC}"
    echo ""
    echo "Usage: $0 [command] [options]"
    echo ""
    echo "Commands:"
    echo "  list                    List all available fuzz targets"
    echo "  run <target>           Run a specific fuzz target"
    echo "  run-all                Run all fuzz targets sequentially"
    echo "  corpus <target>        Show corpus information for a target"
    echo "  clean                  Clean all fuzzing artifacts"
    echo ""
    echo "Options:"
    echo "  -t, --time <seconds>   Fuzzing duration (default: 3600)"
    echo "  -j, --jobs <num>       Number of parallel jobs (default: $(nproc))"
    echo "  -c, --corpus <dir>     Custom corpus directory"
    echo "  -h, --help            Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 run fuzz_unicode_scanner -t 7200"
    echo "  $0 run-all -t 1800"
    echo "  $0 list"
}

list_targets() {
    echo -e "${BLUE}Available fuzz targets:${NC}"
    echo ""
    if [ -d "$FUZZ_DIR/fuzz_targets" ]; then
        for target in "$FUZZ_DIR/fuzz_targets"/*.rs; do
            if [ -f "$target" ]; then
                basename "$target" .rs
            fi
        done
    else
        echo -e "${RED}No fuzz targets found${NC}"
        exit 1
    fi
}

check_cargo_fuzz() {
    if ! command -v cargo-fuzz &> /dev/null; then
        echo -e "${YELLOW}cargo-fuzz not found. Installing...${NC}"
        cargo install cargo-fuzz
    fi
}

run_fuzz_target() {
    local target="$1"
    
    echo -e "${BLUE}Running fuzz target: $target${NC}"
    echo -e "Duration: ${FUZZ_TIME}s | Jobs: ${FUZZ_JOBS}"
    echo ""
    
    cd "$FUZZ_DIR"
    
    # Set up corpus directory
    if [ -z "$CORPUS_DIR" ]; then
        CORPUS_DIR="$FUZZ_DIR/corpus/$target"
    fi
    
    # Create corpus directory if it doesn't exist
    mkdir -p "$CORPUS_DIR"
    
    # Run fuzzing
    RUST_BACKTRACE=1 cargo +nightly fuzz run "$target" \
        -- -max_total_time="$FUZZ_TIME" \
        -jobs="$FUZZ_JOBS" \
        -print_final_stats=1 \
        "$CORPUS_DIR"
    
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "\n${GREEN}Fuzzing completed successfully${NC}"
    else
        echo -e "\n${RED}Fuzzing found issues (exit code: $exit_code)${NC}"
        
        # Check for crash files
        local crash_dir="$FUZZ_DIR/artifacts/$target"
        if [ -d "$crash_dir" ] && [ "$(ls -A "$crash_dir" 2>/dev/null)" ]; then
            echo -e "${YELLOW}Crash files found in: $crash_dir${NC}"
            echo "To reproduce a crash:"
            echo "  cd $FUZZ_DIR && cargo +nightly fuzz run $target $crash_dir/<crash-file>"
        fi
    fi
    
    return $exit_code
}

run_all_targets() {
    echo -e "${BLUE}Running all fuzz targets${NC}"
    echo ""
    
    local failed_targets=()
    local passed_targets=()
    
    for target_file in "$FUZZ_DIR/fuzz_targets"/*.rs; do
        if [ -f "$target_file" ]; then
            local target=$(basename "$target_file" .rs)
            
            echo -e "\n${YELLOW}[$target]${NC}"
            if run_fuzz_target "$target"; then
                passed_targets+=("$target")
            else
                failed_targets+=("$target")
            fi
        fi
    done
    
    echo -e "\n${BLUE}=== Fuzzing Summary ===${NC}"
    echo -e "${GREEN}Passed: ${#passed_targets[@]}${NC}"
    for target in "${passed_targets[@]}"; do
        echo -e "  ✓ $target"
    done
    
    if [ ${#failed_targets[@]} -gt 0 ]; then
        echo -e "${RED}Failed: ${#failed_targets[@]}${NC}"
        for target in "${failed_targets[@]}"; do
            echo -e "  ✗ $target"
        done
        exit 1
    fi
}

show_corpus_info() {
    local target="$1"
    local corpus_path="$FUZZ_DIR/corpus/$target"
    
    echo -e "${BLUE}Corpus information for: $target${NC}"
    echo "Path: $corpus_path"
    
    if [ -d "$corpus_path" ]; then
        local count=$(find "$corpus_path" -type f | wc -l)
        local size=$(du -sh "$corpus_path" | cut -f1)
        echo "Files: $count"
        echo "Size: $size"
    else
        echo -e "${YELLOW}No corpus found${NC}"
    fi
    
    local artifacts_path="$FUZZ_DIR/artifacts/$target"
    if [ -d "$artifacts_path" ] && [ "$(ls -A "$artifacts_path" 2>/dev/null)" ]; then
        echo -e "\n${RED}Crash artifacts found:${NC}"
        ls -la "$artifacts_path"
    fi
}

clean_fuzzing() {
    echo -e "${YELLOW}Cleaning fuzzing artifacts...${NC}"
    
    rm -rf "$FUZZ_DIR/corpus"
    rm -rf "$FUZZ_DIR/artifacts"
    rm -rf "$FUZZ_DIR/target"
    
    echo -e "${GREEN}Cleaned successfully${NC}"
}

# Parse command line arguments
COMMAND=""
while [[ $# -gt 0 ]]; do
    case $1 in
        list|run|run-all|corpus|clean)
            COMMAND="$1"
            if [[ "$1" == "run" || "$1" == "corpus" ]]; then
                shift
                FUZZ_TARGET="$1"
            fi
            ;;
        -t|--time)
            shift
            FUZZ_TIME="$1"
            ;;
        -j|--jobs)
            shift
            FUZZ_JOBS="$1"
            ;;
        -c|--corpus)
            shift
            CORPUS_DIR="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            usage
            exit 1
            ;;
    esac
    shift
done

# Execute command
case $COMMAND in
    list)
        list_targets
        ;;
    run)
        if [ -z "$FUZZ_TARGET" ]; then
            echo -e "${RED}Error: No target specified${NC}"
            usage
            exit 1
        fi
        check_cargo_fuzz
        run_fuzz_target "$FUZZ_TARGET"
        ;;
    run-all)
        check_cargo_fuzz
        run_all_targets
        ;;
    corpus)
        if [ -z "$FUZZ_TARGET" ]; then
            echo -e "${RED}Error: No target specified${NC}"
            usage
            exit 1
        fi
        show_corpus_info "$FUZZ_TARGET"
        ;;
    clean)
        clean_fuzzing
        ;;
    *)
        echo -e "${RED}Error: No command specified${NC}"
        usage
        exit 1
        ;;
esac