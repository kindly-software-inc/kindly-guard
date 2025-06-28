#!/bin/bash
# KindlyGuard Shell Integration for Bash
# Add this to your ~/.bashrc: eval "$(kindly-guard shell-init bash)"

# Check if kindly-guard is available
if ! command -v kindly-guard &> /dev/null; then
    return 0
fi

# KindlyGuard functions
_kindly_guard_pre_command() {
    kindly-guard shield pre-command 2>/dev/null || true
}

_kindly_guard_post_command() {
    kindly-guard shield post-command 2>/dev/null || true
}

_kindly_guard_prompt() {
    local status
    status="$(kindly-guard shield status --format=compact 2>/dev/null)"
    if [ -n "$status" ]; then
        echo -e "\033[1;34m${status}\033[0m"
    fi
}

# Set up command hooks
trap '_kindly_guard_pre_command' DEBUG

# Update PROMPT_COMMAND
if [ -z "$PROMPT_COMMAND" ]; then
    PROMPT_COMMAND="_kindly_guard_prompt; _kindly_guard_post_command"
else
    PROMPT_COMMAND="_kindly_guard_prompt; _kindly_guard_post_command; $PROMPT_COMMAND"
fi

# Optional: Add to PS1 for inline display
# PS1="\$(_kindly_guard_prompt)\n$PS1"

# Export functions
export -f _kindly_guard_pre_command
export -f _kindly_guard_post_command
export -f _kindly_guard_prompt

# Start shield if not running
kindly-guard shield start --background 2>/dev/null || true