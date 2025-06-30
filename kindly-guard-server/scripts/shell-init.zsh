#!/bin/zsh
# KindlyGuard Shell Integration for Zsh
# Add this to your ~/.zshrc: eval "$(kindly-guard shell-init zsh)"

# Check if kindly-guard is available
if ! command -v kindly-guard &> /dev/null; then
    return 0
fi

# Add /kindlyguard command alias
alias /kindlyguard='kindly-guard'

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

# Set up hooks
add-zsh-hook preexec _kindly_guard_pre_command
add-zsh-hook precmd _kindly_guard_post_command

# Update prompt
setopt PROMPT_SUBST
PROMPT=$'$(_kindly_guard_prompt)\n'$PROMPT

# Optional: For right-side prompt
# RPROMPT='$(kindly-guard shield status --format=minimal 2>/dev/null)'

# Start shield if not running
kindly-guard shield start --background 2>/dev/null || true