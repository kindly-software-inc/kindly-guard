#!/usr/bin/fish
# KindlyGuard Shell Integration for Fish
# Add this to your ~/.config/fish/config.fish: kindly-guard shell-init fish | source

# Check if kindly-guard is available
if not command -v kindly-guard &> /dev/null
    exit 0
end

# KindlyGuard functions
function _kindly_guard_pre_command --on-event fish_preexec
    kindly-guard shield pre-command 2>/dev/null
end

function _kindly_guard_post_command --on-event fish_postexec
    kindly-guard shield post-command 2>/dev/null
end

function _kindly_guard_prompt
    set -l status (kindly-guard shield status --format=compact 2>/dev/null)
    if test -n "$status"
        echo -e "\033[1;34m$status\033[0m"
    end
end

# Update prompt
function fish_prompt
    _kindly_guard_prompt
    # Call the original prompt function if it exists
    if functions -q __fish_prompt_original
        __fish_prompt_original
    else
        echo -n (whoami)'@'(hostname) (pwd) '> '
    end
end

# Save original prompt if not already saved
if not functions -q __fish_prompt_original
    functions -c fish_prompt __fish_prompt_original
end

# Start shield if not running
kindly-guard shield start --background 2>/dev/null