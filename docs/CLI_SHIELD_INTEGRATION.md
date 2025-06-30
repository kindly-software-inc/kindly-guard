# KindlyGuard CLI Shield Integration

KindlyGuard provides always-on security monitoring directly in your terminal, seamlessly integrating into modern development workflows.

## Overview

The CLI Shield integration displays real-time security status in your terminal prompt, showing:
- 🛡️ Protection status (active/inactive)
- ⚡ Number of threats blocked
- ⏱ Uptime duration
- Last threat type detected

## Installation

1. **Install the CLI tool:**
```bash
cargo install --path kindly-guard-cli
```

2. **Add to your shell configuration:**

For **Bash** (~/.bashrc):
```bash
eval "$(kindly-guard shell-init bash)"
```

For **Zsh** (~/.zshrc):
```zsh
eval "$(kindly-guard shell-init zsh)"
```

For **Fish** (~/.config/fish/config.fish):
```fish
kindly-guard shell-init fish | source
```

3. **Restart your terminal** or source your config file.

## Display Formats

### Compact Format (Default)
Shows full status in your prompt:
```
[🛡️ KindlyGuard: ✓ Protected | ⚡ 42 blocked | ⏱ 2h15m]
```

### Minimal Format
Just the shield icon and threat count:
```
🛡️⚡42
```

### Status Bar Format
For tmux/screen integration:
```
🛡️ SQL Injection ⚡42
```

## CLI Commands

### Shield Status
```bash
# Get current shield status
kindly-guard shield status

# Different formats
kindly-guard shield status --format compact
kindly-guard shield status --format minimal
kindly-guard shield status --format json
```

### Shield Control
```bash
# Start shield protection
kindly-guard shield start

# Start in background
kindly-guard shield start --background

# Stop shield
kindly-guard shield stop
```

### Shell Integration
```bash
# Generate shell init script
kindly-guard shell-init bash
kindly-guard shell-init zsh
kindly-guard shell-init fish
```

## Integration Options

### 1. Prompt Integration (Recommended)
Adds shield status above your prompt:
```
[🛡️ KindlyGuard: ✓ Protected | ⚡ 3 blocked | ⏱ 45m]
user@host:~/project$
```

### 2. Right Prompt (Zsh)
Add to ~/.zshrc:
```zsh
RPROMPT='$(kindly-guard shield status --format minimal)'
```

### 3. Tmux Status Bar
Add to ~/.tmux.conf:
```tmux
set -g status-right '#(kindly-guard shield status --format status-bar)'
```

### 4. Terminal Title
Add to your shell config:
```bash
# Bash
PS1="\[\e]0;\$(kindly-guard shield status --format minimal)\a\]$PS1"
```

## How It Works

1. **Pre-Command Hook**: Records when commands start
2. **Post-Command Hook**: Updates shield after commands
3. **Prompt Command**: Displays current status
4. **Background Service**: Monitors for threats continuously

## Customization

### Environment Variables
```bash
# Disable shield display temporarily
export KINDLY_GUARD_SHIELD_ENABLED=false

# Change update interval (milliseconds)
export KINDLY_GUARD_UPDATE_INTERVAL=500

# Disable colors
export KINDLY_GUARD_NO_COLOR=1
```

### Custom Format
Create a custom display function:
```bash
_my_shield_status() {
    local status=$(kindly-guard shield status --format json)
    # Parse and format as needed
    echo "🛡️ Custom: ..."
}
```

## Performance

The shield integration is designed to be lightweight:
- Sub-millisecond status checks
- No blocking operations
- Cached status for prompt display
- Async background updates

## Troubleshooting

### Shield not appearing
1. Check installation: `which kindly-guard`
2. Test manually: `kindly-guard shield status`
3. Check shell hooks: `type _kindly_guard_prompt`

### Performance issues
1. Increase update interval
2. Use minimal format
3. Disable in large repositories

### Compatibility
- Works with most terminal emulators
- Compatible with tmux/screen
- Supports SSH sessions
- Works in VS Code terminal

## Example Configurations

### Minimal Setup (Bash)
```bash
# ~/.bashrc
eval "$(kindly-guard shell-init bash)"
export KINDLY_GUARD_UPDATE_INTERVAL=2000
```

### Advanced Setup (Zsh with Powerlevel10k)
```zsh
# ~/.zshrc
eval "$(kindly-guard shell-init zsh)"

# Custom segment for Powerlevel10k
function prompt_kindly_guard() {
    local status=$(kindly-guard shield status --format minimal)
    [[ -n $status ]] && p10k segment -f 33 -t "$status"
}
```

### Development Environment
```bash
# Only enable in specific directories
_kindly_guard_check_dir() {
    if [[ "$PWD" =~ "projects" ]]; then
        kindly-guard shield start --background
    fi
}
cd() { builtin cd "$@" && _kindly_guard_check_dir; }
```

## Security Benefits

1. **Real-time Awareness**: Always know your security status
2. **Threat Visibility**: See threats as they're blocked
3. **Command Context**: Protection during command execution
4. **Audit Trail**: Track security events over time

## FAQ

**Q: Does this slow down my terminal?**
A: No, status checks are cached and async.

**Q: Can I use this over SSH?**
A: Yes, install KindlyGuard on the remote machine.

**Q: Does it work with my prompt theme?**
A: Yes, it adds a line above your existing prompt.

**Q: Can I disable it temporarily?**
A: Yes, use `export KINDLY_GUARD_SHIELD_ENABLED=false`