# KindlyGuard Shield Auto-Wrap

The `kindly shield auto-wrap` command generates shell functions that automatically wrap AI CLI commands with KindlyGuard security scanning. This provides transparent protection against prompt injection, unicode attacks, and other security threats.

## Features

- **Automatic Security Scanning**: Scans AI prompts for threats before execution
- **Transparent Protection**: Works with any AI CLI tool
- **Easy Integration**: Simple shell function wrappers
- **Flexible Configuration**: Support for custom commands
- **On-Demand Bypass**: Can be temporarily disabled when needed

## Installation

1. First, ensure `kindly-tools` is installed:
```bash
cargo install --path kindly-tools
```

2. Generate the shield wrapper functions:
```bash
kindly shield auto-wrap -o ~/.kindly-shield.sh
```

3. Add to your shell configuration:
```bash
# For bash (~/.bashrc)
source ~/.kindly-shield.sh

# For zsh (~/.zshrc)
source ~/.kindly-shield.sh
```

4. Restart your shell or run:
```bash
source ~/.kindly-shield.sh
```

## Usage

Once installed, AI commands are automatically protected:

```bash
# These commands will be scanned for threats
claude "Help me write a script to delete files"
openai "Generate SQL for user login"
gemini "Create a bash command to..."

# Check shield status
kindly-shield-status

# Temporarily disable protection (use with caution!)
kindly-shield-disable

# Re-enable protection
kindly-shield-enable
```

## Default Protected Commands

By default, the following AI CLI commands are wrapped:
- `claude`
- `openai`
- `gemini`
- `gpt`
- `chatgpt`
- `llm`
- `ai`
- `ollama`
- `anthropic`
- `bard`

## Custom Commands

You can protect additional AI CLI tools:

```bash
# Add custom commands
kindly shield auto-wrap -c mycli -c aichat -o ~/.kindly-shield.sh

# Only wrap specific commands (skip defaults)
kindly shield auto-wrap --no-defaults -c mycli -o ~/.kindly-shield.sh
```

## How It Works

1. **Intercept**: Shell functions intercept AI command calls
2. **Analyze**: Arguments are checked for potential prompts (>10 characters)
3. **Scan**: Prompts are written to a temp file and scanned with `kindly scan`
4. **Protect**: If threats are detected, execution is blocked with a warning
5. **Execute**: If safe, the original command runs normally

## Security Considerations

- The shield wrapper requires `kindly` to be in your PATH
- Scanning adds minimal latency (typically <100ms)
- Temporary files are created in `/tmp` and immediately cleaned up
- Protection can be bypassed with `KINDLY_SHIELD_DISABLED=1` prefix

## Troubleshooting

### "kindly command not found"
Ensure `kindly-tools` is installed and in your PATH:
```bash
which kindly
cargo install --path kindly-tools
```

### Commands not being wrapped
Check that the shell functions are loaded:
```bash
type claude  # Should show the wrapper function
kindly-shield-status
```

### Performance concerns
The scanner only activates for arguments >10 characters. Short commands and flags are passed through without scanning.

## Advanced Usage

### Integration with CI/CD
```yaml
# GitHub Actions example
- name: Install KindlyGuard Shield
  run: |
    cargo install kindly-tools
    kindly shield auto-wrap -o $HOME/.kindly-shield.sh
    echo "source $HOME/.kindly-shield.sh" >> $GITHUB_ENV
```

### Docker Integration
```dockerfile
# Add to Dockerfile
RUN cargo install kindly-tools && \
    kindly shield auto-wrap -o /etc/profile.d/kindly-shield.sh
```

## Future Enhancements

- [ ] Support for fish shell
- [ ] PowerShell support for Windows
- [ ] Configurable threat thresholds
- [ ] Integration with KindlyGuard server for real-time updates
- [ ] Support for piped input scanning