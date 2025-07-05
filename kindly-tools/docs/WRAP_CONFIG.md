# KindlyGuard Wrap Configuration

The wrap command now supports configuration files to customize auto-wrapping behavior for AI CLI tools.

## Configuration File Location

The configuration file is stored at: `~/.kindlyguard/wrap.toml`

## Configuration Options

### Basic Settings

- `enabled` (bool): Enable or disable auto-wrapping globally
- `mode` (string): Protection mode - either "warning" or "blocking"
  - `"warning"`: Shows threat warnings but allows execution
  - `"blocking"`: Prevents execution when threats are detected
- `server` (string): URL of the KindlyGuard server for threat detection
- `verbose` (bool): Show detailed threat information
- `log_sessions` (bool): Save wrapped session logs to disk
- `log_directory` (string, optional): Directory for session logs

### Command Lists

- `commands`: List of commands to auto-wrap (includes defaults like "claude", "openai", etc.)
- `custom_commands`: Additional user-defined commands to wrap

## Usage Examples

### Initialize Configuration

Create a default configuration file:

```bash
kindly-tools wrap --init
```

### Show Current Configuration

Display the current wrap configuration:

```bash
kindly-tools wrap --config
```

### Add a Custom Command

Add a new command to the wrap list:

```bash
kindly-tools wrap --add my-ai-tool
```

### Remove a Command

Remove a command from the wrap list:

```bash
kindly-tools wrap --remove gemini
```

### Run with Auto-Wrap

When configuration is enabled, just run any configured command normally:

```bash
claude "Help me write a script"
# KindlyGuard will automatically wrap and protect this command
```

### Override Configuration

Force wrap any command regardless of configuration:

```bash
kindly-tools wrap -- any-command --args
```

## Example Configuration

```toml
# Enable auto-wrapping
enabled = true

# Use blocking mode for maximum security
mode = "blocking"

# Local KindlyGuard server
server = "http://localhost:8080"

# Show detailed information
verbose = true

# Log all sessions
log_sessions = true
log_directory = "/home/user/.kindlyguard/logs"

# Default AI commands
commands = [
    "claude",
    "openai",
    "gemini",
    "anthropic",
    "gpt",
    "ai",
    "llm"
]

# Company-specific AI tools
custom_commands = [
    "company-llm",
    "internal-ai-cli"
]
```

## Security Modes

### Warning Mode
- Displays threat warnings to the user
- Allows the command to proceed
- Useful for monitoring and awareness

### Blocking Mode
- Prevents potentially dangerous input from reaching the AI
- Blocks execution when threats are detected
- Recommended for production environments

## Command Detection

The wrap configuration intelligently handles:
- Simple command names (e.g., `claude`)
- Full paths (e.g., `/usr/bin/claude`)
- Relative paths (e.g., `./claude`)

Only the basename is checked against the configuration list.