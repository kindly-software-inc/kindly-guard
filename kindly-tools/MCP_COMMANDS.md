# MCP Commands for kindly-tools

The `kindly-tools mcp` command provides comprehensive management of MCP (Model Context Protocol) servers for KindlyGuard. This replaces the previous shell scripts (`install_mcp_server.sh` and `verify_mcp_setup.sh`) with a unified Rust implementation.

## Available Commands

### Setup
Install and configure the KindlyGuard MCP server:
```bash
kindly-tools mcp setup [OPTIONS]
```

Options:
- `-n, --non-interactive`: Skip interactive prompts and use defaults
- `-f, --force`: Force reinstall even if already set up

This command will:
1. Check for existing configuration
2. Optionally build the kindly-guard-server
3. Copy the binary to `~/.claude/mcp-servers/kindly-guard/`
4. Create a default configuration file
5. Update the MCP configuration (`~/.mcp.json`)

### Verify
Check that the MCP configuration is correct:
```bash
kindly-tools mcp verify [OPTIONS]
```

Options:
- `-v, --verbose`: Show detailed verification output

This command will:
1. Check if MCP configuration exists
2. Verify the server binary is present and executable
3. Test MCP protocol communication
4. Report any issues found

### Status
Show current MCP server status:
```bash
kindly-tools mcp status [OPTIONS]
```

Options:
- `-p, --processes`: Show running process information

### Start
Start the MCP server:
```bash
kindly-tools mcp start [OPTIONS]
```

Options:
- `-d, --daemon`: Run in background (daemon mode)

### Stop
Stop the MCP server:
```bash
kindly-tools mcp stop [OPTIONS]
```

Options:
- `-f, --force`: Force stop all instances (SIGKILL instead of SIGTERM)

### List
List all configured MCP servers:
```bash
kindly-tools mcp list
```

### Config
Manage MCP configuration:
```bash
kindly-tools mcp config [OPTIONS]
```

Options:
- `-f, --file <FILE>`: Load configuration from a custom file
- `-s, --show`: Display current configuration

Without options, opens the configuration in your default editor.

### Test
Test a specific MCP server connection:
```bash
kindly-tools mcp test <SERVER>
```

Example:
```bash
kindly-tools mcp test kindly-guard
```

## Usage Examples

### Initial Setup
```bash
# Interactive setup (recommended for first time)
kindly-tools mcp setup

# Non-interactive setup with defaults
kindly-tools mcp setup --non-interactive

# Force reinstall
kindly-tools mcp setup --force
```

### Daily Operations
```bash
# Check if everything is configured correctly
kindly-tools mcp verify

# See current status
kindly-tools mcp status

# Start the server in the background
kindly-tools mcp start --daemon

# Stop the server
kindly-tools mcp stop
```

### Troubleshooting
```bash
# Detailed verification
kindly-tools mcp verify --verbose

# Check running processes
kindly-tools mcp status --processes

# Test MCP protocol communication
kindly-tools mcp test kindly-guard

# View current configuration
kindly-tools mcp config --show
```

## Configuration Locations

- MCP Configuration: `~/.mcp.json` (or `~/.config/claude/mcp.json`)
- Server Binary: `~/.claude/mcp-servers/kindly-guard/kindly-guard`
- Server Config: `~/.claude/mcp-servers/kindly-guard/config.toml`

## Migration from Shell Scripts

If you were previously using the shell scripts, here's the command mapping:

| Old Script | New Command |
|------------|-------------|
| `./install_mcp_server.sh` | `kindly-tools mcp setup` |
| `./verify_mcp_setup.sh` | `kindly-tools mcp verify` |

The new commands provide the same functionality with additional features:
- Better error handling and recovery
- Interactive and non-interactive modes
- Process management (start/stop)
- Configuration management
- MCP protocol testing

## Notes

- After running `setup`, restart Claude Desktop to load the new MCP server
- The server will appear as 'kindly-guard' in Claude's MCP servers
- Use `RUST_LOG=debug` environment variable for detailed logging
- The tool automatically detects the correct MCP configuration path