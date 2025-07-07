# KindlyGuard Multi-AI Tool MCP Setup Guide

KindlyGuard now supports automatic configuration for multiple AI tools and IDEs that implement the Model Context Protocol (MCP). This guide explains how to use the unified setup experience.

## Supported AI Tools

### MCP-Compatible Tools (✅ Full Support)
- **Claude Desktop** - Anthropic's desktop application
- **Claude Code** - Anthropic's code editor
- **Visual Studio Code** - Microsoft's popular IDE
- **Cursor** - AI-first code editor
- **Windsurf** - The flow state AI editor
- **Continue** - Open-source AI code assistant
- **Zed** - High-performance collaborative editor

### Non-MCP Tools (ℹ️ Detection Only)
- **Neovim** - Terminal-based editor (MCP support planned)
- **Codeium** - AI code completion
- **TabNine** - AI code completion
- **GitHub Copilot** - GitHub's AI pair programmer

## Quick Start

### 1. Install KindlyGuard

```bash
npm install -g kindlyguard
```

### 2. Run the Setup Command

```bash
kindlyguard mcp setup
```

This will:
1. Automatically detect all installed AI tools
2. Show which ones support MCP
3. Let you select which tools to configure
4. Write the appropriate configuration for each tool

### 3. Verify Configuration

```bash
kindlyguard mcp verify
```

This shows:
- Which AI tools are installed
- Which ones have KindlyGuard configured
- Whether the server can start successfully

## Multi-Tool Setup Process

### Interactive Selection

When multiple AI tools are detected, you'll see:

```
Multiple AI tools detected:

  [1] → Claude Desktop (MCP compatible)
  [2] → Claude Code (MCP compatible)
  [3] → Visual Studio Code (MCP compatible)
  [4] → Cursor (MCP compatible)
  [5] → Windsurf (MCP compatible)
  [6] → GitHub Copilot (not MCP compatible)

Select AI tools to configure:
  • Enter numbers separated by commas (e.g., 1,3,4)
  • Enter 'all' to configure all MCP-compatible tools
  • Press Enter to configure all detected tools
Selection: 
```

### Selection Options

1. **Individual Selection**: `1,3,5` - Configure specific tools
2. **All Compatible**: `all` or press Enter - Configure all MCP-compatible tools
3. **Skip Non-Compatible**: Non-MCP tools are automatically skipped

### Configuration Process

For each selected tool, KindlyGuard will:

1. Show a preview of the configuration
2. Ask for confirmation
3. Create a backup if updating existing config
4. Write the configuration
5. Show tool-specific next steps

## Configuration Locations

### Claude Desktop
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/claude/claude_desktop_config.json`

### Claude Code
- **All platforms**: `~/.mcp.json`
- **Local override**: `~/.mcp.json.local`

### VS Code
- **Windows**: `%APPDATA%\Code\User\mcp.json`
- **macOS**: `~/Library/Application Support/Code/User/mcp.json`
- **Linux**: `~/.config/Code/User/mcp.json`

### Cursor
- **Windows**: `%APPDATA%\Cursor\User\mcp.json`
- **macOS**: `~/Library/Application Support/Cursor/User/mcp.json`
- **Linux**: `~/.config/Cursor/User/mcp.json`

### Windsurf
- **Windows**: `%APPDATA%\Windsurf\User\settings.local.json`
- **macOS**: `~/Library/Application Support/Windsurf/User/settings.local.json`
- **Linux**: `~/.config/Windsurf/User/settings.local.json`

### Continue
- **All platforms**: `~/.continue/mcp.json`

### Zed
- **Windows**: `%APPDATA%\Zed\mcp.json`
- **macOS**: `~/Library/Application Support/Zed/mcp.json`
- **Linux**: `~/.config/zed/mcp.json`

## MCP Commands

### Status Command

View the status of all AI tools:

```bash
kindlyguard mcp status
```

Output example:
```
🤖 AI Tool Status:

  🤖 Claude Desktop - ✅ Configured
     📍 /Users/you/Library/Application Support/Claude/claude_desktop_config.json
  💻 Claude Code - ✅ Configured
     📍 /Users/you/.mcp.json
  📝 Visual Studio Code - ⚠️  Detected
     📍 /Users/you/Library/Application Support/Code/User/mcp.json
  🎯 Cursor - Not installed
  🌊 Windsurf - ✅ Configured
     📍 /Users/you/Library/Application Support/Windsurf/User/settings.local.json
```

### List Command

List all configured MCP servers:

```bash
kindlyguard mcp list
```

### Verify Command

Verify KindlyGuard is properly configured:

```bash
kindlyguard mcp verify
```

### Edit Configuration

Open configuration in your default editor:

```bash
kindlyguard mcp config
```

## Configuration Format

### Standard JSON Format (Most tools)
```json
{
  "mcpServers": {
    "kindly-guard": {
      "command": "kindlyguard",
      "args": ["serve", "--stdio"],
      "env": {}
    }
  }
}
```

### Windsurf Format (settings.local.json)
```json
{
  "mcpServers": {
    "kindly-guard": {
      "provider": "stdio",
      "command": "kindlyguard",
      "args": ["serve", "--stdio"],
      "env": {}
    }
  }
}
```

## Troubleshooting

### Tool Not Detected

If your AI tool isn't detected:

1. Make sure it's installed and running
2. Check if it's in a non-standard location
3. Try running the tool first, then run setup again

### Configuration Not Working

1. Restart the AI tool after configuration
2. Check the configuration file was created correctly
3. Verify KindlyGuard is in your PATH: `which kindlyguard`
4. Check logs in the AI tool for MCP errors

### Multiple Configurations

KindlyGuard can be configured in multiple tools simultaneously. Each tool maintains its own configuration file and they don't interfere with each other.

## Advanced Usage

### Dry Run

Preview what would be configured without making changes:

```bash
kindlyguard mcp setup --dry-run
```

### Specific Tool Configuration

Configure a specific tool by its config path:

```bash
kindlyguard mcp setup --tool claude-desktop
```

### Environment Variables

Set logging level for debugging:

```bash
RUST_LOG=debug kindlyguard mcp setup
```

## Security Notes

1. **Backup Creation**: Existing configurations are automatically backed up
2. **Permission Checks**: Setup verifies write permissions before modifying
3. **Binary Path**: Uses the current KindlyGuard installation path
4. **No Sensitive Data**: Configuration contains no API keys or secrets

## Next Steps

After configuration:

1. **Restart** the configured AI tools
2. **Look for** KindlyGuard in the MCP menu/settings
3. **Enable** KindlyGuard to start protection
4. **Test** with: `kindlyguard test-connection`

## Getting Help

- Run `kindlyguard mcp --help` for command options
- Check `kindlyguard doctor` for system diagnostics
- Visit [GitHub Issues](https://github.com/samduchaine/kindlyguard/issues) for support