# Homebrew Distribution Setup for KindlyGuard

## Current Status
✅ cargo-dist configured with Homebrew tap
✅ Homepage URLs added to packages
✅ Tap repository specified: `kindly-software-inc/homebrew-tap`

## What You Need to Do

1. **Create the Tap Repository**
   - Go to https://github.com/kindly-software-inc
   - Create a new repository named `homebrew-tap`
   - Make it public
   - Initialize with a README.md

2. **Add GitHub Token Permission**
   - The release workflow needs permission to push to the tap repo
   - Add a repository secret named `HOMEBREW_TAP_TOKEN` with a GitHub PAT
   - The token needs `repo` scope for the tap repository

## How It Will Work

When you create a release (e.g., v0.10.4), cargo-dist will:

1. Build all the binaries and create GitHub Release
2. Generate Homebrew formulas:
   - `kindly-guard-server.rb` for the MCP server
   - `kindly-tools.rb` for the development tools
3. Automatically push these formulas to your tap repository
4. Update the formulas with download URLs and SHA256 checksums

## User Installation

Once set up, users can install KindlyGuard via Homebrew:

```bash
# Add your tap (one-time)
brew tap kindly-software-inc/tap

# Install the MCP server
brew install kindlyguard

# Install development tools
brew install kindly-tools

# Update to latest version
brew upgrade kindlyguard
```

### Formula Alias Setup

To allow `brew install kindlyguard` instead of `brew install kindly-guard-server`, create an alias in your tap repository:

1. In the `homebrew-tap` repository, create a file named `Aliases/kindlyguard`
2. Add a single line: `../Formula/kindly-guard-server.rb`
3. Commit and push

This creates an alias so users can use the shorter, cleaner name.

## Benefits

- **Native macOS Experience**: Homebrew is the standard package manager for macOS
- **Automatic Updates**: Users can update with `brew upgrade`
- **Clean Uninstall**: `brew uninstall kindlyguard` removes everything cleanly
- **Version Management**: Users can pin versions or rollback if needed
- **Professional Distribution**: Shows your project is mature and well-maintained

## Formula Example

cargo-dist will generate formulas like this:

```ruby
class KindlyGuardServer < Formula
  desc "KindlyGuard MCP server - Enterprise-grade security for AI model interactions"
  homepage "https://github.com/kindly-software-inc/kindly-guard"
  url "https://github.com/kindly-software-inc/kindly-guard/releases/download/v0.10.4/kindly-guard-server-x86_64-apple-darwin.tar.gz"
  sha256 "abc123..." # Automatically calculated
  license "Apache-2.0"

  def install
    bin.install "kindlyguard"
  end

  test do
    system "#{bin}/kindlyguard", "--version"
  end
end
```

## Next Steps

1. Create the tap repository
2. Add the `HOMEBREW_TAP_TOKEN` secret to your main repository
3. The next release will automatically publish to Homebrew!