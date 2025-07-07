# NPM Publishing Commands for KindlyGuard v0.15.0

## Prerequisites
Make sure you have the NPM_TOKEN environment variable set:
```bash
echo $NPM_TOKEN  # Should show your token
```

## Publishing Commands

### 1. Main Package (Required)
```bash
cd /home/samuel/kindly-guard/npm-package
npm publish --access public
```

### 2. Platform-Specific Packages (Optional)
These are optional dependencies, publish them if you want platform-specific optimization:

```bash
# Linux x64
cd /home/samuel/kindly-guard/npm-package/npm/kindlyguard-linux-x64
npm publish --access public

# macOS x64
cd /home/samuel/kindly-guard/npm-package/npm/kindlyguard-darwin-x64
npm publish --access public

# macOS ARM64 (Apple Silicon)
cd /home/samuel/kindly-guard/npm-package/npm/kindlyguard-darwin-arm64
npm publish --access public

# Windows x64
cd /home/samuel/kindly-guard/npm-package/npm/kindlyguard-win32-x64
npm publish --access public
```

### 3. All-in-One Command
To publish everything at once:

```bash
# From the npm-package directory
cd /home/samuel/kindly-guard/npm-package

# Set NPM token if not already set
npm config set //registry.npmjs.org/:_authToken $NPM_TOKEN

# Publish main package
npm publish --access public

# Publish platform packages
for pkg in npm/kindlyguard-*; do
  echo "Publishing $pkg..."
  (cd "$pkg" && npm publish --access public)
done
```

### 4. Dry Run First (Recommended)
Test what will be published without actually publishing:

```bash
cd /home/samuel/kindly-guard/npm-package
npm publish --dry-run
```

### 5. Verify Publication
After publishing, verify the package is available:

```bash
npm view kindlyguard
npm install -g kindlyguard  # Test installation
```

## Notes
- The `--access public` flag is required for scoped packages or first-time publishing
- Platform-specific packages are optional; the main package will download binaries if they're not available
- Make sure you've built the binaries and they're in the correct locations before publishing