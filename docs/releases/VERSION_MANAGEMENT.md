# Version Management Guide for KindlyGuard

This document describes how version numbers are managed across the KindlyGuard project and provides guidance on using the automated version management tools.

## Version Number Locations

Version numbers appear in multiple locations throughout the project. All these locations must be kept in sync to ensure consistent releases.

### Primary Version Locations

1. **Workspace Cargo.toml** (`/Cargo.toml`)
   - `[workspace.package] version = "X.Y.Z"`
   - This is the primary version source for all Rust crates

2. **Individual Crate Cargo.toml files**
   - `kindly-guard-server/Cargo.toml`
   - `kindly-guard-cli/Cargo.toml`
   - `kindly-guard-shield/Cargo.toml`
   - `kindly-api/Cargo.toml`
   - These inherit from workspace but may have explicit versions

3. **NPM Package** (`npm-package/package.json`)
   - `"version": "X.Y.Z"`
   - Must match Rust version for consistency

4. **Docker Configuration**
   - `docker/Dockerfile` - ARG VERSION and LABEL directives
   - `docker-compose.yml` - image tags

5. **Documentation**
   - `README.md` - Version badges and installation examples
   - API documentation headers
   - Example configurations

### Secondary Version References

These locations may reference version numbers in examples or documentation:

- Installation guides
- Configuration examples
- API documentation
- Release notes
- CI/CD workflows

## Automated Version Update

The `update-version.sh` script automates the process of updating version numbers across all locations.

### Basic Usage

```bash
# Update to a new version
./scripts/update-version.sh 1.0.0

# Preview changes without modifying files
./scripts/update-version.sh 1.0.0 --dry-run

# Update files but don't commit
./scripts/update-version.sh 1.0.0 --no-commit

# Commit but don't create tag
./scripts/update-version.sh 1.0.0 --no-tag
```

### What the Script Does

1. **Validates the version format** (X.Y.Z or X.Y.Z-suffix)
2. **Updates all version locations** automatically
3. **Creates a git commit** with message "chore: update version to X.Y.Z"
4. **Creates a git tag** "vX.Y.Z"
5. **Shows a summary** of all changes made

### Script Options

- `--dry-run`: Shows what would be changed without modifying any files
- `--no-commit`: Updates files but doesn't create a git commit
- `--no-tag`: Creates a commit but doesn't create a git tag

## Version Validation

The `validate-versions.sh` script checks that all version numbers are synchronized.

### Usage

```bash
# Check version consistency
./scripts/validate-versions.sh

# Use in CI/CD pipelines
./scripts/validate-versions.sh || exit 1
```

### What It Validates

1. All Cargo.toml files have matching versions
2. NPM package.json matches Cargo version
3. Docker files reference the correct version
4. README badges show the current version
5. No files contain old version references

## Best Practices

### 1. Always Use the Scripts

Never manually edit version numbers. Always use the automated scripts to ensure consistency:

```bash
# Good
./scripts/update-version.sh 1.0.1

# Bad - Don't do this!
vim Cargo.toml  # Manually editing version
```

### 2. Validate After Updates

Always run validation after updating versions:

```bash
./scripts/update-version.sh 1.0.1
./scripts/validate-versions.sh
```

### 3. Version Numbering Convention

Follow semantic versioning (SemVer):
- **Major** (X.0.0): Breaking changes
- **Minor** (0.X.0): New features, backward compatible
- **Patch** (0.0.X): Bug fixes, backward compatible

Pre-release versions:
- Beta: `1.0.0-beta.1`
- Release Candidate: `1.0.0-rc.1`
- Alpha: `1.0.0-alpha.1`

### 4. Release Workflow Integration

1. Update version as first step of release:
   ```bash
   ./scripts/update-version.sh 1.0.0
   ```

2. Continue with release checklist:
   - Update CHANGELOG.md
   - Run tests
   - Build release artifacts

3. Push version tag to trigger CI/CD:
   ```bash
   git push origin main
   git push origin v1.0.0
   ```

## Troubleshooting

### Version Mismatch Errors

If you encounter version mismatch errors:

1. **Run validation to identify mismatches**:
   ```bash
   ./scripts/validate-versions.sh
   ```

2. **Use update script to fix**:
   ```bash
   ./scripts/update-version.sh $(grep version Cargo.toml | head -1 | cut -d'"' -f2)
   ```

3. **Verify all files are committed**:
   ```bash
   git status
   ```

### Script Errors

Common issues and solutions:

1. **"Permission denied"**
   ```bash
   chmod +x scripts/*.sh
   ```

2. **"Command not found"**
   - Ensure you're in the project root directory
   - Check that scripts/ directory exists

3. **"Version already exists"**
   - Check existing tags: `git tag -l`
   - Use a different version number

### Manual Recovery

If automated scripts fail, you can manually verify versions:

```bash
# Check Rust versions
grep -h "^version" */Cargo.toml

# Check NPM version
cat npm-package/package.json | grep '"version"'

# Check Docker versions
grep -E "(ARG VERSION|version=)" docker/Dockerfile

# Check README badges
grep -o "version-[0-9.]*-" README.md
```

## CI/CD Integration

### GitHub Actions

Add version validation to your workflow:

```yaml
- name: Validate Version Consistency
  run: ./scripts/validate-versions.sh
```

### Pre-commit Hook

Ensure versions are consistent before committing:

```bash
#!/bin/bash
# .git/hooks/pre-commit
./scripts/validate-versions.sh || {
    echo "Version mismatch detected! Run ./scripts/update-version.sh"
    exit 1
}
```

## Version History Tracking

To see version history:

```bash
# List all version tags
git tag -l "v*" --sort=-v:refname

# Show version changes in a file
git log -p --follow Cargo.toml | grep -B3 -A3 "^version"

# Find when a version was introduced
git log --all --grep="update version to"
```

## Contributing

When contributing to KindlyGuard:

1. Don't modify version numbers in PRs
2. Version updates are done by maintainers during release
3. If you add new files with versions, update both scripts:
   - Add to `update-version.sh` for automatic updates
   - Add to `validate-versions.sh` for validation

Report any version management issues to the maintainers.