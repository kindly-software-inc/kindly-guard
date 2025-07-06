# KindlyGuard Release Automation

## Overview

The `update-version.sh` script now includes comprehensive release automation capabilities that streamline the entire release process from version updates to GitHub Actions workflow monitoring.

## New Features

### 1. Automated Release Process (`--release`)

The `--release` flag triggers a complete automated release workflow:

```bash
./scripts/update-version.sh 1.0.0 --release
```

This will:
1. Perform comprehensive pre-release validation
2. Update all version files across the project
3. Create a git commit and annotated tag
4. Push the tag to trigger GitHub Actions
5. Monitor the workflow progress in real-time
6. Report success with links to the release

### 2. Release Dry Run (`--release-dry-run`)

Preview what the release process would do without making any changes:

```bash
./scripts/update-version.sh 1.0.0 --release-dry-run
```

### 3. No-Push Option (`--no-push`)

Complete all local operations but skip pushing to remote:

```bash
./scripts/update-version.sh 1.0.0 --release --no-push
```

## Pre-Release Validation

When using `--release`, the script performs these checks:

| Check | Description | How to Fix |
|-------|-------------|------------|
| Git Clean | Repository has no uncommitted changes | Commit or stash changes |
| Branch Check | Must be on main/master branch | `git checkout main` |
| Version Consistency | All files have matching versions | Run `./scripts/validate-versions.sh --fix` |
| GitHub CLI | `gh` command is installed | Install from https://cli.github.com |
| GitHub Auth | CLI is authenticated | Run `gh auth login` |
| Tag Availability | Version tag doesn't exist | Choose different version or delete existing tag |

## Release State Management

The script saves progress to `.release-state.json` for recovery:

```json
{
    "version": "1.0.0",
    "state": "updating_versions",
    "timestamp": "2024-01-20T10:30:00Z",
    "data": {}
}
```

States include:
- `started` - Initial validation phase
- `updating_versions` - Modifying version files
- `git_operations` - Creating commit and tag
- `failed` - Error occurred (can be resumed)

## Workflow Monitoring

The script uses GitHub CLI to:
- Wait for the workflow to start
- Display real-time progress
- Show success/failure status
- Provide direct links to:
  - Workflow run page
  - Release page
  - Error logs (if failed)

## Error Handling

### Pre-Release Failures

If validation fails, the script:
- Lists all issues clearly
- Provides specific fix instructions
- Exits without making changes

### Release Workflow Failures

If the GitHub Actions workflow fails:
- The local changes remain (versions updated, tagged)
- State is saved for potential retry
- Instructions provided for manual push
- Direct link to workflow logs

## Examples

### Complete Release

```bash
# Full automated release
./scripts/update-version.sh 1.0.0 --release
```

### Testing Changes

```bash
# See what would happen
./scripts/update-version.sh 1.0.0 --release-dry-run

# Make changes locally only
./scripts/update-version.sh 1.0.0 --release --no-push
```

### Traditional Usage

The script maintains backward compatibility:

```bash
# Just update versions
./scripts/update-version.sh 1.0.0

# Update and commit
./scripts/update-version.sh 1.0.0 --commit

# Update, commit, and tag
./scripts/update-version.sh 1.0.0 --commit --tag
```

## Progress Indicators

The script provides visual feedback:
- 🔵 `[INFO]` - General information
- 🟢 `[SUCCESS]` - Successful operations
- 🔴 `[ERROR]` - Errors requiring attention
- 🟡 `[WARNING]` - Important notices
- 🔷 `[STEP]` - Major process steps
- 🟣 `[PROGRESS]` - Ongoing operations
- ⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏ - Spinner for long operations

## Best Practices

1. **Always run dry-run first** for major releases:
   ```bash
   ./scripts/update-version.sh 2.0.0 --release-dry-run
   ```

2. **Ensure clean state** before releasing:
   ```bash
   git status
   ./scripts/validate-versions.sh
   ```

3. **Use semantic versioning**:
   - MAJOR.MINOR.PATCH (e.g., 1.2.3)
   - Pre-release versions supported (e.g., 1.0.0-beta.1)

4. **Monitor the release**:
   - Watch the real-time output
   - Check the GitHub Actions page if needed
   - Verify the release page after completion

## Troubleshooting

### "Git repository is not clean"
```bash
# Check what's changed
git status

# Stash changes temporarily
git stash

# Or commit changes
git add -A && git commit -m "Your message"
```

### "Not on main/master branch"
```bash
# Switch to main
git checkout main

# Or master
git checkout master
```

### "GitHub CLI not authenticated"
```bash
# Authenticate with GitHub
gh auth login

# Verify authentication
gh auth status
```

### "Tag already exists"
```bash
# Check existing tags
git tag -l

# Delete local tag
git tag -d v1.0.0

# Delete remote tag (be careful!)
git push origin :refs/tags/v1.0.0
```

## Resume After Failure

If the release process fails after creating the tag:

1. Check `.release-state.json` for the current state
2. Fix any issues identified
3. Manually push the tag:
   ```bash
   git push origin v1.0.0
   ```
4. Monitor in GitHub Actions

## Integration with CI/CD

The release automation integrates with the existing GitHub Actions workflow:

1. **Tag Push Trigger**: Pushing a tag starting with `v` triggers the release workflow
2. **Workflow Steps**: Build → Test → Package → Create Release → Publish
3. **Multi-Platform**: Builds for Linux, macOS, Windows, and Docker
4. **Package Publishing**: Automatically publishes to crates.io and npm

## Security Considerations

- The script never stores credentials
- Uses existing Git and GitHub CLI authentication
- All operations respect repository permissions
- State file (`.release-state.json`) is gitignored

## Future Enhancements

Potential improvements for consideration:
- [ ] Changelog generation from commit messages
- [ ] Release notes template support
- [ ] Rollback functionality
- [ ] Parallel pre-release check execution
- [ ] Custom pre/post release hooks
- [ ] Integration with issue tracking for milestone closure