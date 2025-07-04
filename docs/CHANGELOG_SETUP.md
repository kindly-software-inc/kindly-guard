# Changelog Setup Guide

This guide explains how to use git-cliff for automated changelog generation in KindlyGuard.

## Quick Start

1. **Install git-cliff**:
   ```bash
   cargo install git-cliff
   # Or use the helper script
   ./scripts/changelog-management.sh install
   ```

2. **Configure git commit template**:
   ```bash
   ./scripts/setup-commit-template.sh
   ```

3. **Preview unreleased changes**:
   ```bash
   ./scripts/changelog-management.sh preview
   ```

## Commit Message Format

We follow conventional commits with a security focus:

### Security Commits (Always Priority)
- `security: <description>` - Security fixes
- `vuln: <description>` - Vulnerability patches
- `cve: <description>` - CVE fixes
- `audit: <description>` - Audit changes

### Standard Commits
- `feat(scope): <description>` - New features
- `fix(scope): <description>` - Bug fixes
- `perf(scope): <description>` - Performance improvements
- Other types: docs, test, refactor, build, ci, deps, chore

### Scopes
- **Scanner**: scanner, unicode, injection, xss, patterns
- **Server**: server, protocol, handler
- **Other**: shield, storage, cache, resilience, config, cli, neutralizer

## Examples

```bash
# Security fix (no scope needed)
git commit -m "security: fix timing attack in token validation

Use constant-time comparison to prevent timing attacks.

Fixes: CVE-2024-XXXXX"

# Feature with scope
git commit -m "feat(scanner): add Windows command injection detection"

# Breaking change
git commit -m "feat(api)!: change scan response format

BREAKING CHANGE: returns array instead of single object"
```

## Release Workflow

During releases, the changelog is automatically updated:

```bash
# Manual changelog generation
./scripts/changelog-management.sh generate

# Release with automatic changelog
./scripts/update-version.sh 1.0.0 --release
```

## Validation

Check if your recent commits follow the convention:

```bash
./scripts/changelog-management.sh validate
```

## Configuration

The git-cliff configuration is in `.cliff.toml`. It:
- Prioritizes security commits at the top
- Groups commits by type
- Includes emoji indicators
- Generates comparison links
- Follows Keep a Changelog format

## Security & Compliance

For audit trails:
1. All commits should be signed when possible
2. Security commits are highlighted in changelogs
3. CVE references are tracked
4. Breaking changes are clearly marked

Configure GPG signing:
```bash
git config --global user.signingkey YOUR_GPG_KEY
git config --global commit.gpgsign true
```

## Troubleshooting

- **Invalid commits**: Run `./scripts/changelog-management.sh validate`
- **Missing git-cliff**: Run `cargo install git-cliff`
- **Template not showing**: Run `./scripts/setup-commit-template.sh`

## Resources

- [Conventional Commits](https://www.conventionalcommits.org/)
- [git-cliff Documentation](https://git-cliff.org/)
- [Keep a Changelog](https://keepachangelog.com/)