# KindlyGuard Scripts

This directory contains utility scripts for managing the KindlyGuard project.

## Available Scripts

### update-version.sh

Updates version numbers across all project files including Cargo.toml files, package.json files, and README.md.

**Usage:**
```bash
./scripts/update-version.sh VERSION [OPTIONS]
```

**Options:**
- `--dry-run` - Show what would be changed without making changes
- `--commit` - Create a git commit with the changes
- `--tag` - Create a git tag for the version (implies --commit)

**Examples:**
```bash
# Update to version 0.9.6
./scripts/update-version.sh 0.9.6

# Preview changes without applying them
./scripts/update-version.sh 1.0.0 --dry-run

# Update version and create a commit and tag
./scripts/update-version.sh 0.9.7 --commit --tag
```

**Files Updated:**
- All Cargo.toml files (workspace and crates)
- All package.json files (npm packages)
- README.md (Current Release section)

The script includes:
- Semantic version validation
- Version comparison to ensure new version is greater
- Git integration for commits and tags
- Dry-run mode for previewing changes
- Comprehensive error handling and colored output

### check-dependencies.sh

Runs comprehensive supply chain security checks using cargo-deny.

**Usage:**
```bash
./scripts/check-dependencies.sh
```

**Checks Performed:**
- Security advisories (RUSTSEC database)
- License compliance (Apache-2.0 compatible)
- Banned crates (security and weight restrictions)
- Source validation (trusted registries only)

**Example Output:**
```
🔒 KindlyGuard Dependency Security Check
========================================

▶ Running Security Advisories...
✅ Security Advisories passed

▶ Running License Compliance...
✅ License Compliance passed
```

### install-cargo-deny.sh

Installs or updates cargo-deny for dependency auditing.

**Usage:**
```bash
./scripts/install-cargo-deny.sh
```

**Features:**
- Checks for existing installation
- Updates advisory database
- Runs initial security scan
- Provides usage instructions

### install-hooks.sh

Installs pre-commit hooks for security-first development practices.

**Usage:**
```bash
./scripts/install-hooks.sh
```

**Installed Hooks:**
- **rustfmt** - Prevents unicode hiding in weird formatting
- **clippy** - Catches common security vulnerabilities
- **unsafe code check** - Ensures all `unsafe` blocks have SAFETY comments
- **detect-secrets** - Prevents API keys/passwords in commits
- **file size limits** - Prevents binary smuggling (>1MB files)
- **conventional commits** - Enables security audit trails
- **cargo audit** - Vulnerability scanning (pre-push)
- **version consistency** - Ensures synchronized versions
- **license headers** - Validates Apache-2.0 headers

**Features:**
- Installs pre-commit framework if not present
- Sets up git hooks for commit and commit-msg
- Creates secrets baseline for detect-secrets
- Installs security tools (cargo-audit, cargo-machete)
- Provides manual fallback hooks in .git-hooks/
- Clear error messages with fix instructions

**Security Philosophy:**
This creates a "security shift-left" culture where issues are caught at the earliest moment - before code enters the repository. Each rejected commit is a prevented vulnerability.

### pre-release-checklist.sh

Comprehensive pre-release validation including dependency analysis.

**Usage:**
```bash
./scripts/pre-release-checklist.sh
```

**Security Checks:**
- cargo audit (known vulnerabilities)
- cargo deny (supply chain security)
- cargo geiger (unsafe code scan)
- **cargo machete (unused dependencies)**
- Version consistency validation

**Dependency Security:**
cargo-machete integration checks for unused dependencies that:
- Increase attack surface
- Add supply chain risk
- Slow build times
- Provide no value

The script treats unused dependencies as errors that must be fixed before release.