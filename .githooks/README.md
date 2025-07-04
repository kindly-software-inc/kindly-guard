# Git Hooks for KindlyGuard

This directory contains Git hooks to prevent accidental leakage of proprietary implementation details.

## Pre-commit Hook

The pre-commit hook prevents commits that contain references to:
- Hierarchical rate limiter implementation
- Atomic bit-packed event buffer details
- Performance metrics that reveal proprietary optimizations
- Internal module names and patterns

## Installation

To install these hooks, run:

```bash
./install-hooks.sh
```

Or manually:

```bash
ln -sf ../../.githooks/pre-commit .git/hooks/pre-commit
```

## Allowed Files

The following files are allowed to contain sensitive terms:
- `docs/FUTURE_INNOVATIONS.md` - Internal roadmap documentation
- `docs/HIERARCHICAL_RATE_LIMITER.md` - Technical specification
- `docs/ATOMIC_STATE_MACHINE.md` - Implementation details
- `src/enhanced_impl/*` - Actual implementation files
- `benches/rate_limiter_comparison.rs` - Performance benchmarks

## Bypassing the Hook

In rare cases where you need to bypass the hook:

```bash
git commit --no-verify
```

**WARNING**: Only bypass if you're absolutely certain the commit doesn't expose proprietary information.

## Adding New Sensitive Terms

Edit `.githooks/pre-commit` and add new patterns to the `sensitive_terms` array.

## Testing the Hook

To test the hook without committing:

```bash
./.githooks/pre-commit
```