# Development Documentation

This directory contains all development-related documentation for the KindlyGuard project. Documents are organized by topic for easy navigation.

## 📚 Developer Guides

### Getting Started
- **[DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)** - Comprehensive guide for new developers, including setup, architecture overview, and contribution guidelines
- **[RUST_GUIDE.md](./RUST_GUIDE.md)** - Rust-specific development practices, idioms, and patterns used in the project

### Project Overview
- **[PROJECT_JOURNEY.md](./PROJECT_JOURNEY.md)** - Historical context and evolution of the KindlyGuard project
- **[FEATURES.md](./FEATURES.md)** - Complete inventory of implemented features with their current status

## 🚀 CI/CD Documentation

### Implementation Guides
- **[RUST_CICD_GUIDE.md](./RUST_CICD_GUIDE.md)** - Complete guide to the Rust CI/CD pipeline setup and configuration
- **[CICD_MIGRATION_GUIDE.md](./CICD_MIGRATION_GUIDE.md)** - Step-by-step guide for migrating to the new CI/CD system

### Status and Planning
- **[RUST_CICD_IMPLEMENTATION_STATUS.md](./RUST_CICD_IMPLEMENTATION_STATUS.md)** - Current implementation status of CI/CD components
- **[RUST_CICD_OPTIMIZATION_PLAN.md](./RUST_CICD_OPTIMIZATION_PLAN.md)** - Optimization strategies and performance improvements for CI/CD

## 🗺️ Roadmap and Planning

### Future Development
- **[ROADMAP.md](./ROADMAP.md)** - Project roadmap with planned features and milestones
- **[FUTURE_INNOVATIONS.md](./FUTURE_INNOVATIONS.md)** - Long-term vision and innovative features under consideration
- **[TODO_TRACKER.md](./TODO_TRACKER.md)** - Current task list and work items

### Policies
- **[MSRV_POLICY.md](./MSRV_POLICY.md)** - Minimum Supported Rust Version policy and upgrade guidelines

## 🏗️ Build Processes

Build-related documentation is integrated within the guides above:
- Build configuration details in [DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md#building-the-project)
- CI/CD build pipelines in [RUST_CICD_GUIDE.md](./RUST_CICD_GUIDE.md)
- Security-focused build profiles in project root's CLAUDE.md

## 📖 Quick Reference

### For New Contributors
1. Start with [DEVELOPER_GUIDE.md](./DEVELOPER_GUIDE.md)
2. Review [RUST_GUIDE.md](./RUST_GUIDE.md) for Rust conventions
3. Check [FEATURES.md](./FEATURES.md) to understand current capabilities

### For CI/CD Work
1. Consult [RUST_CICD_GUIDE.md](./RUST_CICD_GUIDE.md) for pipeline details
2. Follow [CICD_MIGRATION_GUIDE.md](./CICD_MIGRATION_GUIDE.md) for migrations
3. Review [RUST_CICD_IMPLEMENTATION_STATUS.md](./RUST_CICD_IMPLEMENTATION_STATUS.md) for current state

### For Planning
1. Review [ROADMAP.md](./ROADMAP.md) for upcoming work
2. Check [TODO_TRACKER.md](./TODO_TRACKER.md) for immediate tasks
3. Explore [FUTURE_INNOVATIONS.md](./FUTURE_INNOVATIONS.md) for long-term vision

## 🔍 Document Maintenance

- All documentation should follow the project's security-first philosophy
- Update relevant docs when implementing new features
- Keep CI/CD documentation in sync with actual pipeline configurations
- Review and update the roadmap quarterly

## 📝 Contributing to Documentation

When adding new development documentation:
1. Place it in this directory
2. Update this README.md with appropriate categorization
3. Follow the existing naming conventions (UPPERCASE_WITH_UNDERSCORES.md)
4. Include clear headers and table of contents for longer documents
5. Cross-reference related documentation where appropriate