# KindlyGuard Operational Documentation

This directory contains all operational documentation for the KindlyGuard project, organized by operational area.

## 📊 Performance & Analysis

### Performance Monitoring
- [`PERFORMANCE_ANALYSIS.md`](../PERFORMANCE_ANALYSIS.md) - Comprehensive performance analysis and benchmarks
- [`PERFORMANCE_REPORT.md`](../PERFORMANCE_REPORT.md) - Latest performance testing results
- [`BENCHMARKS_2024.md`](../BENCHMARKS_2024.md) - 2024 benchmark baselines and comparisons

### Code Analysis
- [`CODE_ANALYSIS_REPORT.md`](../CODE_ANALYSIS_REPORT.md) - Static code analysis results
- [`SECURITY_AUDIT_REPORT.md`](../SECURITY_AUDIT_REPORT.md) - Security vulnerability analysis
- [`DEPENDENCY_SECURITY_ANALYSIS.md`](../DEPENDENCY_SECURITY_ANALYSIS.md) - Dependency security audit

## 🔧 MCP Server Integration

### Core MCP Documentation
- [`MCP_INTEGRATION.md`](../MCP_INTEGRATION.md) - MCP protocol implementation guide
- [`MCP_SERVER_SETUP.md`](../MCP_SERVER_SETUP.md) - Server configuration and deployment
- [`MCP_TOOLS_DOCUMENTATION.md`](../MCP_TOOLS_DOCUMENTATION.md) - Available MCP tools reference

### Development MCP Servers
- [`TREE_SITTER_MCP_SETUP.md`](../TREE_SITTER_MCP_SETUP.md) - AST analysis server setup
- [`AST_GREP_MCP_SETUP.md`](../AST_GREP_MCP_SETUP.md) - Pattern search server setup
- [`RUST_DOCS_MCP_SETUP.md`](../RUST_DOCS_MCP_SETUP.md) - Documentation search server
- [`FILESCOPEMCP_SETUP.md`](../FILESCOPEMCP_SETUP.md) - Dependency analysis server

## 🚀 CI/CD & Deployment

### Build & Release
- [`BUILD_PROCESS.md`](../BUILD_PROCESS.md) - Complete build instructions
- [`RELEASE_PROCESS.md`](../RELEASE_PROCESS.md) - Release workflow and versioning
- [`CROSS_COMPILATION.md`](../CROSS_COMPILATION.md) - Multi-platform build guide

### Testing & Quality
- [`TESTING_GUIDE.md`](../TESTING_GUIDE.md) - Testing strategies and commands
- [`CI_SETUP.md`](../CI_SETUP.md) - GitHub Actions configuration
- [`LOCAL_CI_GUIDE.md`](LOCAL_CI_GUIDE.md) - 🆕 Local CI/CD with cargo xtask
- [`PRE_COMMIT_HOOKS.md`](../PRE_COMMIT_HOOKS.md) - Git hooks for quality control

## 🤖 Claude Integration

### Claude Configuration
- [`CLAUDE.md`](../../CLAUDE.md) - Main Claude configuration (project root)
- [`CLAUDE_INTEGRATION_GUIDE.md`](../CLAUDE_INTEGRATION_GUIDE.md) - Claude Code setup
- [`CLAUDE_WORKFLOW.md`](../CLAUDE_WORKFLOW.md) - Development workflow with Claude

### MCP for Claude
- [`CLAUDE_MCP_SETUP.md`](../CLAUDE_MCP_SETUP.md) - Configuring MCP servers for Claude
- [`CLAUDE_NAVIGATION.md`](../CLAUDE_NAVIGATION.md) - Codebase navigation aids

## 📋 Operational Procedures

### Monitoring & Maintenance
- [`MONITORING_SETUP.md`](../MONITORING_SETUP.md) - Production monitoring configuration
- [`TROUBLESHOOTING.md`](../TROUBLESHOOTING.md) - Common issues and solutions
- [`MAINTENANCE_PROCEDURES.md`](../MAINTENANCE_PROCEDURES.md) - Regular maintenance tasks

### Security Operations
- [`SECURITY_OPERATIONS.md`](../SECURITY_OPERATIONS.md) - Security monitoring and response
- [`INCIDENT_RESPONSE.md`](../INCIDENT_RESPONSE.md) - Security incident procedures
- [`AUDIT_PROCEDURES.md`](../AUDIT_PROCEDURES.md) - Security audit checklist

## 🛠️ Development Operations

### Development Environment
- [`DEV_ENVIRONMENT_SETUP.md`](../DEV_ENVIRONMENT_SETUP.md) - Developer machine setup
- [`VSCODE_CONFIGURATION.md`](../VSCODE_CONFIGURATION.md) - VS Code optimizations
- [`TOOLING_SETUP.md`](../TOOLING_SETUP.md) - Required development tools

### Database & Storage
- [`DATABASE_OPERATIONS.md`](../DATABASE_OPERATIONS.md) - SQLite management
- [`CACHE_OPERATIONS.md`](../CACHE_OPERATIONS.md) - Cache configuration and tuning
- [`BACKUP_PROCEDURES.md`](../BACKUP_PROCEDURES.md) - Data backup strategies

## 📊 Metrics & Reporting

### Performance Metrics
- [`METRICS_COLLECTION.md`](../METRICS_COLLECTION.md) - Metrics gathering setup
- [`DASHBOARD_SETUP.md`](../DASHBOARD_SETUP.md) - Monitoring dashboard configuration
- [`ALERT_CONFIGURATION.md`](../ALERT_CONFIGURATION.md) - Alert rules and thresholds

### Operational Reports
- [`WEEKLY_OPERATIONS_TEMPLATE.md`](../WEEKLY_OPERATIONS_TEMPLATE.md) - Weekly ops report template
- [`INCIDENT_REPORT_TEMPLATE.md`](../INCIDENT_REPORT_TEMPLATE.md) - Incident documentation
- [`PERFORMANCE_REPORT_TEMPLATE.md`](../PERFORMANCE_REPORT_TEMPLATE.md) - Performance analysis template

## 🔄 Automation

### Scripts & Tools
- [`AUTOMATION_SCRIPTS.md`](../AUTOMATION_SCRIPTS.md) - Operational automation scripts
- [`DEPLOYMENT_AUTOMATION.md`](../DEPLOYMENT_AUTOMATION.md) - Automated deployment
- [`TESTING_AUTOMATION.md`](../TESTING_AUTOMATION.md) - Automated testing setup

## 📚 Quick References

### Command Cheatsheets
- [`OPERATIONS_COMMANDS.md`](../OPERATIONS_COMMANDS.md) - Common operational commands
- [`TROUBLESHOOTING_COMMANDS.md`](../TROUBLESHOOTING_COMMANDS.md) - Diagnostic commands
- [`PERFORMANCE_COMMANDS.md`](../PERFORMANCE_COMMANDS.md) - Performance analysis commands

### Configuration References
- [`CONFIG_REFERENCE.md`](../CONFIG_REFERENCE.md) - Configuration file schemas
- [`ENVIRONMENT_VARIABLES.md`](../ENVIRONMENT_VARIABLES.md) - Environment configuration
- [`FEATURE_FLAGS.md`](../FEATURE_FLAGS.md) - Feature flag documentation

---

## Contributing to Operations Docs

When adding new operational documentation:

1. Place it in the appropriate category above
2. Use descriptive filenames in UPPER_SNAKE_CASE
3. Include a brief description in this index
4. Update relevant cross-references
5. Follow the documentation template in [`DOC_TEMPLATE.md`](../DOC_TEMPLATE.md)

## Document Status Key

- 🟢 **Current** - Up to date with latest changes
- 🟡 **Review Needed** - May need updates
- 🔴 **Outdated** - Requires immediate update
- 🆕 **New** - Recently added documentation

Last updated: 2025-01-20