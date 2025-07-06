# KindlyGuard Parallel CI Architecture

## Overview

The KindlyGuard Parallel CI system is a Tokio-based, massively parallel continuous integration framework designed to maximize hardware utilization and minimize CI/CD pipeline execution time. It orchestrates multiple pipelines across different platforms simultaneously, providing real-time monitoring and intelligent caching.

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Parallel CI System                        │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │ Coordinator │  │   Monitor    │  │  Cache Manager  │   │
│  │             │  │  (TUI/JSON)  │  │                 │   │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                │                     │            │
│  ┌──────┴────────────────┴─────────────────────┴────────┐  │
│  │                    Task Scheduler                     │  │
│  │              (Tokio + Semaphore Control)             │  │
│  └───────────────────────┬──────────────────────────────┘  │
│                          │                                  │
│  ┌───────────┬───────────┼───────────┬────────────────┐   │
│  │ Format    │   Build   │   Test    │    Security    │   │
│  │ Pipeline  │ Pipeline  │ Pipeline  │   Pipeline     │   │
│  └───────────┴───────────┴───────────┴────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Target Matrix                           │   │
│  │  [linux-x64, linux-arm64, macos, windows, wasm]    │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Massive Parallelization**: Every independent task runs simultaneously
2. **Zero Idle Time**: Hardware is constantly utilized through intelligent scheduling
3. **Fail-Fast Options**: Can stop immediately on first failure or continue for full report
4. **Real-time Visibility**: Live dashboard shows all running tasks and their status
5. **Smart Caching**: Build artifacts and test results are cached across runs

## Components

### 1. Coordinator (`coordinator.rs`)

The central orchestrator that manages all pipelines and tasks:

```rust
pub struct Coordinator {
    ctx: Arc<Context>,
    max_parallel: usize,
    fail_fast: bool,
    pipelines: Vec<Box<dyn Pipeline>>,
    targets: TargetMatrix,
    results: Arc<DashMap<String, PipelineResult>>,
    semaphore: Arc<Semaphore>,
    monitor: Option<Monitor>,
}
```

**Responsibilities:**
- Pipeline lifecycle management
- Task scheduling and parallelism control
- Result aggregation and reporting
- Resource management (via semaphore)

### 2. Pipelines (`pipelines/`)

Each pipeline represents a specific CI/CD workflow:

#### Format Pipeline
- Runs `cargo fmt --check`
- Validates code formatting
- Fast, runs first to catch simple issues

#### Build Pipeline
- Compiles for all target platforms
- Uses `cargo` for native builds
- Uses `cross` for cross-compilation
- Caches build artifacts

#### Test Pipeline
- Runs unit tests, integration tests, and doctests
- Uses `cargo-nextest` for 60% faster execution
- Supports smoke tests and full suite modes
- Parallel test execution across packages

#### Security Pipeline
- `cargo audit` - Vulnerability scanning
- `cargo deny` - License and dependency audit
- `cargo geiger` - Unsafe code detection
- Custom security tests

#### Benchmark Pipeline
- Performance benchmarks
- Regression detection
- Results comparison with baseline

### 3. Monitor (`monitor/`)

Real-time monitoring system with two modes:

#### TUI Dashboard
- Live task status updates
- Progress bars for each pipeline
- CPU and memory usage
- Error highlighting
- Built with `ratatui`

#### JSON Output
- Machine-readable progress updates
- Integration with external monitoring tools
- Structured logging

### 4. Cache Manager (`cache/`)

Intelligent caching system:

```rust
pub struct CacheManager {
    cache_dir: PathBuf,
    metadata: DashMap<String, CacheEntry>,
    compression: bool,
}
```

**Features:**
- Content-based cache keys
- Compression for large artifacts
- TTL-based expiration
- Concurrent access safety

### 5. Target Matrix (`targets.rs`)

Platform configuration system:

```rust
pub struct TargetMatrix {
    targets: Vec<Target>,
    cross_compile: bool,
    parallel_builds: bool,
}
```

**Supported Targets:**
- `linux-x64` (x86_64-unknown-linux-gnu)
- `linux-arm64` (aarch64-unknown-linux-gnu)
- `macos` (x86_64-apple-darwin, aarch64-apple-darwin)
- `windows` (x86_64-pc-windows-msvc)
- `wasm` (wasm32-unknown-unknown)

## Execution Flow

### 1. Initialization
```rust
let coordinator = Coordinator::new(ctx, max_parallel, fail_fast, dashboard).await?;
coordinator.enable_all_pipelines();
coordinator.set_targets(vec!["linux-x64", "macos", "windows"]);
```

### 2. Task Scheduling
```rust
// Each pipeline generates tasks for each target
let tasks = pipelines.iter()
    .flat_map(|p| targets.iter().map(|t| p.create_task(t)))
    .collect();

// Execute with controlled parallelism
let mut join_set = JoinSet::new();
for task in tasks {
    let permit = semaphore.acquire().await?;
    join_set.spawn(async move {
        let result = task.execute().await;
        drop(permit); // Release semaphore
        result
    });
}
```

### 3. Result Aggregation
```rust
while let Some(result) = join_set.join_next().await {
    match result {
        Ok(Ok(pipeline_result)) => {
            results.insert(pipeline_result.id(), pipeline_result);
            monitor.update(MonitorEvent::TaskComplete(pipeline_result));
        }
        Ok(Err(e)) if fail_fast => {
            join_set.abort_all();
            return Err(e);
        }
        _ => continue,
    }
}
```

## Performance Optimizations

### 1. Parallel Test Execution
- Uses `cargo-nextest` for parallel test running
- Tests are distributed across CPU cores
- Smart test grouping to minimize overhead

### 2. Build Caching
- Incremental compilation enabled
- `sccache` integration for distributed caching
- Docker layer caching for cross-compilation

### 3. Pipeline Dependencies
- DAG-based dependency resolution
- Independent pipelines run simultaneously
- Dependent pipelines wait only for required predecessors

### 4. Resource Management
- CPU core detection and optimal thread allocation
- Memory usage monitoring
- Disk I/O optimization through batching

## Configuration

### Basic Configuration (`.kindly-ci.toml`)

```toml
[parallel-ci]
max_parallel = 16
fail_fast = false
cache_dir = "target/ci-cache"
cache_compression = true

[monitor]
dashboard = true
log_level = "info"
output_format = "pretty" # or "json"

[targets]
enabled = ["linux-x64", "linux-arm64", "macos", "windows"]
cross_compile = true
docker_args = ["--platform", "linux/amd64,linux/arm64"]

[pipelines.format]
enabled = true
timeout = "2m"

[pipelines.build]
enabled = true
release = true
features = ["all"]
timeout = "10m"

[pipelines.test]
enabled = true
nextest = true
threads = 8
retries = 2
timeout = "15m"

[pipelines.security]
enabled = true
audit = true
deny = true
geiger = true
timeout = "5m"

[pipelines.benchmark]
enabled = false
baseline = "main"
timeout = "20m"
```

### Environment Variables

```bash
# Override configuration
KINDLY_CI_MAX_PARALLEL=32
KINDLY_CI_CACHE_DIR=/tmp/kindly-cache
KINDLY_CI_FAIL_FAST=true

# Performance tuning
CARGO_BUILD_JOBS=16
CARGO_INCREMENTAL=1
RUSTC_WRAPPER=sccache

# Cross-compilation
CROSS_CONTAINER_ENGINE=podman
CROSS_CONTAINER_OPTS="--cpus 4"
```

## Usage Examples

### Basic Usage

```bash
# Run everything in parallel
cargo xtask parallel-ci

# Run with dashboard
cargo xtask parallel-ci --dashboard

# Run specific pipelines
cargo xtask parallel-ci --smoke-tests
cargo xtask parallel-ci --full-suite --security-scan
```

### Advanced Usage

```bash
# Target specific platforms
cargo xtask parallel-ci --targets linux-x64,windows

# Clean run with fresh cache
cargo xtask parallel-ci --clean

# Fail fast on first error
cargo xtask parallel-ci --fail-fast

# Custom configuration
cargo xtask parallel-ci --config ci/parallel.toml

# Maximum parallelism
cargo xtask parallel-ci --max-parallel 32
```

### CI/CD Integration

```yaml
# GitHub Actions
- name: Run Parallel CI
  run: |
    cargo xtask parallel-ci \
      --dashboard \
      --fail-fast \
      --targets ${{ matrix.target }}
  env:
    KINDLY_CI_MAX_PARALLEL: 16
```

## Monitoring and Debugging

### Dashboard View

```
╔══════════════════════════════════════════════════════════════╗
║                KindlyGuard Parallel CI Monitor               ║
╠══════════════════════════════════════════════════════════════╣
║ Total Tasks: 48 | Running: 16 | Complete: 28 | Failed: 0    ║
╠══════════════════════════════════════════════════════════════╣
║ Format    [████████████████████████] 100% (4/4)   ✓         ║
║ Build     [████████████░░░░░░░░░░░░]  60% (12/20) ⟳        ║
║ Test      [████████░░░░░░░░░░░░░░░░]  40% (8/20)  ⟳        ║
║ Security  [████░░░░░░░░░░░░░░░░░░░░]  25% (1/4)   ⟳        ║
╠══════════════════════════════════════════════════════════════╣
║ CPU: 87% | Memory: 4.2 GB | Time: 02:34 | ETA: 01:20       ║
╚══════════════════════════════════════════════════════════════╝
```

### JSON Output

```json
{
  "timestamp": "2024-01-20T10:30:45Z",
  "status": "running",
  "progress": {
    "total": 48,
    "running": 16,
    "complete": 28,
    "failed": 0
  },
  "pipelines": {
    "format": { "status": "complete", "duration": "12s" },
    "build": { "status": "running", "progress": 0.6 },
    "test": { "status": "running", "progress": 0.4 },
    "security": { "status": "running", "progress": 0.25 }
  },
  "resources": {
    "cpu_percent": 87,
    "memory_mb": 4300,
    "elapsed_seconds": 154
  }
}
```

### Debugging Failed Tasks

```bash
# View detailed logs
cat target/ci-cache/logs/test-linux-x64.log

# Run single pipeline with verbose output
cargo xtask parallel-ci --verbose --full-suite

# Disable parallelism for debugging
cargo xtask parallel-ci --max-parallel 1 --verbose
```

## Best Practices

### 1. Resource Allocation
- Set `max_parallel` based on available CPU cores
- Leave headroom for system processes (e.g., 75% of cores)
- Monitor memory usage for memory-intensive tasks

### 2. Cache Management
- Clean cache periodically: `cargo xtask parallel-ci --clean`
- Use compression for large artifacts
- Configure appropriate TTLs for cache entries

### 3. Pipeline Design
- Keep pipelines independent when possible
- Use fine-grained tasks for better parallelization
- Set appropriate timeouts to prevent hanging

### 4. Error Handling
- Use `--fail-fast` in CI for quick feedback
- Use `--no-fail-fast` locally for complete reports
- Check logs for detailed error information

## Troubleshooting

### Common Issues

1. **Out of Memory**
   - Reduce `max_parallel`
   - Enable swap space
   - Use `--targets` to build fewer platforms

2. **Slow Performance**
   - Check cache hit rates
   - Verify network connectivity for cross-compilation
   - Ensure sufficient disk space

3. **Build Failures**
   - Check target-specific requirements
   - Verify cross-compilation setup
   - Review platform-specific code

### Performance Tuning

```bash
# Profile CPU usage
cargo xtask parallel-ci --dashboard 2>profile.log

# Analyze bottlenecks
grep "SLOW" target/ci-cache/logs/*.log

# Optimize parallelism
# Start conservative
cargo xtask parallel-ci --max-parallel 4
# Gradually increase
cargo xtask parallel-ci --max-parallel 8
cargo xtask parallel-ci --max-parallel 16
```

## Future Enhancements

1. **Distributed Execution**
   - Support for distributed CI across multiple machines
   - Kubernetes job orchestration
   - Cloud provider integration

2. **Intelligent Scheduling**
   - ML-based task duration prediction
   - Dynamic resource allocation
   - Priority-based scheduling

3. **Enhanced Caching**
   - Distributed cache sharing
   - Content-addressable storage
   - P2P cache distribution

4. **Advanced Monitoring**
   - Grafana integration
   - Historical performance tracking
   - Predictive failure detection