# Seqlock Metrics Implementation Specification

This document specifies how the seqlock metrics should be implemented in `kindly-guard-core`.

## Overview

The seqlock pattern provides near-zero read overhead for metrics by using optimistic concurrency:
- Readers check version, read data, check version again
- Writers increment version, write data, increment version
- Readers retry if version changed during read

## Implementation Status

### Completed
- ✅ MetricsProvider trait definition in `kindly-guard-server/src/traits.rs`
- ✅ StandardMetricsProvider implementation using RwLock in `kindly-guard-server/src/metrics/standard.rs`
- ✅ Factory function pattern in `kindly-guard-server/src/metrics/mod.rs`

### Pending
- ⏳ SeqlockMetricsProvider implementation in `kindly-guard-core`
- ⏳ Performance benchmarks comparing standard vs seqlock implementations
- ⏳ Integration with enhanced feature flag

## MetricsProvider Trait

The MetricsProvider trait has been implemented in `kindly-guard-server/src/traits.rs`:

```rust
/// Metrics provider trait for different implementations
#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait MetricsProvider: Send + Sync {
    /// Get or create a counter metric
    fn counter(&self, name: &str, help: &str) -> Arc<dyn CounterTrait>;
    
    /// Get or create a gauge metric
    fn gauge(&self, name: &str, help: &str) -> Arc<dyn GaugeTrait>;
    
    /// Get or create a histogram metric
    fn histogram(&self, name: &str, help: &str, buckets: Vec<f64>) -> Arc<dyn HistogramTrait>;
    
    /// Export metrics in Prometheus format
    fn export_prometheus(&self) -> String;
    
    /// Export metrics as JSON
    fn export_json(&self) -> serde_json::Value;
    
    /// Get uptime in seconds
    fn uptime_seconds(&self) -> u64;
}

/// Counter metric trait
pub trait CounterTrait: Send + Sync {
    /// Increment the counter by 1
    fn inc(&self);
    
    /// Increment the counter by a specific amount
    fn inc_by(&self, amount: u64);
    
    /// Get current value
    fn value(&self) -> u64;
}

/// Gauge metric trait
pub trait GaugeTrait: Send + Sync {
    /// Set the gauge value
    fn set(&self, value: i64);
    
    /// Increment the gauge
    fn inc(&self);
    
    /// Decrement the gauge
    fn dec(&self);
    
    /// Get current value
    fn value(&self) -> i64;
}

/// Histogram metric trait
pub trait HistogramTrait: Send + Sync {
    /// Record an observation
    fn observe(&self, value: f64);
    
    /// Get histogram statistics
    fn stats(&self) -> HistogramStats;
}
```

## Implementations

### 1. StandardMetricsProvider (Completed)

Located in `kindly-guard-server/src/metrics/standard.rs`, this implementation uses RwLock for thread-safe access to metrics. It's suitable for most use cases where metrics read overhead is not critical.

Key characteristics:
- Uses `RwLock<HashMap<String, Arc<Metric>>>` for metric storage
- Atomic operations for individual metric updates
- Good performance for typical workloads
- No allocation on metric updates (only on metric creation)

### 2. SeqlockMetricsProvider (Pending)

Will be implemented in `kindly-guard-core`, this implementation uses the seqlock pattern for near-zero read overhead.

Key characteristics:
- Lock-free reads with optimistic concurrency
- Single-writer protection via mutex
- Fixed-size data structures for `Copy` trait compatibility
- Designed for high-frequency metric reads

## Usage Examples

### Basic Usage

```rust
use kindly_guard_server::metrics::create_metrics_provider;
use kindly_guard_server::traits::MetricsProvider;

// Create metrics provider based on configuration
let config = Config::default();
let metrics = create_metrics_provider(&config);

// Create and use counters
let request_counter = metrics.counter("http_requests_total", "Total HTTP requests");
request_counter.inc();
request_counter.inc_by(5);

// Create and use gauges
let connections = metrics.gauge("active_connections", "Number of active connections");
connections.set(10);
connections.inc();  // Now 11
connections.dec();  // Back to 10

// Create and use histograms
let response_times = metrics.histogram(
    "http_response_duration_seconds",
    "HTTP response times",
    vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
);
response_times.observe(0.123);  // Record 123ms response

// Export metrics
let prometheus_output = metrics.export_prometheus();
let json_output = metrics.export_json();
```

### Integration with Request Handler

```rust
use std::time::Instant;

async fn handle_request(
    request: Request,
    metrics: Arc<dyn MetricsProvider>,
) -> Response {
    // Track request count
    let request_counter = metrics.counter("api_requests_total", "Total API requests");
    request_counter.inc();
    
    // Track active requests
    let active_gauge = metrics.gauge("api_requests_active", "Active API requests");
    active_gauge.inc();
    
    // Time the request
    let timer_hist = metrics.histogram(
        "api_request_duration_seconds",
        "API request duration",
        vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
    );
    let start = Instant::now();
    
    // Process request
    let response = process_request(request).await;
    
    // Record timing
    let duration = start.elapsed().as_secs_f64();
    timer_hist.observe(duration);
    
    // Decrement active requests
    active_gauge.dec();
    
    response
}
```

### Using the Timer Helper

```rust
use kindly_guard_server::metrics::Timer;

async fn timed_operation(metrics: Arc<dyn MetricsProvider>) -> Result<()> {
    let histogram = metrics.histogram(
        "operation_duration_seconds",
        "Operation duration",
        vec![0.1, 0.5, 1.0, 2.0, 5.0]
    );
    
    // Timer automatically records on drop
    let _timer = Timer::new(histogram);
    
    // Do some work...
    perform_operation().await?;
    
    // Timer stops and records when it goes out of scope
    Ok(())
}
```

## Factory Function Pattern

The factory function in `kindly-guard-server/src/metrics/mod.rs` selects the appropriate implementation:

```rust
/// Create a metrics provider based on configuration
pub fn create_metrics_provider(config: &Config) -> Arc<dyn MetricsProvider> {
    #[cfg(feature = "enhanced")]
    {
        if config.is_event_processor_enabled() {
            // Try to use enhanced implementation from kindly-guard-core
            if let Some(provider) = try_create_enhanced_provider() {
                tracing::info!(
                    target: "metrics.init",
                    mode = "seqlock",
                    "Initializing enhanced seqlock metrics provider"
                );
                return provider;
            }
        }
    }
    
    tracing::info!(
        target: "metrics.init",
        mode = "standard",
        "Initializing standard metrics provider"
    );
    
    Arc::new(StandardMetricsProvider::new())
}
```

This pattern allows:
- Automatic selection based on feature flags
- Fallback to standard implementation if enhanced is unavailable
- Easy A/B testing between implementations
- Configuration-driven selection

## Implementation Structure

### Core Seqlock Type

```rust
pub struct Seqlock<T> {
    version: AtomicU64,
    data: UnsafeCell<T>,
    write_lock: Mutex<()>, // Ensures single writer
}

impl<T: Copy> Seqlock<T> {
    pub fn read(&self) -> T {
        loop {
            // Load version with acquire ordering
            let v1 = self.version.load(Ordering::Acquire);
            
            // Check if write in progress (odd version)
            if v1 & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            
            // Read data
            let data = unsafe { *self.data.get() };
            
            // Check version hasn't changed
            let v2 = self.version.load(Ordering::Acquire);
            if v1 == v2 {
                return data;
            }
            
            // Retry if version changed
            std::hint::spin_loop();
        }
    }
    
    pub fn write(&self, data: T) {
        let _guard = self.write_lock.lock().unwrap();
        
        // Increment version (make odd)
        self.version.fetch_add(1, Ordering::Release);
        
        // Write data
        unsafe { *self.data.get() = data; }
        
        // Increment version again (make even)
        self.version.fetch_add(1, Ordering::Release);
    }
}
```

### Metrics Provider Implementation

```rust
pub struct SeqlockMetricsProvider {
    counters: DashMap<String, Arc<SeqlockCounter>>,
    gauges: DashMap<String, Arc<SeqlockGauge>>,
    histograms: DashMap<String, Arc<SeqlockHistogram>>,
    start_time: Instant,
    read_stats: SeqlockReadStats,
}

struct SeqlockCounter {
    name: String,
    help: String,
    value: Seqlock<u64>,
}

struct SeqlockGauge {
    name: String,
    help: String,
    value: Seqlock<i64>,
}

struct SeqlockHistogram {
    name: String,
    help: String,
    buckets: Vec<f64>,
    data: Seqlock<HistogramData>,
}

#[derive(Copy, Clone)]
struct HistogramData {
    bucket_counts: [u64; 16], // Fixed size for Copy
    sum: u64,
    count: u64,
}
```

### Performance Tracking

```rust
struct SeqlockReadStats {
    total_reads: AtomicU64,
    fast_path_reads: AtomicU64,
    retry_reads: AtomicU64,
    total_read_nanos: AtomicU64,
}
```

## Key Design Decisions

### 1. Fixed-Size Histogram Buckets
To make `HistogramData` `Copy`, use fixed-size array for bucket counts.
Common bucket configurations:
- Response times: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10]
- Sizes: [100, 1000, 10000, 100000, 1000000]

### 2. Write-Side Locking
While reads are lock-free, writes use a mutex to ensure consistency.
This is acceptable because:
- Metrics writes are infrequent compared to reads
- Prevents complex atomic operations for histogram updates

### 3. Memory Ordering
- Readers use `Acquire` ordering for version checks
- Writers use `Release` ordering for version updates
- This ensures proper synchronization without full barriers

## Integration with KindlyGuard

### Factory Function
```rust
// In kindly-guard-core
pub fn create_seqlock_metrics_provider() -> Arc<dyn MetricsProvider> {
    Arc::new(SeqlockMetricsProvider::new())
}
```

### Configuration
```toml
[event_processor]
enabled = true  # Enables enhanced features including seqlock metrics
```

## Performance Characteristics

### Read Path
- **Fast path**: 2 atomic loads + data copy (~10ns)
- **Retry path**: Additional spin loops (~50ns)
- **No allocation**: Stack-only operations

### Write Path
- Mutex acquisition (~100ns)
- 2 atomic increments
- Data write
- Total: ~200ns

### Memory Usage
- Per metric: ~256 bytes (padded for cache alignment)
- No dynamic allocation on read path

## Testing Strategy

### Correctness Tests
1. Single writer, multiple readers
2. Version rollover handling
3. Concurrent write serialization

### Performance Tests
1. Read throughput under no contention
2. Read throughput under write contention
3. Write latency distribution

### Stress Tests
1. 64+ concurrent readers
2. Rapid write bursts
3. Mixed read/write workloads

## Security Considerations

1. **No Information Leakage**: Version counter reveals nothing about data
2. **DoS Resistance**: Readers can't block writers
3. **Memory Safety**: All unsafe usage is sound

## Migration Path

1. Implement in kindly-guard-core as separate crate
2. Feature-flag integration in kindly-guard-server
3. A/B test standard vs seqlock implementations
4. Enable by default in v2.0 for paid customers