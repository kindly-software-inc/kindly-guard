// Copyright 2025 Kindly Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! Interface for enhanced metrics implementation
//! This file defines the trait interface for enhanced metrics providers

use crate::traits::MetricsProvider;

/// Trait that enhanced metrics provider must implement
pub trait EnhancedMetricsProvider: MetricsProvider {
    /// Get read-side performance statistics
    fn read_performance_stats(&self) -> ReadPerformanceStats;

    /// Get write-side performance statistics  
    fn write_performance_stats(&self) -> WritePerformanceStats;
}

/// Statistics about read-side performance
#[derive(Debug, Clone)]
pub struct ReadPerformanceStats {
    /// Total number of reads
    pub total_reads: u64,

    /// Number of reads that succeeded without retry
    pub fast_path_reads: u64,

    /// Number of reads that required retry
    pub retry_reads: u64,

    /// Average read latency in nanoseconds
    pub avg_read_latency_ns: u64,
}

/// Statistics about write-side performance
#[derive(Debug, Clone)]
pub struct WritePerformanceStats {
    /// Total number of writes
    pub total_writes: u64,

    /// Average write latency in nanoseconds
    pub avg_write_latency_ns: u64,

    /// Number of concurrent write conflicts
    pub write_conflicts: u64,
}

/// Placeholder for enhanced metrics implementation
/// The actual implementation would be provided by the enhanced feature
pub struct EnhancedMetricsSpec {
    _phantom: std::marker::PhantomData<()>,
}
