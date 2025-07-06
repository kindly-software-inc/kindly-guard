#!/bin/bash
# Fix remaining warnings in kindly-guard

echo "Fixing remaining warnings..."

# Fix unused imports in xtask
sed -i 's/use anyhow::{Context as _, Result};/use anyhow::Result;/' xtask/src/test/flaky.rs
sed -i 's/use std::path::Path;//' xtask/src/utils/cargo.rs

# Fix unused variables in xtask
sed -i 's/ctx: &Context,/_ctx: &Context,/g' xtask/src/commands/test.rs
sed -i 's/ctx: &Context,/_ctx: &Context,/g' xtask/src/commands/package.rs

# Fix unused imports in kindly-guard-server
sed -i 's/use std::sync::Arc;//' kindly-guard-server/src/audit/enhanced.rs
sed -i 's/, StandardBulkhead}/}/' kindly-guard-server/src/enhanced_impl/mod.rs
sed -i 's/use std::time::{Duration, Instant};/use std::time::Duration;/' kindly-guard-server/src/event_processor.rs

# Fix unused variables in kindly-guard-server
sed -i 's/char_idx: usize/_char_idx: usize/' kindly-guard-server/src/neutralizer/enhanced.rs
sed -i 's/filter: &QueryFilter/_filter: &QueryFilter/' kindly-guard-server/src/audit/enhanced.rs
sed -i 's/config: &Config/_config: &Config/g' kindly-guard-server/src/audit/mod.rs
sed -i 's/endpoint_id: &str/_endpoint_id: &str/g' kindly-guard-server/src/permissions/enhanced.rs
sed -i 's/let mut permissions = Vec::new();/let permissions = Vec::new();/' kindly-guard-server/src/permissions/enhanced.rs
sed -i 's/let mut last_error = None;/let mut _last_error = None;/' kindly-guard-server/src/resilience/enhanced.rs
sed -i 's/config: &Config/_config: &Config/g' kindly-guard-server/src/storage/mod.rs
sed -i 's/config: &Config/_config: &Config/g' kindly-guard-server/src/telemetry/mod.rs
sed -i 's/config: &Config/_config: &Config/g' kindly-guard-server/src/transport/mod.rs

# Add allow(dead_code) for unused traits in enhanced.rs files
sed -i '/^trait AuditSigner/i #[allow(dead_code)]' kindly-guard-server/src/audit/enhanced.rs
sed -i '/^trait DistributedStore/i #[allow(dead_code)]' kindly-guard-server/src/audit/enhanced.rs
sed -i '/^trait AlertManager/i #[allow(dead_code)]' kindly-guard-server/src/audit/enhanced.rs
sed -i '/^trait AnalyticsEngine/i #[allow(dead_code)]' kindly-guard-server/src/audit/enhanced.rs

# Add allow(dead_code) for unused methods in storage/enhanced.rs
sed -i '/impl EventStore for OptimizedEventStore/i #[allow(dead_code)]' kindly-guard-server/src/storage/enhanced.rs
sed -i '/impl<T: EventStore> HealthChecker<T>/i #[allow(dead_code)]' kindly-guard-server/src/storage/enhanced.rs
sed -i '/impl EventCorrelator/i #[allow(dead_code)]' kindly-guard-server/src/storage/enhanced.rs
sed -i '/impl SnapshotManager/i #[allow(dead_code)]' kindly-guard-server/src/storage/enhanced.rs
sed -i '/impl EventArchiver/i #[allow(dead_code)]' kindly-guard-server/src/storage/enhanced.rs

# Add allow(dead_code) for unused methods in telemetry/enhanced.rs
sed -i '/impl TelemetryBuffer/i #[allow(dead_code)]' kindly-guard-server/src/telemetry/enhanced.rs

echo "All fixes applied!"