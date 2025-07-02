//! Performance benchmarks for universal display system

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use kindly_guard_server::scanner::{Location, Severity, Threat, ThreatType};
use kindly_guard_server::shield::universal_display::DisplayFormat;
use kindly_guard_server::shield::{Shield, UniversalDisplay, UniversalDisplayConfig};
use std::sync::Arc;

/// Create a shield with specified number of threats for benchmarking
fn create_benchmark_shield(threat_count: u64) -> Arc<Shield> {
    let shield = Arc::new(Shield::new());

    // Add a mix of different threat types
    for i in 0..threat_count {
        let threat_type = match i % 4 {
            0 => ThreatType::UnicodeInvisible,
            1 => ThreatType::SqlInjection,
            2 => ThreatType::PathTraversal,
            _ => ThreatType::PromptInjection,
        };

        let threat = Threat {
            threat_type,
            severity: if i % 3 == 0 {
                Severity::Critical
            } else {
                Severity::High
            },
            description: format!("Benchmark threat {}", i),
            location: Location::Text {
                offset: i as usize,
                length: 10,
            },
            remediation: None,
        };
        shield.record_threats(&[threat]);
    }

    shield
}

fn benchmark_display_formats(c: &mut Criterion) {
    let mut group = c.benchmark_group("display_formats");
    let shield = create_benchmark_shield(100);

    for format in &[
        DisplayFormat::Minimal,
        DisplayFormat::Compact,
        DisplayFormat::Dashboard,
        DisplayFormat::Json,
    ] {
        group.bench_with_input(
            BenchmarkId::new("render", format!("{:?}", format)),
            format,
            |b, &format| {
                let config = UniversalDisplayConfig {
                    color: false,
                    detailed: true,
                    format,
                    status_file: None,
                };
                let display = UniversalDisplay::new(shield.clone(), config);

                b.iter(|| black_box(display.render()));
            },
        );
    }

    group.finish();
}

fn benchmark_color_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("color_overhead");
    let shield = create_benchmark_shield(50);

    for (color, label) in &[(true, "with_color"), (false, "no_color")] {
        group.bench_with_input(BenchmarkId::new("compact", label), color, |b, &color| {
            let config = UniversalDisplayConfig {
                color,
                detailed: true,
                format: DisplayFormat::Compact,
                status_file: None,
            };
            let display = UniversalDisplay::new(shield.clone(), config);

            b.iter(|| black_box(display.render()));
        });
    }

    group.finish();
}

fn benchmark_threat_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("threat_scaling");

    for threat_count in &[10u64, 100, 1000, 10000] {
        let shield = create_benchmark_shield(*threat_count);

        group.bench_with_input(
            BenchmarkId::new("dashboard", threat_count),
            threat_count,
            |b, _| {
                let config = UniversalDisplayConfig {
                    color: false,
                    detailed: true,
                    format: DisplayFormat::Dashboard,
                    status_file: None,
                };
                let display = UniversalDisplay::new(shield.clone(), config);

                b.iter(|| black_box(display.render()));
            },
        );
    }

    group.finish();
}

fn benchmark_status_file_writing(c: &mut Criterion) {
    let mut group = c.benchmark_group("status_file");
    let shield = create_benchmark_shield(100);
    let temp_dir = tempfile::tempdir().unwrap();

    group.bench_function("write_json", |b| {
        let status_file = temp_dir.path().join("status.json");
        let config = UniversalDisplayConfig {
            color: false,
            detailed: true,
            format: DisplayFormat::Json,
            status_file: Some(status_file.to_str().unwrap().to_string()),
        };
        let display = UniversalDisplay::new(shield.clone(), config);

        b.iter(|| display.write_status_file().unwrap());
    });

    group.finish();
}

fn benchmark_json_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_serialization");

    for threat_count in &[10u64, 100, 1000] {
        let shield = create_benchmark_shield(*threat_count);

        group.bench_with_input(
            BenchmarkId::new("serialize", threat_count),
            threat_count,
            |b, _| {
                let config = UniversalDisplayConfig {
                    color: false,
                    detailed: true,
                    format: DisplayFormat::Json,
                    status_file: None,
                };
                let display = UniversalDisplay::new(shield.clone(), config);

                b.iter(|| {
                    let status = display.get_status();
                    black_box(serde_json::to_string(&status).unwrap())
                });
            },
        );
    }

    group.finish();
}

fn benchmark_enhanced_mode_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("enhanced_mode");
    let shield = create_benchmark_shield(100);

    // Test with enhanced mode on/off
    for (enhanced, label) in &[(true, "enhanced"), (false, "standard")] {
        shield.set_event_processor_enabled(*enhanced);

        group.bench_with_input(BenchmarkId::new("dashboard", label), enhanced, |b, _| {
            let config = UniversalDisplayConfig {
                color: true, // With color to show purple theme
                detailed: true,
                format: DisplayFormat::Dashboard,
                status_file: None,
            };
            let display = UniversalDisplay::new(shield.clone(), config);

            b.iter(|| black_box(display.render()));
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_display_formats,
    benchmark_color_overhead,
    benchmark_threat_scaling,
    benchmark_status_file_writing,
    benchmark_json_serialization,
    benchmark_enhanced_mode_overhead
);
criterion_main!(benches);
