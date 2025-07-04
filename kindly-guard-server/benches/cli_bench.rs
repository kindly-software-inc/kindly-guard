// Copyright 2025 Kindly-Software
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
//! Performance benchmarks for CLI command processing

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use kindly_guard_server::cli::validation::{
    sanitize_output, validate_feature_name, validate_file_path, validate_port, validate_scan_input,
};

fn benchmark_path_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("path_validation");

    let test_paths = vec![
        "/tmp/test.txt",
        "/home/user/documents/file.json",
        "./relative/path/to/file.txt",
        "/very/long/path/with/many/directories/that/goes/on/and/on/file.txt",
    ];

    for path in test_paths {
        group.bench_with_input(
            BenchmarkId::new("validate", path.len()),
            &path,
            |b, path| {
                b.iter(|| black_box(validate_file_path(path).ok()));
            },
        );
    }

    group.finish();
}

fn benchmark_input_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("input_validation");

    // Create owned strings to avoid lifetime issues
    let medium_input = "x".repeat(1000);
    let large_input = "x".repeat(100_000);

    let test_inputs = vec![
        ("small", "Hello, world!".to_string()),
        ("medium", medium_input),
        ("large", large_input),
        ("unicode", "Unicode: 你好世界 مرحبا بالعالم".to_string()),
    ];

    for (label, input) in &test_inputs {
        group.bench_with_input(BenchmarkId::new("validate", label), input, |b, input| {
            b.iter(|| black_box(validate_scan_input(input).ok()));
        });
    }

    group.finish();
}

fn benchmark_output_sanitization(c: &mut Criterion) {
    let mut group = c.benchmark_group("output_sanitization");

    // Create owned strings to avoid lifetime issues
    let large_output = format!(
        "{}\x1b[31m{}\x1b[0m{}",
        "x".repeat(1000),
        "colored",
        "x".repeat(1000)
    );

    let test_outputs = vec![
        (
            "plain",
            "Simple text without special characters".to_string(),
        ),
        (
            "ansi",
            "\x1b[31mRed text\x1b[0m with \x1b[32mgreen\x1b[0m colors".to_string(),
        ),
        (
            "control",
            "Text with\x00null\x01and\x02other\x07control chars".to_string(),
        ),
        (
            "mixed",
            "Mixed \x1b[35mcolors\x1b[0m and\x00\x01control\nchars\ttabs".to_string(),
        ),
        ("large", large_output),
    ];

    for (label, output) in &test_outputs {
        group.bench_with_input(BenchmarkId::new("sanitize", label), output, |b, output| {
            b.iter(|| black_box(sanitize_output(output)));
        });
    }

    group.finish();
}

fn benchmark_feature_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("feature_validation");

    let test_features = vec![
        "unicode",
        "injection",
        "advanced",
        "custom-feature",
        "feature_with_underscores",
        "very-long-feature-name-that-is-still-valid",
    ];

    for feature in test_features {
        group.bench_function(BenchmarkId::new("validate", feature), |b| {
            b.iter(|| black_box(validate_feature_name(feature).ok()));
        });
    }

    group.finish();
}

fn benchmark_port_validation(c: &mut Criterion) {
    c.bench_function("port_validation", |b| {
        let test_ports = vec![1024, 3000, 8080, 8443, 9000, 65535];

        b.iter(|| {
            for port in &test_ports {
                black_box(validate_port(*port).ok());
            }
        });
    });
}

fn benchmark_command_parsing(c: &mut Criterion) {
    use clap::Parser;
    use kindly_guard_server::cli::KindlyCommand;

    let mut group = c.benchmark_group("command_parsing");

    let test_commands = vec![
        ("status", vec!["/kindlyguard", "status"]),
        (
            "scan_text",
            vec!["/kindlyguard", "scan", "test input", "--text"],
        ),
        (
            "scan_file",
            vec!["/kindlyguard", "scan", "/path/to/file.json"],
        ),
        ("telemetry", vec!["/kindlyguard", "telemetry", "--detailed"]),
        (
            "advanced",
            vec!["/kindlyguard", "advancedsecurity", "enable"],
        ),
        ("info", vec!["/kindlyguard", "info", "unicode"]),
        (
            "dashboard",
            vec!["/kindlyguard", "dashboard", "--port", "8080"],
        ),
    ];

    for (label, args) in test_commands {
        group.bench_with_input(BenchmarkId::new("parse", label), &args, |b, args| {
            b.iter(|| black_box(KindlyCommand::try_parse_from(args).ok()));
        });
    }

    group.finish();
}

fn benchmark_validation_error_cases(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation_errors");

    // Benchmark error path performance
    group.bench_function("invalid_path", |b| {
        b.iter(|| black_box(validate_file_path("../../../etc/passwd").err()));
    });

    let large_input = "x".repeat(11 * 1024 * 1024); // 11MB
    group.bench_function("oversized_input", |b| {
        b.iter(|| black_box(validate_scan_input(&large_input).err()));
    });

    group.bench_function("invalid_port", |b| {
        b.iter(|| black_box(validate_port(80).err()));
    });

    group.finish();
}

criterion_group!(
    benches,
    benchmark_path_validation,
    benchmark_input_validation,
    benchmark_output_sanitization,
    benchmark_feature_validation,
    benchmark_port_validation,
    benchmark_command_parsing,
    benchmark_validation_error_cases
);
criterion_main!(benches);
