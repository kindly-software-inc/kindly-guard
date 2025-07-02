use std::{
    sync::{Arc, atomic::{AtomicBool, Ordering}},
    time::Duration,
};

use kindly_guard_shield_lib::{
    core::{Severity, Threat, ThreatType},
    ipc::{
        client::ShmClient,
        shm::{SharedMemoryIpc, ShmConfig},
    },
};
use tokio::time::timeout;

#[tokio::test]
async fn test_shm_write_read() {
    if !SharedMemoryIpc::is_available() {
        println!("Shared memory not available, skipping test");
        return;
    }

    // Create writer and reader
    let mut writer = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
    let reader = ShmClient::new().unwrap();

    // Create test threat
    let threat = Threat {
        id: "test-1".to_string(),
        threat_type: ThreatType::UnicodeInvisible,
        severity: Severity::High,
        source: "test".to_string(),
        details: "Test threat".to_string(),
        blocked: true,
        timestamp: chrono::Utc::now(),
        context: None,
    };

    // Write threat
    writer.write_threat(&threat).unwrap();

    // Read threat
    let read_threat = reader.shm.read_threat().unwrap().unwrap();
    
    // Verify
    assert_eq!(read_threat.threat_type, threat.threat_type);
    assert_eq!(read_threat.severity, threat.severity);
    assert_eq!(read_threat.source, threat.source);
    assert_eq!(read_threat.blocked, threat.blocked);
}

#[tokio::test]
async fn test_shm_multiple_threats() {
    if !SharedMemoryIpc::is_available() {
        println!("Shared memory not available, skipping test");
        return;
    }

    let mut writer = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
    let reader = ShmClient::new().unwrap();

    // Write multiple threats
    let count = 100;
    for i in 0..count {
        let threat = Threat {
            id: format!("test-{}", i),
            threat_type: ThreatType::SuspiciousPattern,
            severity: Severity::Medium,
            source: format!("source-{}", i),
            details: format!("Details for threat {}", i),
            blocked: false,
            timestamp: chrono::Utc::now(),
            context: None,
        };
        writer.write_threat(&threat).unwrap();
    }

    // Read all threats
    let mut read_count = 0;
    while let Some(_threat) = reader.shm.read_threat().unwrap() {
        read_count += 1;
    }

    assert_eq!(read_count, count);
}

#[tokio::test]
async fn test_shm_concurrent_access() {
    if !SharedMemoryIpc::is_available() {
        println!("Shared memory not available, skipping test");
        return;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();

    // Spawn reader task
    let reader_task = tokio::spawn(async move {
        let reader = ShmClient::new().unwrap();
        let mut count = 0;

        while !stop_flag_clone.load(Ordering::Relaxed) {
            if let Some(_threat) = reader.shm.read_threat().unwrap() {
                count += 1;
            }
            tokio::time::sleep(Duration::from_micros(100)).await;
        }

        count
    });

    // Give reader time to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Write threats
    let mut writer = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
    let write_count = 50;
    
    for i in 0..write_count {
        let threat = Threat {
            id: format!("concurrent-{}", i),
            threat_type: ThreatType::InjectionAttempt,
            severity: Severity::Critical,
            source: "concurrent-test".to_string(),
            details: format!("Concurrent threat {}", i),
            blocked: true,
            timestamp: chrono::Utc::now(),
            context: None,
        };
        writer.write_threat(&threat).unwrap();
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    // Give reader time to catch up
    tokio::time::sleep(Duration::from_millis(100)).await;
    stop_flag.store(true, Ordering::Relaxed);

    // Wait for reader
    let read_count = reader_task.await.unwrap();
    assert_eq!(read_count, write_count);
}

#[tokio::test]
async fn test_shm_latency() {
    if !SharedMemoryIpc::is_available() {
        println!("Shared memory not available, skipping test");
        return;
    }

    use std::time::Instant;

    let mut writer = SharedMemoryIpc::new(ShmConfig::default()).unwrap();
    let reader = ShmClient::new().unwrap();

    let threat = Threat {
        id: "latency-test".to_string(),
        threat_type: ThreatType::PathTraversal,
        severity: Severity::Low,
        source: "latency".to_string(),
        details: "Latency test threat".to_string(),
        blocked: false,
        timestamp: chrono::Utc::now(),
        context: None,
    };

    // Measure write-read latency
    let mut latencies = Vec::new();
    
    for _ in 0..100 {
        let start = Instant::now();
        
        writer.write_threat(&threat).unwrap();
        let _read = reader.shm.read_threat().unwrap().unwrap();
        
        let latency = start.elapsed();
        latencies.push(latency.as_micros());
    }

    // Calculate average
    let avg = latencies.iter().sum::<u128>() / latencies.len() as u128;
    println!("Average write-read latency: {}μs", avg);

    // Should be well under 1ms
    assert!(avg < 1000);
}

#[tokio::test]
async fn test_shm_buffer_full() {
    if !SharedMemoryIpc::is_available() {
        println!("Shared memory not available, skipping test");
        return;
    }

    let mut config = ShmConfig::default();
    config.buffer_size = 8192; // Small buffer for testing
    config.max_events = 10;

    let mut writer = SharedMemoryIpc::new(config).unwrap();

    // Fill the buffer
    let mut success_count = 0;
    for i in 0..20 {
        let threat = Threat {
            id: format!("overflow-{}", i),
            threat_type: ThreatType::RateLimitViolation,
            severity: Severity::Medium,
            source: "overflow-test".to_string(),
            details: format!("This is a longer threat description to fill the buffer more quickly. Threat number: {}", i),
            blocked: false,
            timestamp: chrono::Utc::now(),
            context: None,
        };

        match writer.write_threat(&threat) {
            Ok(()) => success_count += 1,
            Err(e) => {
                println!("Buffer full at threat {}: {}", i, e);
                break;
            }
        }
    }

    // Should have written some but not all
    assert!(success_count > 5);
    assert!(success_count < 20);
}