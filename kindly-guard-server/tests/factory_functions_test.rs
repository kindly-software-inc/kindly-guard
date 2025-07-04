// Test the factory functions we just created
use kindly_guard_server::{
    config::Config,
    create_scanner,
    create_storage,
    create_rate_limiter,
    create_transport,
    create_telemetry,
    create_audit_logger,
};

#[test]
fn test_create_scanner() {
    let config = Config::default();
    let scanner = create_scanner(&config);
    assert!(!scanner.scan_text("test").unwrap().is_empty() == false); // Should scan without panicking
}

#[test]
fn test_create_storage() {
    let config = Config::default();
    let storage = create_storage(&config);
    // Just verify it creates without panicking
    assert!(std::sync::Arc::strong_count(&storage) >= 1);
}

#[test]
fn test_create_rate_limiter() {
    let config = Config::default();
    let rate_limiter = create_rate_limiter(&config);
    // Just verify it creates without panicking
    assert!(std::sync::Arc::strong_count(&rate_limiter) >= 1);
}

#[test]
fn test_create_transport() {
    let config = Config::default();
    let transport = create_transport(&config);
    // Just verify it creates without panicking
    assert!(std::sync::Arc::strong_count(&transport) >= 1);
}

#[test]
fn test_create_telemetry() {
    let config = Config::default();
    let telemetry = create_telemetry(&config);
    // Just verify it creates without panicking
    assert!(std::sync::Arc::strong_count(&telemetry) >= 1);
}

#[test]
fn test_create_audit_logger() {
    let config = Config::default();
    let audit_logger = create_audit_logger(&config);
    // Just verify it creates without panicking
    assert!(std::sync::Arc::strong_count(&audit_logger) >= 1);
}

#[tokio::test]
async fn test_rate_limiter_basic() {
    let config = Config::default();
    let rate_limiter = create_rate_limiter(&config);
    
    // Basic check_limit test
    let result = rate_limiter.check_limit("test_client", None, 1.0).await.unwrap();
    assert!(result.allowed); // Should allow first request
}