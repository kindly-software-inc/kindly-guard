//! Demo of the friendly messages system

use kindly_guard_server::messages::{
    MessageService, MessageBuilder, MessageType, Mood, PersonalityContext
};
use kindly_guard_server::scanner::{Threat, ThreatType, Severity, Location};
use kindly_guard_server::shield::{Shield, message_integration::ShieldMessageHandler};
use std::sync::Arc;

fn main() {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("=== KindlyGuard Friendly Messages Demo ===\n");

    // Create message service
    let service = MessageService::new();

    // 1. Welcome message
    println!("1. Welcome Message:");
    let welcome = service.welcome(Some("Alice"));
    println!("{}\n", welcome);

    // 2. Threat neutralization messages
    println!("2. Threat Neutralization:");
    let sql_threat = service.threat_neutralized("SQL Injection", 3);
    println!("{}", sql_threat);
    
    let xss_threat = service.threat_neutralized("XSS", 1);
    println!("{}\n", xss_threat);

    // 3. Success celebration
    println!("3. Success Celebration:");
    let success = service.celebrate_success("Reached 100 days without security incidents");
    println!("{}\n", success);

    // 4. Quarantine notification
    println!("4. Quarantine Notification:");
    let quarantine = service.quarantine_notification(
        "/tmp/malicious.js",
        "contains obfuscated JavaScript code"
    );
    println!("{}\n", quarantine);

    // 5. Interactive prompt
    println!("5. Interactive Prompt:");
    let prompt = service.prompt(
        "A suspicious file was detected. What would you like to do?",
        &["Quarantine it", "Allow once", "Inspect details", "Cancel"]
    );
    println!("{}\n", prompt);

    // 6. Encouragement
    println!("6. Encouragement:");
    let encouragement = service.encourage();
    println!("{}\n", encouragement);

    // 7. Security tip
    println!("7. Security Tip:");
    let tip = service.security_tip();
    println!("{}\n", tip);

    // Demonstrate mood changes
    println!("=== Mood Demonstrations ===\n");

    // Professional mode
    println!("8. Professional Mode:");
    service.set_mood(Mood::Professional);
    let professional = service.threat_neutralized("Command Injection", 2);
    println!("{}\n", professional);

    // Serious mode (for incidents)
    println!("9. Serious Mode (Security Incident):");
    service.set_mood(Mood::Serious);
    let serious = service.threat_neutralized("Multiple Attack Vectors", 15);
    println!("{}\n", serious);

    // Shield integration demo
    println!("=== Shield Integration Demo ===\n");

    let shield = Arc::new(Shield::new());
    let shield_handler = ShieldMessageHandler::new(shield.clone());

    // Simulate shield activation
    println!("10. Shield Activation:");
    let activation = shield_handler.on_shield_activated();
    println!("{}\n", activation);

    // Simulate threat detection
    println!("11. Threat Detection with Shield:");
    let threats = vec![
        Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text { offset: 42, length: 30 },
            description: "Unparameterized SQL query detected: SELECT * FROM users WHERE id = '{}'".to_string(),
            remediation: Some("Use parameterized queries".to_string()),
        },
        Threat {
            threat_type: ThreatType::CrossSiteScripting,
            severity: Severity::Medium,
            location: Location::Text { offset: 156, length: 29 },
            description: "Unescaped user input in HTML: <script>alert('xss')</script>".to_string(),
            remediation: Some("Escape HTML entities".to_string()),
        },
    ];

    shield.record_threats(&threats);
    let threat_messages = shield_handler.on_threats_detected(&threats);
    for msg in threat_messages {
        println!("{}", msg);
    }
    println!();

    // Status update
    println!("12. Status Update:");
    let status = shield_handler.status_update();
    println!("{}\n", status);

    // Demonstrate message building
    println!("=== Advanced Message Building ===\n");

    println!("13. Custom Message with Context:");
    let custom = MessageBuilder::new(MessageType::ThreatNeutralized)
        .content("Advanced persistent threat detected and neutralized")
        .icon("🔥")
        .threats_count(42)
        .success_rate(99.9)
        .elapsed_time(std::time::Duration::from_secs(3))
        .resource("api/v2/users")
        .metadata("attack_vector", "sql_injection")
        .metadata("source_ip", "192.168.1.100")
        .build();
    println!("{}\n", custom);

    // Demonstrate personality contexts
    println!("=== Personality Contexts ===\n");

    println!("14. First Time User:");
    service.adapt_to_context(PersonalityContext::FirstTimeUser);
    let first_time = service.welcome(Some("New User"));
    println!("{}\n", first_time);

    println!("15. Major Achievement:");
    service.adapt_to_context(PersonalityContext::MajorAchievement);
    let achievement = service.celebrate_success("1 Million Threats Blocked!");
    println!("{}\n", achievement);

    println!("Demo complete! KindlyGuard - Kind to you, tough on threats! 🛡️");
}