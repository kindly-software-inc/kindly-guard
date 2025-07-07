//! Integration of friendly messages with the shield display

use std::sync::Arc;
use crate::messages::{MessageService, MessageType, FriendlyMessage, MessageBuilder, Mood};
use crate::scanner::{Threat, ThreatType};
use crate::shield::Shield;

/// Shield message handler for integrating friendly messages
pub struct ShieldMessageHandler {
    shield: Arc<Shield>,
    message_service: Arc<MessageService>,
}

impl ShieldMessageHandler {
    /// Create a new shield message handler
    pub fn new(shield: Arc<Shield>) -> Self {
        Self {
            shield,
            message_service: Arc::new(MessageService::new()),
        }
    }

    /// Handle shield activation
    pub fn on_shield_activated(&self) -> FriendlyMessage {
        self.message_service.set_mood(Mood::Cheerful);
        self.message_service.welcome(None)
    }

    /// Handle threat detection
    pub fn on_threats_detected(&self, threats: &[Threat]) -> Vec<FriendlyMessage> {
        let mut messages = Vec::new();
        
        // Group threats by type
        let mut threat_groups: std::collections::HashMap<String, Vec<&Threat>> = std::collections::HashMap::new();
        
        for threat in threats {
            let threat_type = match &threat.threat_type {
                ThreatType::SqlInjection => "SQL Injection",
                ThreatType::CommandInjection => "Command Injection",
                ThreatType::CrossSiteScripting => "XSS",
                ThreatType::UnicodeInvisible | ThreatType::UnicodeBiDi | ThreatType::UnicodeHomograph => "Unicode",
                ThreatType::PathTraversal => "Path Traversal",
                ThreatType::PromptInjection => "Prompt Injection",
                _ => "Generic",
            };
            
            threat_groups.entry(threat_type.to_string()).or_default().push(threat);
        }
        
        // Generate messages for each threat type
        for (threat_type, threats_of_type) in threat_groups {
            let message = self.message_service.threat_neutralized(&threat_type, threats_of_type.len());
            messages.push(message);
        }
        
        // Add encouragement if many threats were blocked
        if threats.len() > 5 {
            self.message_service.set_mood(Mood::Encouraging);
            messages.push(self.message_service.encourage());
        }
        
        messages
    }

    /// Handle milestone achievements
    pub fn on_milestone_reached(&self, milestone: ShieldMilestone) -> FriendlyMessage {
        self.message_service.set_mood(Mood::Celebratory);
        
        let achievement = match milestone {
            ShieldMilestone::FirstThreatBlocked => "Blocked your first threat",
            ShieldMilestone::HundredThreatsBlocked => "Blocked 100 threats",
            ShieldMilestone::ThousandThreatsBlocked => "Blocked 1,000 threats",
            ShieldMilestone::OneDayUptime => "Protected for 24 hours",
            ShieldMilestone::OneWeekUptime => "Protected for one week",
            ShieldMilestone::PerfectDefenseHour => "Perfect defense for one hour",
        };
        
        self.message_service.celebrate_success(achievement)
    }

    /// Handle quarantine events
    pub fn on_file_quarantined(&self, file_path: &str, threat: &Threat) -> FriendlyMessage {
        let reason = format!("{}: {}", threat.threat_type, threat.description);
        self.message_service.quarantine_notification(file_path, &reason)
    }

    /// Generate status update message
    pub fn status_update(&self) -> FriendlyMessage {
        let info = self.shield.get_info();
        
        if info.threats_blocked == 0 {
            MessageBuilder::new(MessageType::StatusUpdate)
                .content("All quiet on the security front! No threats detected.")
                .icon("✅")
                .build()
        } else if info.recent_threat_rate > 10.0 {
            // Adapt to security incident context
            MessageBuilder::new(MessageType::StatusUpdate)
                .content(format!(
                    "High threat activity detected! {} threats/min. Enhanced protection active.",
                    info.recent_threat_rate as u32
                ))
                .icon("🚨")
                .threats_count(info.threats_blocked as usize)
                .build()
        } else {
            MessageBuilder::new(MessageType::StatusUpdate)
                .content(format!(
                    "Shield active for {}. {} total threats blocked.",
                    format_duration(info.uptime),
                    info.threats_blocked
                ))
                .icon("🛡️")
                .threats_count(info.threats_blocked as usize)
                .elapsed_time(info.uptime)
                .build()
        }
    }

    /// Generate security tip
    pub fn get_security_tip(&self) -> FriendlyMessage {
        self.message_service.security_tip()
    }

    /// Handle user interaction prompts
    pub fn create_action_prompt(&self, threat: &Threat) -> FriendlyMessage {
        let question = format!(
            "A {} threat was detected in '{}'",
            threat.threat_type,
            threat.description.chars().take(50).collect::<String>()
        );
        
        let options = &[
            "Block and quarantine",
            "Allow this time only",
            "Add to exceptions",
            "View details",
        ];
        
        self.message_service.prompt(&question, options)
    }

    /// Check for milestones
    pub fn check_milestones(&self) -> Option<ShieldMilestone> {
        let info = self.shield.get_info();
        let stats = self.shield.stats();
        
        // Check threat count milestones
        match stats.threats_blocked {
            1 => Some(ShieldMilestone::FirstThreatBlocked),
            100 => Some(ShieldMilestone::HundredThreatsBlocked),
            1000 => Some(ShieldMilestone::ThousandThreatsBlocked),
            _ => {
                // Check uptime milestones
                let uptime_secs = info.uptime.as_secs();
                match uptime_secs {
                    86400 => Some(ShieldMilestone::OneDayUptime),
                    604800 => Some(ShieldMilestone::OneWeekUptime),
                    _ => {
                        // Check perfect defense
                        if uptime_secs >= 3600 && info.recent_threat_rate == 0.0 {
                            Some(ShieldMilestone::PerfectDefenseHour)
                        } else {
                            None
                        }
                    }
                }
            }
        }
    }
}

/// Shield milestones for celebration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldMilestone {
    FirstThreatBlocked,
    HundredThreatsBlocked,
    ThousandThreatsBlocked,
    OneDayUptime,
    OneWeekUptime,
    PerfectDefenseHour,
}

/// Format duration in a friendly way
fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    
    if secs < 60 {
        format!("{} seconds", secs)
    } else if secs < 3600 {
        let mins = secs / 60;
        format!("{} minute{}", mins, if mins == 1 { "" } else { "s" })
    } else if secs < 86400 {
        let hours = secs / 3600;
        let mins = (secs % 3600) / 60;
        if mins > 0 {
            format!("{} hour{} {} minute{}", 
                hours, if hours == 1 { "" } else { "s" },
                mins, if mins == 1 { "" } else { "s" }
            )
        } else {
            format!("{} hour{}", hours, if hours == 1 { "" } else { "s" })
        }
    } else {
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        if hours > 0 {
            format!("{} day{} {} hour{}", 
                days, if days == 1 { "" } else { "s" },
                hours, if hours == 1 { "" } else { "s" }
            )
        } else {
            format!("{} day{}", days, if days == 1 { "" } else { "s" })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::{Location, Severity};

    fn create_test_threat() -> Threat {
        Threat {
            threat_type: ThreatType::SqlInjection,
            severity: Severity::High,
            location: Location::Text { offset: 0, length: 23 },
            description: "SQL injection attempt detected in query: '; DROP TABLE users; --".to_string(),
            remediation: Some("Use parameterized queries".to_string()),
        }
    }

    #[test]
    fn test_shield_activation() {
        let shield = Arc::new(Shield::new());
        let handler = ShieldMessageHandler::new(shield);
        
        let message = handler.on_shield_activated();
        assert_eq!(message.message_type, MessageType::Welcome);
    }

    #[test]
    fn test_threat_messages() {
        let shield = Arc::new(Shield::new());
        let handler = ShieldMessageHandler::new(shield);
        
        let threats = vec![create_test_threat()];
        let messages = handler.on_threats_detected(&threats);
        
        assert!(!messages.is_empty());
        assert_eq!(messages[0].message_type, MessageType::ThreatNeutralized);
    }

    #[test]
    fn test_milestone_detection() {
        let shield = Arc::new(Shield::new());
        shield.record_threats(&[create_test_threat()]);
        
        let handler = ShieldMessageHandler::new(shield);
        let milestone = handler.check_milestones();
        
        assert_eq!(milestone, Some(ShieldMilestone::FirstThreatBlocked));
    }

    #[test]
    fn test_duration_formatting() {
        use std::time::Duration;
        
        assert_eq!(format_duration(Duration::from_secs(30)), "30 seconds");
        assert_eq!(format_duration(Duration::from_secs(60)), "1 minute");
        assert_eq!(format_duration(Duration::from_secs(90)), "1 minute");
        assert_eq!(format_duration(Duration::from_secs(3600)), "1 hour");
        assert_eq!(format_duration(Duration::from_secs(3660)), "1 hour 1 minute");
        assert_eq!(format_duration(Duration::from_secs(86400)), "1 day");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1 day 1 hour");
    }
}