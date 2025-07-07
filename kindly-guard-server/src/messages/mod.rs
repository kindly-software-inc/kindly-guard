//! Friendly messaging system for KindlyGuard
//! 
//! Implements the "Kind to you, tough on threats" philosophy through
//! positive, encouraging messages while maintaining a strong security stance.

use std::fmt;
use std::sync::Arc;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod templates;
pub mod formatter;
pub mod personality;

pub use formatter::MessageFormatter;
pub use personality::{MessagePersonality, Mood, PersonalityContext};
pub use templates::MessageTemplates;

/// Type of message being displayed
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Positive reinforcement and encouragement
    PositiveReinforcement,
    /// Threat neutralization confirmations
    ThreatNeutralized,
    /// Interactive prompts for user input
    InteractivePrompt,
    /// Success celebrations
    SuccessCelebration,
    /// Quarantine notifications
    QuarantineNotification,
    /// Welcome messages
    Welcome,
    /// Status updates
    StatusUpdate,
    /// Security tips
    SecurityTip,
    /// All clear - no threats detected
    AllClear,
    /// Protection mode engaged
    ProtectionEngaged,
    /// Error messages
    Error,
}

/// Priority level for messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum MessagePriority {
    Low,
    Normal,
    High,
    Critical,
}

/// A friendly message with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FriendlyMessage {
    /// Unique identifier for the message
    pub id: String,
    /// Type of message
    pub message_type: MessageType,
    /// Priority level
    pub priority: MessagePriority,
    /// The actual message content
    pub content: String,
    /// Optional emoji or icon
    pub icon: Option<String>,
    /// Timestamp when the message was created
    pub timestamp: DateTime<Utc>,
    /// Additional context or details
    pub context: Option<MessageContext>,
}

/// Additional context for messages
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContext {
    /// Number of threats handled (if applicable)
    pub threats_count: Option<usize>,
    /// Success rate percentage (if applicable)
    pub success_rate: Option<f64>,
    /// Time elapsed for an operation
    pub elapsed_time: Option<std::time::Duration>,
    /// Related file or resource
    pub resource: Option<String>,
    /// Additional key-value pairs
    pub metadata: std::collections::HashMap<String, String>,
}

impl FriendlyMessage {
    /// Create a new friendly message
    pub fn new(
        message_type: MessageType,
        content: impl Into<String>,
        priority: MessagePriority,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            message_type,
            priority,
            content: content.into(),
            icon: None,
            timestamp: Utc::now(),
            context: None,
        }
    }

    /// Add an icon to the message
    pub fn with_icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Add context to the message
    pub fn with_context(mut self, context: MessageContext) -> Self {
        self.context = Some(context);
        self
    }

    /// Create a positive reinforcement message
    pub fn positive(content: impl Into<String>) -> Self {
        Self::new(MessageType::PositiveReinforcement, content, MessagePriority::Normal)
            .with_icon("✨")
    }

    /// Create a threat neutralized message
    pub fn threat_neutralized(content: impl Into<String>) -> Self {
        Self::new(MessageType::ThreatNeutralized, content, MessagePriority::High)
            .with_icon("🛡️")
    }

    /// Create an interactive prompt
    pub fn prompt(content: impl Into<String>) -> Self {
        Self::new(MessageType::InteractivePrompt, content, MessagePriority::Normal)
            .with_icon("💬")
    }

    /// Create a success celebration
    pub fn celebrate(content: impl Into<String>) -> Self {
        Self::new(MessageType::SuccessCelebration, content, MessagePriority::High)
            .with_icon("🎉")
    }

    /// Create a quarantine notification
    pub fn quarantine(content: impl Into<String>) -> Self {
        Self::new(MessageType::QuarantineNotification, content, MessagePriority::Critical)
            .with_icon("🔒")
    }
}

impl FriendlyMessage {
    /// Format the message with optional color and emoji
    pub fn format(&self, color: bool, emoji: bool) -> String {
        let mut result = String::new();
        
        // Add icon if requested and available
        if emoji && self.icon.is_some() {
            result.push_str(self.icon.as_ref().unwrap());
            result.push(' ');
        }
        
        // Add color if requested
        if color {
            let color_code = match self.message_type {
                MessageType::Welcome => "\x1b[36m",       // Cyan
                MessageType::AllClear => "\x1b[32m",      // Green
                MessageType::ThreatNeutralized => "\x1b[33m", // Yellow
                MessageType::InteractivePrompt => "\x1b[35m", // Magenta
                MessageType::SuccessCelebration => "\x1b[32m", // Green
                MessageType::QuarantineNotification => "\x1b[34m", // Blue
                MessageType::ProtectionEngaged => "\x1b[33m", // Yellow
                MessageType::SecurityTip => "\x1b[36m",   // Cyan
                MessageType::Error => "\x1b[31m",         // Red
                MessageType::PositiveReinforcement => "\x1b[32m", // Green
                MessageType::StatusUpdate => "\x1b[37m",  // White
            };
            result.push_str(color_code);
            result.push_str(&self.content);
            result.push_str("\x1b[0m"); // Reset
        } else {
            result.push_str(&self.content);
        }
        
        result
    }
}

impl fmt::Display for FriendlyMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(icon) = &self.icon {
            write!(f, "{} ", icon)?;
        }
        write!(f, "{}", self.content)?;
        
        if let Some(context) = &self.context {
            if let Some(count) = context.threats_count {
                write!(f, " ({} threats handled)", count)?;
            }
            if let Some(rate) = context.success_rate {
                write!(f, " ({}% success rate)", rate)?;
            }
        }
        
        Ok(())
    }
}

/// Message builder for creating complex messages
pub struct MessageBuilder {
    message_type: MessageType,
    priority: MessagePriority,
    content: String,
    icon: Option<String>,
    context: MessageContext,
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(message_type: MessageType) -> Self {
        Self {
            message_type,
            priority: MessagePriority::Normal,
            content: String::new(),
            icon: None,
            context: MessageContext {
                threats_count: None,
                success_rate: None,
                elapsed_time: None,
                resource: None,
                metadata: std::collections::HashMap::new(),
            },
        }
    }

    /// Set the message content
    pub fn content(mut self, content: impl Into<String>) -> Self {
        self.content = content.into();
        self
    }

    /// Set the priority
    pub fn priority(mut self, priority: MessagePriority) -> Self {
        self.priority = priority;
        self
    }

    /// Set the icon
    pub fn icon(mut self, icon: impl Into<String>) -> Self {
        self.icon = Some(icon.into());
        self
    }

    /// Set the threat count
    pub fn threats_count(mut self, count: usize) -> Self {
        self.context.threats_count = Some(count);
        self
    }

    /// Set the success rate
    pub fn success_rate(mut self, rate: f64) -> Self {
        self.context.success_rate = Some(rate);
        self
    }

    /// Set the elapsed time
    pub fn elapsed_time(mut self, duration: std::time::Duration) -> Self {
        self.context.elapsed_time = Some(duration);
        self
    }

    /// Set the related resource
    pub fn resource(mut self, resource: impl Into<String>) -> Self {
        self.context.resource = Some(resource.into());
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.metadata.insert(key.into(), value.into());
        self
    }

    /// Build the message
    pub fn build(self) -> FriendlyMessage {
        let mut message = FriendlyMessage::new(self.message_type, self.content, self.priority);
        
        if let Some(icon) = self.icon {
            message = message.with_icon(icon);
        }
        
        message.with_context(self.context)
    }
}

/// Message service for managing and delivering friendly messages
pub struct MessageService {
    formatter: Arc<MessageFormatter>,
    templates: Arc<MessageTemplates>,
    personality: Arc<MessagePersonality>,
}

impl MessageService {
    /// Create a new message service
    pub fn new() -> Self {
        Self {
            formatter: Arc::new(MessageFormatter::new()),
            templates: Arc::new(MessageTemplates::new()),
            personality: Arc::new(MessagePersonality::new()),
        }
    }

    /// Generate a welcome message
    pub fn welcome(&self, user_name: Option<&str>) -> FriendlyMessage {
        let template = self.templates.get_welcome_message(user_name);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::new(MessageType::Welcome, formatted, MessagePriority::Normal)
            .with_icon("👋")
    }

    /// Generate a threat neutralized message
    pub fn threat_neutralized(&self, threat_type: &str, count: usize) -> FriendlyMessage {
        let template = self.templates.get_threat_neutralized_message(threat_type, count);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        MessageBuilder::new(MessageType::ThreatNeutralized)
            .content(formatted)
            .priority(MessagePriority::High)
            .icon("🛡️")
            .threats_count(count)
            .build()
    }

    /// Generate a success celebration
    pub fn celebrate_success(&self, achievement: &str) -> FriendlyMessage {
        let template = self.templates.get_celebration_message(achievement);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::celebrate(formatted)
    }

    /// Generate a quarantine notification
    pub fn quarantine_notification(&self, file_path: &str, reason: &str) -> FriendlyMessage {
        let template = self.templates.get_quarantine_message(file_path, reason);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        MessageBuilder::new(MessageType::QuarantineNotification)
            .content(formatted)
            .priority(MessagePriority::Critical)
            .icon("🔒")
            .resource(file_path)
            .metadata("reason", reason)
            .build()
    }

    /// Generate an interactive prompt
    pub fn prompt(&self, question: &str, options: &[&str]) -> FriendlyMessage {
        let template = self.templates.get_prompt_message(question, options);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::prompt(formatted)
    }

    /// Generate a positive reinforcement message
    pub fn encourage(&self) -> FriendlyMessage {
        let template = self.templates.get_encouragement_message();
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::positive(formatted)
    }

    /// Generate a security tip
    pub fn security_tip(&self) -> FriendlyMessage {
        let template = self.templates.get_security_tip();
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::new(MessageType::SecurityTip, formatted, MessagePriority::Low)
            .with_icon("💡")
    }

    /// Set the mood of the message personality
    pub fn set_mood(&self, mood: Mood) {
        self.personality.set_mood(mood);
    }
    
    /// Adapt personality to context
    pub fn adapt_to_context(&self, context: PersonalityContext) {
        self.personality.adapt_to_context(context);
    }
    
    /// Generate an all clear message (no threats detected)
    pub fn all_clear(&self) -> FriendlyMessage {
        let template = self.templates.get_all_clear_message();
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::new(MessageType::AllClear, formatted, MessagePriority::Normal)
            .with_icon("✅")
    }
    
    /// Generate a protection engaged message
    pub fn protection_engaged(&self, threat_count: usize) -> FriendlyMessage {
        let template = self.templates.get_protection_engaged_message(threat_count);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        MessageBuilder::new(MessageType::ProtectionEngaged)
            .content(formatted)
            .priority(MessagePriority::High)
            .icon("🚨")
            .threats_count(threat_count)
            .build()
    }
    
    /// Generate an interactive prompt for a specific threat
    pub fn interactive_prompt(&self, threat_type: &str) -> FriendlyMessage {
        let template = self.templates.get_interactive_prompt(threat_type);
        let formatted = self.formatter.format_with_personality(&template, &self.personality);
        
        FriendlyMessage::prompt(formatted)
    }
}

impl Default for MessageService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation() {
        let message = FriendlyMessage::positive("Great job!");
        assert_eq!(message.message_type, MessageType::PositiveReinforcement);
        assert_eq!(message.icon, Some("✨".to_string()));
    }

    #[test]
    fn test_message_builder() {
        let message = MessageBuilder::new(MessageType::ThreatNeutralized)
            .content("Successfully blocked SQL injection attempt")
            .priority(MessagePriority::High)
            .icon("🛡️")
            .threats_count(5)
            .success_rate(100.0)
            .build();

        assert_eq!(message.message_type, MessageType::ThreatNeutralized);
        assert_eq!(message.priority, MessagePriority::High);
        assert_eq!(message.context.as_ref().unwrap().threats_count, Some(5));
        assert_eq!(message.context.as_ref().unwrap().success_rate, Some(100.0));
    }

    #[test]
    fn test_message_service() {
        let service = MessageService::new();
        
        let welcome = service.welcome(Some("Alice"));
        assert_eq!(welcome.message_type, MessageType::Welcome);
        
        let threat = service.threat_neutralized("SQL Injection", 3);
        assert_eq!(threat.message_type, MessageType::ThreatNeutralized);
        assert_eq!(threat.context.as_ref().unwrap().threats_count, Some(3));
    }
}