//! Message formatting with personality and style

use crate::messages::personality::{MessagePersonality, Mood};
use chrono::{DateTime, Local, Utc};

/// Message formatter for applying personality and styling to messages
pub struct MessageFormatter {
    /// Color support detection
    color_enabled: bool,
    /// Unicode support detection
    unicode_enabled: bool,
    /// Terminal width for wrapping
    terminal_width: usize,
}

impl MessageFormatter {
    /// Create a new message formatter
    pub fn new() -> Self {
        Self {
            color_enabled: Self::detect_color_support(),
            unicode_enabled: Self::detect_unicode_support(),
            terminal_width: Self::detect_terminal_width(),
        }
    }

    /// Format a message with personality applied
    pub fn format_with_personality(&self, message: &str, personality: &MessagePersonality) -> String {
        let mut formatted = message.to_string();
        
        // Apply mood modifiers
        formatted = self.apply_mood(&formatted, personality.current_mood());
        
        // Apply personality traits
        formatted = self.apply_personality_traits(&formatted, personality);
        
        // Apply formatting
        formatted = self.apply_formatting(&formatted);
        
        formatted
    }

    /// Apply mood-based modifications to the message
    fn apply_mood(&self, message: &str, mood: Mood) -> String {
        match mood {
            Mood::Cheerful => {
                // Add extra enthusiasm
                message
                    .replace("!", "! ")
                    .replace(".", "! ")
                    .trim()
                    .to_string()
            }
            Mood::Professional => {
                // Keep it clean and professional
                message.to_string()
            }
            Mood::Encouraging => {
                // Add encouraging phrases
                format!("{} You've got this!", message)
            }
            Mood::Celebratory => {
                // Add celebration elements
                if self.unicode_enabled {
                    format!("🎊 {} 🎊", message)
                } else {
                    format!("*** {} ***", message)
                }
            }
            Mood::Serious => {
                // Remove exclamation marks for a more serious tone
                message.replace("!", ".").to_string()
            }
        }
    }

    /// Apply personality traits to the message
    fn apply_personality_traits(&self, message: &str, personality: &MessagePersonality) -> String {
        let mut result = message.to_string();
        
        // Apply friendliness level
        if personality.friendliness_level() > 0.8 {
            result = self.make_extra_friendly(&result);
        }
        
        // Apply formality level
        if personality.formality_level() < 0.3 {
            result = self.make_casual(&result);
        } else if personality.formality_level() > 0.7 {
            result = self.make_formal(&result);
        }
        
        result
    }

    /// Make the message extra friendly
    fn make_extra_friendly(&self, message: &str) -> String {
        let friendly_replacements = vec![
            ("blocked", "safely blocked"),
            ("detected", "spotted"),
            ("neutralized", "taken care of"),
            ("eliminated", "handled"),
            ("stopped", "prevented"),
        ];
        
        let mut result = message.to_string();
        for (from, to) in friendly_replacements {
            result = result.replace(from, to);
        }
        
        result
    }

    /// Make the message more casual
    fn make_casual(&self, message: &str) -> String {
        let casual_replacements = vec![
            ("Hello", "Hey"),
            ("Greetings", "Hi there"),
            ("Excellent", "Awesome"),
            ("Congratulations", "Congrats"),
        ];
        
        let mut result = message.to_string();
        for (from, to) in casual_replacements {
            result = result.replace(from, to);
        }
        
        result
    }

    /// Make the message more formal
    fn make_formal(&self, message: &str) -> String {
        let formal_replacements = vec![
            ("Hey", "Greetings"),
            ("Hi", "Hello"),
            ("Awesome", "Excellent"),
            ("Congrats", "Congratulations"),
        ];
        
        let mut result = message.to_string();
        for (from, to) in formal_replacements {
            result = result.replace(from, to);
        }
        
        result
    }

    /// Apply visual formatting (colors, styles)
    fn apply_formatting(&self, message: &str) -> String {
        if !self.color_enabled {
            return message.to_string();
        }
        
        // Apply color based on content
        if message.contains("threat") || message.contains("blocked") || message.contains("neutralized") {
            self.colorize(message, Color::Red)
        } else if message.contains("success") || message.contains("celebrate") || message.contains("achievement") {
            self.colorize(message, Color::Green)
        } else if message.contains("tip") || message.contains("hint") {
            self.colorize(message, Color::Yellow)
        } else {
            message.to_string()
        }
    }

    /// Apply color to text
    fn colorize(&self, text: &str, color: Color) -> String {
        if !self.color_enabled {
            return text.to_string();
        }
        
        match color {
            Color::Red => format!("\x1b[31m{}\x1b[0m", text),
            Color::Green => format!("\x1b[32m{}\x1b[0m", text),
            Color::Yellow => format!("\x1b[33m{}\x1b[0m", text),
            Color::Blue => format!("\x1b[34m{}\x1b[0m", text),
            Color::Magenta => format!("\x1b[35m{}\x1b[0m", text),
            Color::Cyan => format!("\x1b[36m{}\x1b[0m", text),
        }
    }

    /// Format a timestamp in a friendly way
    pub fn format_timestamp(&self, timestamp: &DateTime<Utc>) -> String {
        let local_time: DateTime<Local> = (*timestamp).into();
        let now = Local::now();
        let duration = now.signed_duration_since(local_time);
        
        if duration.num_seconds() < 60 {
            "just now".to_string()
        } else if duration.num_minutes() < 60 {
            format!("{} minute{} ago", 
                duration.num_minutes(), 
                if duration.num_minutes() == 1 { "" } else { "s" }
            )
        } else if duration.num_hours() < 24 {
            format!("{} hour{} ago", 
                duration.num_hours(), 
                if duration.num_hours() == 1 { "" } else { "s" }
            )
        } else {
            local_time.format("%Y-%m-%d %H:%M").to_string()
        }
    }

    /// Wrap text to terminal width
    pub fn wrap_text(&self, text: &str, indent: usize) -> String {
        if text.len() <= self.terminal_width - indent {
            return text.to_string();
        }
        
        let words: Vec<&str> = text.split_whitespace().collect();
        let mut lines = vec![];
        let mut current_line = String::new();
        let max_width = self.terminal_width - indent;
        
        for word in words {
            if current_line.is_empty() {
                current_line = word.to_string();
            } else if current_line.len() + 1 + word.len() <= max_width {
                current_line.push(' ');
                current_line.push_str(word);
            } else {
                lines.push(current_line);
                current_line = word.to_string();
            }
        }
        
        if !current_line.is_empty() {
            lines.push(current_line);
        }
        
        lines.join(&format!("\n{}", " ".repeat(indent)))
    }

    /// Detect if terminal supports colors
    fn detect_color_support() -> bool {
        // Check common environment variables
        if std::env::var("NO_COLOR").is_ok() {
            return false;
        }
        
        if let Ok(term) = std::env::var("TERM") {
            if term == "dumb" {
                return false;
            }
        }
        
        // Default to true for modern terminals
        true
    }

    /// Detect if terminal supports Unicode
    fn detect_unicode_support() -> bool {
        // Check locale settings
        if let Ok(lang) = std::env::var("LANG") {
            return lang.to_lowercase().contains("utf");
        }
        
        // Default to true for modern systems
        true
    }

    /// Detect terminal width
    fn detect_terminal_width() -> usize {
        // Try to get actual terminal width using crossterm
        if let Ok((width, _)) = crossterm::terminal::size() {
            return width as usize;
        }
        
        // Default to 80 columns
        80
    }
}

impl Default for MessageFormatter {
    fn default() -> Self {
        Self::new()
    }
}

/// Colors for terminal output
#[derive(Debug, Clone, Copy)]
enum Color {
    Red,
    Green,
    Yellow,
    #[allow(dead_code)]
    Blue,
    #[allow(dead_code)]
    Magenta,
    #[allow(dead_code)]
    Cyan,
}

/// Format options for messages
#[derive(Debug, Clone)]
pub struct FormatOptions {
    /// Whether to use colors
    pub use_colors: bool,
    /// Whether to use Unicode characters
    pub use_unicode: bool,
    /// Maximum line width
    pub max_width: Option<usize>,
    /// Indentation level
    pub indent: usize,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            use_colors: true,
            use_unicode: true,
            max_width: None,
            indent: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_formatter_creation() {
        let formatter = MessageFormatter::new();
        assert!(formatter.terminal_width > 0);
    }

    #[test]
    fn test_mood_application() {
        let formatter = MessageFormatter::new();
        
        let cheerful = formatter.apply_mood("Test message.", Mood::Cheerful);
        assert_eq!(cheerful, "Test message!");
        
        let serious = formatter.apply_mood("Test message!", Mood::Serious);
        assert_eq!(serious, "Test message.");
    }

    #[test]
    fn test_text_wrapping() {
        let formatter = MessageFormatter {
            color_enabled: false,
            unicode_enabled: true,
            terminal_width: 20,
        };
        
        let wrapped = formatter.wrap_text("This is a very long message that should be wrapped", 0);
        assert!(wrapped.contains('\n'));
    }

    #[test]
    fn test_timestamp_formatting() {
        let formatter = MessageFormatter::new();
        let now = Utc::now();
        
        let formatted = formatter.format_timestamp(&now);
        assert_eq!(formatted, "just now");
    }
}