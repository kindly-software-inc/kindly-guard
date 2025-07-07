use colored::Colorize;
use kindly_guard_server::scanner::ThreatType;

/// Friendly messaging system for KindlyGuard
/// "Kind to you, tough on threats"
pub struct Messages;

impl Messages {
    /// Display when no threats are found
    pub fn all_clear() -> String {
        format!(
            "{} {}\n   {}\n   {} {}",
            "✅".bright_green(),
            "All Clear! Your content is squeaky clean!".bright_green().bold(),
            "KindlyGuard checked every corner and found nothing suspicious.",
            "You're good to go!",
            "🛡️"
        )
    }

    /// Display when threats are found and neutralized
    pub fn threats_neutralized(threat_count: usize, threat_summary: &str) -> String {
        format!(
            "{} {}\n   {}\n\n{}\n\n   {} {}",
            "🛡️".bright_cyan(),
            "KindlyGuard Protected You!".bright_cyan().bold(),
            format!("Found and neutralized {} threats - you're safe now!", threat_count).bright_white(),
            threat_summary,
            "💚".bright_green(),
            "Kind to you, tough on threats - that's our promise!".italic()
        )
    }

    /// Display when threats are quarantined
    pub fn threats_quarantined(threat_count: usize, quarantine_path: &str) -> String {
        format!(
            "{} {}\n   {}\n   \n   {} {}\n   {} {}\n   \n   {} {}",
            "🔒".bright_yellow(),
            "Threats Quarantined for Your Safety".bright_yellow().bold(),
            format!("We've isolated {} high-risk threats in a secure quarantine.", threat_count),
            "Quarantine location:".bright_white(),
            quarantine_path.bright_cyan(),
            "Review quarantined content:".bright_white(),
            "kindlyguard quarantine --list".bright_cyan(),
            "You're protected! The threats can't hurt you now.",
            "🌟"
        )
    }

    /// Generate threat action summary
    pub fn threat_action_summary(threats: &[(ThreatType, String)]) -> String {
        let mut summary = String::from("   What we did:\n");
        
        for (threat_type, action) in threats {
            let icon = "•".bright_cyan();
            let threat_desc = Self::friendly_threat_description(threat_type);
            summary.push_str(&format!("   {} {} → {}\n", 
                icon, 
                threat_desc.bright_red(), 
                action.bright_green()
            ));
        }
        
        summary
    }

    /// Convert technical threat types to friendly descriptions
    pub fn friendly_threat_description(threat_type: &ThreatType) -> &'static str {
        match threat_type {
            ThreatType::SqlInjection => "Removed dangerous SQL injection",
            ThreatType::CrossSiteScripting => "Sanitized XSS attempts",
            ThreatType::CommandInjection => "Blocked command injection",
            ThreatType::PathTraversal => "Fixed directory traversal tricks",
            ThreatType::UnicodeInvisible => "Cleaned up invisible characters",
            ThreatType::UnicodeBiDi => "Fixed text direction tricks",
            ThreatType::UnicodeHomograph => "Replaced lookalike characters",
            ThreatType::UnicodeControl => "Removed control characters",
            ThreatType::LdapInjection => "Prevented LDAP injection",
            ThreatType::XmlInjection => "Blocked XML attacks",
            ThreatType::NoSqlInjection => "Stopped NoSQL injection",
            ThreatType::PromptInjection => "Prevented AI prompt manipulation",
            ThreatType::SessionIdExposure => "Protected session information",
            ThreatType::ToolPoisoning => "Removed malicious tool definitions",
            ThreatType::TokenTheft => "Secured authentication tokens",
            ThreatType::DosPotential => "Prevented denial of service",
            ThreatType::Custom(_) => "Fixed security issue",
        }
    }

    /// Display scanning progress
    pub fn scanning_progress(filename: &str) -> String {
        format!("{} Scanning {}...", "🔍".bright_cyan(), filename.bright_white())
    }

    /// Display scanning file
    pub fn scanning_file(filename: &str) -> String {
        format!("{} Scanning {}...", "🔍".bright_cyan(), filename.bright_white())
    }

    /// Display protection mode info
    pub fn protection_mode_info(mode: &str) -> String {
        match mode {
            "auto" => format!("{} {} {}", 
                "🛡️".bright_green(),
                "Auto-Protection Mode:".bright_green().bold(),
                "Threats will be automatically neutralized"
            ),
            "interactive" => format!("{} {} {}", 
                "🤝".bright_yellow(),
                "Interactive Mode:".bright_yellow().bold(),
                "You'll be asked about each threat"
            ),
            "report" => format!("{} {} {}", 
                "📋".bright_blue(),
                "Report-Only Mode:".bright_blue().bold(),
                "Threats will be reported but not neutralized"
            ),
            _ => String::new(),
        }
    }

    /// Display when starting neutralization
    pub fn neutralizing_threats(count: usize) -> String {
        format!(
            "{} {} {}",
            "💪".bright_green(),
            "Neutralizing".bright_green(),
            format!("{} threat{}...", count, if count == 1 { "" } else { "s" }).bright_white()
        )
    }

    /// Display when creating quarantine
    pub fn creating_quarantine() -> String {
        format!("{} Creating secure quarantine...", "📦".bright_yellow())
    }

    /// Success celebration (subtle)
    pub fn success_celebration() -> String {
        format!("\n{} {}", "✨".bright_green(), "Success! Your content is now safe to use.".bright_green())
    }

    /// Interactive prompt for threat
    pub fn interactive_threat_prompt(threat_type: &ThreatType, location: &str) -> String {
        format!(
            "{} Found {} at {}.\n   Neutralize this threat? [Y/n] ",
            "🔍".bright_yellow(),
            Self::friendly_threat_description(threat_type).bright_red(),
            location.bright_cyan()
        )
    }

    /// Display file saved message
    pub fn file_saved(path: &str) -> String {
        format!("{} Saved neutralized content to: {}", "💾".bright_green(), path.bright_cyan())
    }

    /// Display backup created message
    pub fn backup_created(path: &str) -> String {
        format!("{} Original backed up to: {}", "📂".bright_blue(), path.bright_cyan())
    }


    /// Display clean result
    pub fn clean_result() -> String {
        Self::all_clear()
    }

    /// Display protection summary
    pub fn protection_summary(threats_found: usize, threats_neutralized: usize, quarantined: bool) -> String {
        let mut summary = format!(
            "{} {}\n   Found {} threats, neutralized {}",
            "✅".bright_green(),
            "Protection Complete!".bright_green().bold(),
            threats_found,
            threats_neutralized
        );
        
        if quarantined {
            summary.push_str("\n   Original content has been quarantined for safety");
        }
        
        summary
    }

    /// Display quarantine info
    pub fn quarantine_info(quarantine_id: &str) -> String {
        format!(
            "{} Quarantine ID: {}\n   View with: kindlyguard quarantine --view {}",
            "🔒".bright_yellow(),
            quarantine_id.bright_cyan(),
            quarantine_id
        )
    }

    /// Display saved output message
    pub fn saved_output(path: &str) -> String {
        format!("{} Neutralized content saved to: {}", "💾".bright_green(), path.bright_cyan())
    }

    /// Display saved report message
    pub fn saved_report(path: &str) -> String {
        format!("{} Security report saved to: {}", "📄".bright_blue(), path.bright_cyan())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_friendly_messages() {
        // Test that messages are generated without panicking
        let _ = Messages::all_clear();
        let _ = Messages::threats_neutralized(3, "test summary");
        let _ = Messages::threats_quarantined(2, "/path/to/quarantine");
        let _ = Messages::scanning_progress("test.txt");
    }

    #[test]
    fn test_threat_descriptions() {
        // Ensure all threat types have friendly descriptions
        assert_eq!(
            Messages::friendly_threat_description(&ThreatType::SqlInjection),
            "Removed dangerous SQL injection"
        );
        assert_eq!(
            Messages::friendly_threat_description(&ThreatType::CrossSiteScripting),
            "Sanitized XSS attempts"
        );
    }
}