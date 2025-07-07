//! Message templates for different scenarios

use rand::seq::SliceRandom;
use std::collections::HashMap;

/// Message templates for various scenarios
pub struct MessageTemplates {
    welcome_messages: Vec<String>,
    threat_messages: HashMap<String, Vec<String>>,
    celebration_messages: Vec<String>,
    quarantine_messages: Vec<String>,
    encouragement_messages: Vec<String>,
    security_tips: Vec<String>,
    prompt_templates: Vec<String>,
    all_clear_messages: Vec<String>,
    protection_engaged_messages: Vec<String>,
    interactive_prompts: HashMap<String, Vec<String>>,
}

impl MessageTemplates {
    /// Create a new message templates collection
    pub fn new() -> Self {
        Self {
            welcome_messages: Self::init_welcome_messages(),
            threat_messages: Self::init_threat_messages(),
            celebration_messages: Self::init_celebration_messages(),
            quarantine_messages: Self::init_quarantine_messages(),
            encouragement_messages: Self::init_encouragement_messages(),
            security_tips: Self::init_security_tips(),
            prompt_templates: Self::init_prompt_templates(),
            all_clear_messages: Self::init_all_clear_messages(),
            protection_engaged_messages: Self::init_protection_engaged_messages(),
            interactive_prompts: Self::init_interactive_prompts(),
        }
    }

    fn init_welcome_messages() -> Vec<String> {
        vec![
            "Welcome to KindlyGuard! I'm here to keep you safe while you work. 🌟",
            "Hello {name}! Ready to code securely? I've got your back! 💪",
            "Good to see you, {name}! Let's make today productive and secure! 🛡️",
            "Welcome back! Your security guardian is active and ready! ✨",
            "Hi there! Together we'll keep your code safe and sound! 🤝",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn init_threat_messages() -> HashMap<String, Vec<String>> {
        let mut messages = HashMap::new();
        
        messages.insert("SQL Injection".to_string(), vec![
            "Blocked {count} SQL injection attempt(s)! Your database is safe! 🛡️",
            "Nice try, hackers! Neutralized {count} SQL injection(s). Database integrity maintained! 💪",
            "SQL injection detected and defeated! {count} threat(s) eliminated. You're protected! ✨",
        ]);
        
        messages.insert("XSS".to_string(), vec![
            "Stopped {count} XSS attempt(s)! Your users are protected! 🛡️",
            "Cross-site scripting blocked! {count} malicious script(s) neutralized. Well defended! 🎯",
            "XSS attempt foiled! {count} threat(s) eliminated. Your app stays clean! ✨",
        ]);
        
        messages.insert("Unicode".to_string(), vec![
            "Caught {count} suspicious Unicode character(s)! No hidden surprises here! 👁️",
            "Unicode trickery detected! {count} invisible threat(s) revealed and neutralized! 🔍",
            "Blocked {count} Unicode attack(s)! Your text is clean and safe! ✨",
        ]);
        
        messages.insert("Command Injection".to_string(), vec![
            "Command injection blocked! {count} attempt(s) stopped. System integrity preserved! 🛡️",
            "Nice try! Neutralized {count} command injection(s). Your system is secure! 💪",
            "Command injection defeated! {count} threat(s) eliminated. Shell access denied! 🚫",
        ]);
        
        messages.insert("Generic".to_string(), vec![
            "Threat neutralized! {count} suspicious pattern(s) blocked. You're safe! 🛡️",
            "Security threat defeated! {count} attempt(s) stopped. Great defense! 💪",
            "Blocked {count} threat(s)! Your security shield is working perfectly! ✨",
        ]);
        
        messages.into_iter()
            .map(|(k, v)| (k, v.into_iter().map(String::from).collect()))
            .collect()
    }

    fn init_celebration_messages() -> Vec<String> {
        vec![
            "🎉 Amazing! {achievement} - You're doing great!",
            "🌟 Fantastic work! {achievement} - Keep it up!",
            "🏆 Achievement unlocked: {achievement} - You're a security champion!",
            "✨ Excellent! {achievement} - Your dedication to security is inspiring!",
            "🎊 Congratulations! {achievement} - You're making the digital world safer!",
            "💫 Stellar performance! {achievement} - Security excellence achieved!",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn init_quarantine_messages() -> Vec<String> {
        vec![
            "File '{file}' has been safely quarantined due to {reason}. You're protected! 🔒",
            "Suspicious file isolated: '{file}'. Reason: {reason}. Threat contained! 🛡️",
            "Quarantine successful! '{file}' isolated for {reason}. Your system is safe! ✅",
            "File '{file}' moved to secure quarantine. Detected: {reason}. Crisis averted! 🚨",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn init_encouragement_messages() -> Vec<String> {
        vec![
            "You're doing great! Every secure line of code makes the world safer! 💪",
            "Keep up the excellent work! Your security awareness is impressive! ⭐",
            "Remember: You're not just writing code, you're building trust! 🤝",
            "Your commitment to security is admirable! Together we're unstoppable! 🛡️",
            "Great job staying vigilant! Security is a journey, and you're on the right path! 🌟",
            "You're a security star! Keep shining bright! ✨",
            "Every threat blocked is a victory! You're winning the security game! 🏆",
            "Your security instincts are sharp! Trust them! 🎯",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn init_security_tips() -> Vec<String> {
        vec![
            "💡 Security tip: Always validate user input - it's your first line of defense!",
            "💡 Pro tip: Use parameterized queries to prevent SQL injection attacks!",
            "💡 Remember: Encoding output prevents XSS attacks. Stay safe!",
            "💡 Security wisdom: The principle of least privilege keeps systems secure!",
            "💡 Fun fact: Most security breaches could be prevented with proper input validation!",
            "💡 Did you know? Regular security updates are your best friend!",
            "💡 Security insight: Defense in depth means multiple layers of protection!",
            "💡 Quick tip: Strong, unique passwords are still your best defense!",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }

    fn init_prompt_templates() -> Vec<String> {
        vec![
            "{question}\n\nYour options:\n{options}\n\nWhat would you like to do? 💭",
            "I need your input! {question}\n\nAvailable choices:\n{options}\n\nPlease select: 🤔",
            "Quick question: {question}\n\n{options}\n\nYour choice matters! 💡",
            "{question}\n\nHere are your options:\n{options}\n\nI'm ready when you are! ⏳",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
    
    fn init_all_clear_messages() -> Vec<String> {
        vec![
            "✅ All clear! No threats detected. Your code is sparkling clean! ✨",
            "🎉 Fantastic! Zero threats found. You're writing secure code like a pro! 🏆",
            "💚 Perfect! Your code passed all security checks. Keep up the great work! 🌟",
            "🛡️ Excellent! No security issues detected. Your defenses are impeccable! 💪",
            "✨ Wonderful! Clean bill of health for your code. Security champion! 🎯",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
    
    fn init_protection_engaged_messages() -> Vec<String> {
        vec![
            "🚨 Protection mode activated! Found {count} threat(s). Don't worry, I'll handle this! 💪",
            "🛡️ Security shield engaged! Detected {count} potential issue(s). Time to neutralize! ⚡",
            "⚠️ Alert! {count} threat(s) detected. Engaging automatic protection protocols! 🤖",
            "🔒 Lockdown initiated! {count} security concern(s) found. Neutralization in progress! 🎯",
            "💫 Guardian mode ON! Spotted {count} threat(s). Let me take care of this for you! ✨",
        ]
        .into_iter()
        .map(String::from)
        .collect()
    }
    
    fn init_interactive_prompts() -> HashMap<String, Vec<String>> {
        let mut prompts = HashMap::new();
        
        prompts.insert("SQL Injection".to_string(), vec![
            "I found a SQL injection attempt. This could compromise your database. Should I neutralize it? 🤔",
            "SQL injection detected! This is serious but fixable. Want me to clean it up? 💭",
            "Uh oh, SQL injection spotted! Let's protect your database. Shall I neutralize? 🛡️",
        ]);
        
        prompts.insert("XSS".to_string(), vec![
            "Cross-site scripting attempt found! This could affect your users. Should I block it? 🤔",
            "XSS detected! Let's keep your users safe. Want me to neutralize this threat? 💭",
            "Found an XSS vulnerability. This needs attention. Shall I fix it for you? 🛡️",
        ]);
        
        prompts.insert("Unicode".to_string(), vec![
            "Suspicious Unicode characters detected! They might be hiding something. Should I clean them? 🤔",
            "Found some tricky Unicode. Could be an attempt to deceive. Want me to neutralize? 💭",
            "Unicode anomaly spotted! Let's make sure it's safe. Shall I handle this? 🛡️",
        ]);
        
        prompts.insert("Generic".to_string(), vec![
            "I detected a potential security issue. Should I neutralize this threat? 🤔",
            "Found something suspicious. Want me to take care of it for you? 💭",
            "Security concern detected. Shall I apply protection? 🛡️",
        ]);
        
        prompts.into_iter()
            .map(|(k, v)| (k, v.into_iter().map(String::from).collect()))
            .collect()
    }

    /// Get a random welcome message
    pub fn get_welcome_message(&self, user_name: Option<&str>) -> String {
        let mut rng = rand::thread_rng();
        let template = self.welcome_messages.choose(&mut rng).unwrap();
        
        if let Some(name) = user_name {
            template.replace("{name}", name)
        } else {
            template.replace("{name}", "friend")
        }
    }

    /// Get a threat neutralized message
    pub fn get_threat_neutralized_message(&self, threat_type: &str, count: usize) -> String {
        let mut rng = rand::thread_rng();
        
        let messages = self.threat_messages
            .get(threat_type)
            .or_else(|| self.threat_messages.get("Generic"))
            .unwrap();
            
        let template = messages.choose(&mut rng).unwrap();
        template.replace("{count}", &count.to_string())
    }

    /// Get a celebration message
    pub fn get_celebration_message(&self, achievement: &str) -> String {
        let mut rng = rand::thread_rng();
        let template = self.celebration_messages.choose(&mut rng).unwrap();
        template.replace("{achievement}", achievement)
    }

    /// Get a quarantine message
    pub fn get_quarantine_message(&self, file_path: &str, reason: &str) -> String {
        let mut rng = rand::thread_rng();
        let template = self.quarantine_messages.choose(&mut rng).unwrap();
        
        template
            .replace("{file}", file_path)
            .replace("{reason}", reason)
    }

    /// Get an encouragement message
    pub fn get_encouragement_message(&self) -> String {
        let mut rng = rand::thread_rng();
        self.encouragement_messages
            .choose(&mut rng)
            .unwrap()
            .clone()
    }

    /// Get a security tip
    pub fn get_security_tip(&self) -> String {
        let mut rng = rand::thread_rng();
        self.security_tips
            .choose(&mut rng)
            .unwrap()
            .clone()
    }

    /// Get a prompt message
    pub fn get_prompt_message(&self, question: &str, options: &[&str]) -> String {
        let mut rng = rand::thread_rng();
        let template = self.prompt_templates.choose(&mut rng).unwrap();
        
        let options_str = options
            .iter()
            .enumerate()
            .map(|(i, opt)| format!("  {}. {}", i + 1, opt))
            .collect::<Vec<_>>()
            .join("\n");
        
        template
            .replace("{question}", question)
            .replace("{options}", &options_str)
    }
    
    /// Get an all clear message
    pub fn get_all_clear_message(&self) -> String {
        let mut rng = rand::thread_rng();
        self.all_clear_messages
            .choose(&mut rng)
            .unwrap()
            .clone()
    }
    
    /// Get a protection engaged message
    pub fn get_protection_engaged_message(&self, threat_count: usize) -> String {
        let mut rng = rand::thread_rng();
        let template = self.protection_engaged_messages.choose(&mut rng).unwrap();
        template.replace("{count}", &threat_count.to_string())
    }
    
    /// Get an interactive prompt for a specific threat type
    pub fn get_interactive_prompt(&self, threat_type: &str) -> String {
        let mut rng = rand::thread_rng();
        
        let prompts = self.interactive_prompts
            .get(threat_type)
            .or_else(|| self.interactive_prompts.get("Generic"))
            .unwrap();
            
        prompts.choose(&mut rng).unwrap().clone()
    }
}

impl Default for MessageTemplates {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_welcome_message() {
        let templates = MessageTemplates::new();
        
        let message = templates.get_welcome_message(Some("Alice"));
        assert!(message.contains("Alice") || !message.contains("{name}"));
        
        let message = templates.get_welcome_message(None);
        assert!(message.contains("friend") || !message.contains("{name}"));
    }

    #[test]
    fn test_threat_message() {
        let templates = MessageTemplates::new();
        
        let message = templates.get_threat_neutralized_message("SQL Injection", 5);
        assert!(message.contains("5"));
        assert!(message.contains("SQL") || message.contains("injection") || message.contains("database"));
    }

    #[test]
    fn test_prompt_message() {
        let templates = MessageTemplates::new();
        
        let message = templates.get_prompt_message(
            "How should we handle this threat?",
            &["Block it", "Allow once", "Add to whitelist"]
        );
        
        assert!(message.contains("How should we handle this threat?"));
        assert!(message.contains("1. Block it"));
        assert!(message.contains("2. Allow once"));
        assert!(message.contains("3. Add to whitelist"));
    }
}