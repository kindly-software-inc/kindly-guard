//! Message personality system for KindlyGuard

use std::sync::RwLock;

/// Different moods that affect message tone
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mood {
    /// Happy and upbeat
    Cheerful,
    /// Business-like and efficient
    Professional,
    /// Supportive and motivating
    Encouraging,
    /// Party mode for big achievements
    Celebratory,
    /// Focused and alert for serious threats
    Serious,
}

/// Personality traits that affect message delivery
#[derive(Debug, Clone)]
pub struct PersonalityTraits {
    /// How friendly the messages are (0.0 - 1.0)
    pub friendliness: f64,
    /// How formal the language is (0.0 = casual, 1.0 = formal)
    pub formality: f64,
    /// How much encouragement to include (0.0 - 1.0)
    pub encouragement: f64,
    /// How much humor to inject (0.0 - 1.0)
    pub humor: f64,
}

impl Default for PersonalityTraits {
    fn default() -> Self {
        Self {
            friendliness: 0.9,  // Very friendly by default
            formality: 0.4,     // Somewhat casual
            encouragement: 0.8, // Highly encouraging
            humor: 0.3,         // Light humor
        }
    }
}

/// Message personality manager
pub struct MessagePersonality {
    current_mood: RwLock<Mood>,
    traits: RwLock<PersonalityTraits>,
    threat_count: RwLock<usize>,
    success_count: RwLock<usize>,
}

impl MessagePersonality {
    /// Create a new message personality
    pub fn new() -> Self {
        Self {
            current_mood: RwLock::new(Mood::Cheerful),
            traits: RwLock::new(PersonalityTraits::default()),
            threat_count: RwLock::new(0),
            success_count: RwLock::new(0),
        }
    }

    /// Get the current mood
    pub fn current_mood(&self) -> Mood {
        *self.current_mood.read().unwrap()
    }

    /// Set the mood
    pub fn set_mood(&self, mood: Mood) {
        *self.current_mood.write().unwrap() = mood;
    }

    /// Get friendliness level
    pub fn friendliness_level(&self) -> f64 {
        self.traits.read().unwrap().friendliness
    }

    /// Get formality level
    pub fn formality_level(&self) -> f64 {
        self.traits.read().unwrap().formality
    }

    /// Get encouragement level
    pub fn encouragement_level(&self) -> f64 {
        self.traits.read().unwrap().encouragement
    }

    /// Get humor level
    pub fn humor_level(&self) -> f64 {
        self.traits.read().unwrap().humor
    }

    /// Update personality traits
    pub fn set_traits(&self, traits: PersonalityTraits) {
        *self.traits.write().unwrap() = traits;
    }

    /// Record a threat encounter
    pub fn record_threat(&self) {
        let mut count = self.threat_count.write().unwrap();
        *count += 1;
        
        // Adjust mood based on threat frequency
        if *count > 10 {
            self.set_mood(Mood::Serious);
        } else if *count > 5 {
            self.set_mood(Mood::Professional);
        }
    }

    /// Record a success
    pub fn record_success(&self) {
        let mut count = self.success_count.write().unwrap();
        *count += 1;
        
        // Celebrate milestones
        if *count % 100 == 0 {
            self.set_mood(Mood::Celebratory);
        } else if *count % 10 == 0 {
            self.set_mood(Mood::Encouraging);
        }
    }

    /// Reset counters (e.g., for a new session)
    pub fn reset_counters(&self) {
        *self.threat_count.write().unwrap() = 0;
        *self.success_count.write().unwrap() = 0;
        self.set_mood(Mood::Cheerful);
    }

    /// Get adaptive personality based on context
    pub fn adapt_to_context(&self, context: PersonalityContext) {
        match context {
            PersonalityContext::FirstTimeUser => {
                self.set_traits(PersonalityTraits {
                    friendliness: 1.0,
                    formality: 0.3,
                    encouragement: 1.0,
                    humor: 0.4,
                });
                self.set_mood(Mood::Cheerful);
            }
            PersonalityContext::SecurityIncident => {
                self.set_traits(PersonalityTraits {
                    friendliness: 0.7,
                    formality: 0.8,
                    encouragement: 0.6,
                    humor: 0.0,
                });
                self.set_mood(Mood::Serious);
            }
            PersonalityContext::MajorAchievement => {
                self.set_traits(PersonalityTraits {
                    friendliness: 1.0,
                    formality: 0.2,
                    encouragement: 1.0,
                    humor: 0.6,
                });
                self.set_mood(Mood::Celebratory);
            }
            PersonalityContext::RoutineOperation => {
                self.set_traits(PersonalityTraits::default());
                self.set_mood(Mood::Professional);
            }
        }
    }

    /// Get personality summary
    pub fn get_summary(&self) -> PersonalitySummary {
        PersonalitySummary {
            mood: self.current_mood(),
            traits: self.traits.read().unwrap().clone(),
            threat_count: *self.threat_count.read().unwrap(),
            success_count: *self.success_count.read().unwrap(),
        }
    }
}

impl Default for MessagePersonality {
    fn default() -> Self {
        Self::new()
    }
}

/// Context that affects personality adaptation
#[derive(Debug, Clone, Copy)]
pub enum PersonalityContext {
    /// User is new to the system
    FirstTimeUser,
    /// Dealing with a security incident
    SecurityIncident,
    /// Celebrating a major achievement
    MajorAchievement,
    /// Normal day-to-day operations
    RoutineOperation,
}

/// Summary of current personality state
#[derive(Debug, Clone)]
pub struct PersonalitySummary {
    pub mood: Mood,
    pub traits: PersonalityTraits,
    pub threat_count: usize,
    pub success_count: usize,
}

/// Personality presets for quick configuration
pub struct PersonalityPresets;

impl PersonalityPresets {
    /// Super friendly and encouraging
    pub fn friendly_guardian() -> PersonalityTraits {
        PersonalityTraits {
            friendliness: 1.0,
            formality: 0.2,
            encouragement: 0.9,
            humor: 0.5,
        }
    }

    /// Professional and efficient
    pub fn security_professional() -> PersonalityTraits {
        PersonalityTraits {
            friendliness: 0.6,
            formality: 0.9,
            encouragement: 0.5,
            humor: 0.1,
        }
    }

    /// Balanced approach
    pub fn balanced() -> PersonalityTraits {
        PersonalityTraits::default()
    }

    /// Minimal personality, just the facts
    pub fn minimal() -> PersonalityTraits {
        PersonalityTraits {
            friendliness: 0.3,
            formality: 1.0,
            encouragement: 0.2,
            humor: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_personality_creation() {
        let personality = MessagePersonality::new();
        assert_eq!(personality.current_mood(), Mood::Cheerful);
        assert_eq!(personality.friendliness_level(), 0.9);
    }

    #[test]
    fn test_mood_changes() {
        let personality = MessagePersonality::new();
        
        personality.set_mood(Mood::Serious);
        assert_eq!(personality.current_mood(), Mood::Serious);
        
        personality.set_mood(Mood::Celebratory);
        assert_eq!(personality.current_mood(), Mood::Celebratory);
    }

    #[test]
    fn test_threat_recording() {
        let personality = MessagePersonality::new();
        
        // Record multiple threats
        for _ in 0..6 {
            personality.record_threat();
        }
        
        // Should switch to professional mood after 5 threats
        assert_eq!(personality.current_mood(), Mood::Professional);
    }

    #[test]
    fn test_success_recording() {
        let personality = MessagePersonality::new();
        
        // Record 10 successes
        for _ in 0..10 {
            personality.record_success();
        }
        
        // Should be encouraging after 10 successes
        assert_eq!(personality.current_mood(), Mood::Encouraging);
    }

    #[test]
    fn test_context_adaptation() {
        let personality = MessagePersonality::new();
        
        personality.adapt_to_context(PersonalityContext::SecurityIncident);
        assert_eq!(personality.current_mood(), Mood::Serious);
        assert_eq!(personality.humor_level(), 0.0);
        
        personality.adapt_to_context(PersonalityContext::MajorAchievement);
        assert_eq!(personality.current_mood(), Mood::Celebratory);
        assert_eq!(personality.humor_level(), 0.6);
    }

    #[test]
    fn test_personality_presets() {
        let friendly = PersonalityPresets::friendly_guardian();
        assert_eq!(friendly.friendliness, 1.0);
        assert_eq!(friendly.humor, 0.5);
        
        let professional = PersonalityPresets::security_professional();
        assert_eq!(professional.formality, 0.9);
        assert_eq!(professional.humor, 0.1);
    }
}