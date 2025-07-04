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
//! Lightning effects system
//!
//! Provides various visual effects for the lightning shield including
//! particles, lightning bolts, and glow effects.

#![cfg(feature = "enhanced")]

use super::{Intensity, AnimationState};
use anyhow::Result;

/// Type of visual effect
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EffectType {
    /// Lightning bolt strike
    LightningBolt,
    /// Glowing particles
    Particle,
    /// Threat indicator pulse
    ThreatIndicator,
    /// Shield shimmer
    ShieldShimmer,
    /// Victory celebration
    Victory,
}

/// Lightning effect instance
#[derive(Debug, Clone)]
pub struct LightningEffect {
    /// Effect type
    pub effect_type: EffectType,
    /// Current intensity
    pub intensity: Intensity,
    /// Position in normalized coordinates (0.0-1.0)
    pub position: (f32, f32),
    /// Age of the effect in seconds
    pub age: f32,
    /// Maximum lifetime in seconds
    pub lifetime: f32,
    /// Custom parameters
    pub params: EffectParams,
}

/// Effect-specific parameters
#[derive(Debug, Clone)]
pub struct EffectParams {
    /// Size multiplier
    pub scale: f32,
    /// Rotation angle in radians
    pub rotation: f32,
    /// Color override (R, G, B, A)
    pub color: Option<(f32, f32, f32, f32)>,
    /// Animation speed multiplier
    pub speed: f32,
}

impl Default for EffectParams {
    fn default() -> Self {
        Self {
            scale: 1.0,
            rotation: 0.0,
            color: None,
            speed: 1.0,
        }
    }
}

impl LightningEffect {
    /// Create a new effect
    pub fn new(effect_type: EffectType, intensity: Intensity, position: (f32, f32)) -> Self {
        let lifetime = match effect_type {
            EffectType::LightningBolt => 0.3,
            EffectType::Particle => 2.0,
            EffectType::ThreatIndicator => 1.5,
            EffectType::ShieldShimmer => 3.0,
            EffectType::Victory => 4.0,
        };
        
        Self {
            effect_type,
            intensity,
            position,
            age: 0.0,
            lifetime,
            params: EffectParams::default(),
        }
    }
    
    /// Update the effect
    pub fn update(&mut self, delta_time: f32, state: &AnimationState) {
        self.age += delta_time * self.params.speed * state.speed;
        
        // Update rotation for spinning effects
        match self.effect_type {
            EffectType::Particle | EffectType::Victory => {
                self.params.rotation += delta_time * 2.0;
            }
            _ => {}
        }
    }
    
    /// Check if the effect has completed
    pub fn is_complete(&self) -> bool {
        self.age >= self.lifetime
    }
    
    /// Get the current progress (0.0-1.0)
    pub fn progress(&self) -> f32 {
        (self.age / self.lifetime).min(1.0)
    }
    
    /// Get the current alpha value for fading
    pub fn alpha(&self) -> f32 {
        match self.effect_type {
            EffectType::LightningBolt => {
                // Quick flash
                if self.progress() < 0.1 {
                    1.0
                } else {
                    1.0 - self.progress()
                }
            }
            EffectType::Particle => {
                // Fade in and out
                let p = self.progress();
                if p < 0.2 {
                    p * 5.0
                } else {
                    1.0 - (p - 0.2) / 0.8
                }
            }
            _ => 1.0 - self.progress(),
        }
    }
}

impl Intensity {
    /// Convert threat level to intensity
    pub fn from_threat_level(level: f32) -> Self {
        if level < 0.3 {
            Intensity::Idle
        } else if level < 0.6 {
            Intensity::Alert
        } else if level < 0.9 {
            Intensity::Active
        } else {
            Intensity::Victory
        }
    }
}

/// Initialize and preload effect resources
pub fn preload_effects() -> Result<()> {
    // In a real implementation, this would load shaders, textures, etc.
    // For now, just validate the system
    Ok(())
}