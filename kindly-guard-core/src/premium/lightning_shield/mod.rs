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
//! Lightning Shield Animation System
//!
//! Premium animation effects for the KindlyGuard shield, featuring smooth
//! breathing animations, particle effects, and lightning bolt overlays.

pub mod animator;
pub mod effects;
pub mod renderer;

pub use animator::{LightningAnimator, AnimationState};
pub use effects::{LightningEffect, EffectType};
pub use renderer::{LightningRenderer, RenderConfig, ShieldStats};

/// Animation intensity levels for different states
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Intensity {
    /// Calm, steady breathing
    Idle,
    /// Alert, detecting potential threats
    Alert,
    /// Active, blocking threats
    Active,
    /// Victory, threat neutralized
    Victory,
}

impl Intensity {
    /// Get the base amplitude for breathing animation
    pub fn amplitude(&self) -> f32 {
        match self {
            Intensity::Idle => 0.05,
            Intensity::Alert => 0.15,
            Intensity::Active => 0.25,
            Intensity::Victory => 0.1,
        }
    }

    /// Get particle spawn rate multiplier
    pub fn particle_rate(&self) -> f32 {
        match self {
            Intensity::Idle => 0.2,
            Intensity::Alert => 0.6,
            Intensity::Active => 1.0,
            Intensity::Victory => 1.5,
        }
    }

    /// Get glow intensity
    pub fn glow_strength(&self) -> f32 {
        match self {
            Intensity::Idle => 0.3,
            Intensity::Alert => 0.6,
            Intensity::Active => 1.0,
            Intensity::Victory => 0.8,
        }
    }
}

/// Initialize the lightning shield subsystem
pub fn initialize() -> anyhow::Result<()> {
    // Initialize rendering backend
    renderer::initialize_backend()?;
    Ok(())
}

/// Easing functions for smooth animation
pub mod easing {
    use std::f32::consts::PI;

    /// Smooth sine wave easing for breathing effect
    pub fn sine_in_out(t: f32) -> f32 {
        -(PI * t).cos() / 2.0 + 0.5
    }

    /// Exponential easing for particle fade
    pub fn expo_out(t: f32) -> f32 {
        if t >= 1.0 {
            1.0
        } else {
            1.0 - 2.0_f32.powf(-10.0 * t)
        }
    }

    /// Cubic easing for smooth transitions
    pub fn cubic_in_out(t: f32) -> f32 {
        if t < 0.5 {
            4.0 * t * t * t
        } else {
            1.0 - (-2.0 * t + 2.0).powi(3) / 2.0
        }
    }

    /// Elastic easing for bounce effects
    pub fn elastic_out(t: f32) -> f32 {
        if t <= 0.0 {
            0.0
        } else if t >= 1.0 {
            1.0
        } else {
            2.0_f32.powf(-10.0 * t) * ((t * 10.0 - 0.75) * (2.0 * PI / 3.0)).sin() + 1.0
        }
    }
}