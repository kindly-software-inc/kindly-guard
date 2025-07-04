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
//! Lightning Shield Animator
//!
//! Handles frame generation, interpolation, and animation cycles for the shield.

use std::time::{Duration, Instant};
use super::{Intensity, easing};

/// Configuration for the animation system
#[derive(Debug, Clone)]
pub struct AnimationConfig {
    /// Base breathing cycle duration (default: 2.5 seconds)
    pub breathing_cycle: Duration,
    /// Frames per second for smooth animation
    pub target_fps: u32,
    /// Enable particle effects
    pub particles_enabled: bool,
    /// Enable glow effects
    pub glow_enabled: bool,
}

impl Default for AnimationConfig {
    fn default() -> Self {
        Self {
            breathing_cycle: Duration::from_millis(2500), // Match Claude's breathing
            target_fps: 30,
            particles_enabled: true,
            glow_enabled: true,
        }
    }
}

/// A single frame of the shield animation
#[derive(Debug, Clone)]
pub struct AnimationFrame {
    /// ASCII art lines for this frame
    pub lines: Vec<String>,
    /// Current scale factor (1.0 = normal size)
    pub scale: f32,
    /// Glow intensity (0.0 - 1.0)
    pub glow: f32,
    /// Lightning bolt positions (if any)
    pub lightning_bolts: Vec<LightningBolt>,
    /// Frame timestamp
    pub timestamp: Instant,
}

/// Lightning bolt overlay
#[derive(Debug, Clone)]
pub struct LightningBolt {
    /// Starting position (x, y)
    pub start: (usize, usize),
    /// Ending position (x, y)
    pub end: (usize, usize),
    /// Intensity (0.0 - 1.0)
    pub intensity: f32,
    /// Bolt character
    pub character: char,
}

/// Main animator for the lightning shield
pub struct LightningShieldAnimator {
    config: AnimationConfig,
    start_time: Instant,
    current_intensity: Intensity,
    target_intensity: Intensity,
    transition_start: Option<Instant>,
    transition_duration: Duration,
    base_frames: Vec<Vec<String>>,
}

impl LightningShieldAnimator {
    /// Create a new animator with default configuration
    pub fn new() -> Self {
        Self::with_config(AnimationConfig::default())
    }

    /// Create a new animator with custom configuration
    pub fn with_config(config: AnimationConfig) -> Self {
        Self {
            config,
            start_time: Instant::now(),
            current_intensity: Intensity::Idle,
            target_intensity: Intensity::Idle,
            transition_start: None,
            transition_duration: Duration::from_millis(500),
            base_frames: Self::generate_base_frames(),
        }
    }

    /// Set the animation intensity with smooth transition
    pub fn set_intensity(&mut self, intensity: Intensity) {
        if self.target_intensity != intensity {
            self.current_intensity = self.get_interpolated_intensity();
            self.target_intensity = intensity;
            self.transition_start = Some(Instant::now());
        }
    }

    /// Generate the next animation frame
    pub fn next_frame(&mut self) -> AnimationFrame {
        let now = Instant::now();
        let elapsed = now.duration_since(self.start_time);
        
        // Calculate breathing phase (0.0 - 1.0)
        let cycle_progress = (elapsed.as_secs_f32() % self.config.breathing_cycle.as_secs_f32()) 
            / self.config.breathing_cycle.as_secs_f32();
        let breathing_phase = easing::sine_in_out(cycle_progress);
        
        // Get current intensity with smooth transition
        let intensity = self.get_interpolated_intensity();
        let amplitude = intensity.amplitude();
        let glow = intensity.glow_strength();
        
        // Calculate scale with breathing effect
        let scale = 1.0 + amplitude * breathing_phase;
        
        // Select appropriate base frame
        let frame_index = self.get_frame_index(breathing_phase);
        let mut lines = self.apply_scale(&self.base_frames[frame_index], scale);
        
        // Generate lightning bolts for active states
        let lightning_bolts = self.generate_lightning_bolts(intensity, breathing_phase);
        
        // Apply lightning to frame
        self.apply_lightning(&mut lines, &lightning_bolts);
        
        AnimationFrame {
            lines,
            scale,
            glow: glow * (0.8 + 0.2 * breathing_phase),
            lightning_bolts,
            timestamp: now,
        }
    }

    /// Get interpolated intensity during transitions
    fn get_interpolated_intensity(&self) -> Intensity {
        if let Some(start) = self.transition_start {
            let elapsed = Instant::now().duration_since(start);
            let progress = (elapsed.as_secs_f32() / self.transition_duration.as_secs_f32()).min(1.0);
            
            if progress >= 1.0 {
                self.target_intensity
            } else {
                // For now, return target (smooth blending would require float intensities)
                self.target_intensity
            }
        } else {
            self.current_intensity
        }
    }

    /// Get frame index based on breathing phase
    fn get_frame_index(&self, phase: f32) -> usize {
        let total_frames = self.base_frames.len();
        ((phase * total_frames as f32) as usize).min(total_frames - 1)
    }

    /// Apply scale to frame lines
    fn apply_scale(&self, lines: &[String], scale: f32) -> Vec<String> {
        if (scale - 1.0).abs() < 0.01 {
            return lines.to_vec();
        }

        // Simple scaling by adjusting spacing
        lines.iter().map(|line| {
            if scale > 1.0 {
                // Add spacing for larger scale
                let extra_spaces = ((scale - 1.0) * 2.0) as usize;
                let padding = " ".repeat(extra_spaces);
                format!("{}{}", padding, line)
            } else {
                // Trim for smaller scale (careful not to break the art)
                line.clone()
            }
        }).collect()
    }

    /// Generate lightning bolt positions
    fn generate_lightning_bolts(&self, intensity: Intensity, phase: f32) -> Vec<LightningBolt> {
        let mut bolts = Vec::new();

        match intensity {
            Intensity::Alert => {
                // Occasional small bolts
                if phase > 0.7 && phase < 0.8 {
                    bolts.push(LightningBolt {
                        start: (15, 2),
                        end: (18, 5),
                        intensity: 0.6,
                        character: '╱',
                    });
                }
            }
            Intensity::Active => {
                // Multiple active bolts
                bolts.push(LightningBolt {
                    start: (10, 1),
                    end: (15, 6),
                    intensity: 0.9,
                    character: '╲',
                });
                
                if phase > 0.5 {
                    bolts.push(LightningBolt {
                        start: (20, 2),
                        end: (17, 7),
                        intensity: 0.7,
                        character: '╱',
                    });
                }
            }
            Intensity::Victory => {
                // Sparkle pattern
                let sparkle_phase = (phase * 8.0) as usize % 4;
                for i in 0..3 {
                    if i == sparkle_phase {
                        bolts.push(LightningBolt {
                            start: (12 + i * 4, 3),
                            end: (12 + i * 4, 3),
                            intensity: 1.0,
                            character: '✦',
                        });
                    }
                }
            }
            _ => {}
        }

        bolts
    }

    /// Apply lightning bolts to frame
    fn apply_lightning(&self, lines: &mut [String], bolts: &[LightningBolt]) {
        for bolt in bolts {
            if bolt.start.1 < lines.len() {
                let line = &mut lines[bolt.start.1];
                if bolt.start.0 < line.len() {
                    // Simple overlay for now
                    let mut chars: Vec<char> = line.chars().collect();
                    chars[bolt.start.0] = bolt.character;
                    *line = chars.into_iter().collect();
                }
            }
        }
    }

    /// Generate base frames for animation
    fn generate_base_frames() -> Vec<Vec<String>> {
        vec![
            // Frame 0: Base shield
            vec![
                "      ╭─────────────╮      ".to_string(),
                "     ╱               ╲     ".to_string(),
                "    │    ⚡ KINDLY ⚡  │    ".to_string(),
                "    │                 │    ".to_string(),
                "    │     GUARD       │    ".to_string(),
                "    │                 │    ".to_string(),
                "     ╲               ╱     ".to_string(),
                "      ╰─────────────╯      ".to_string(),
            ],
            
            // Frame 1: Slight expansion
            vec![
                "      ╭─────────────╮      ".to_string(),
                "     ╱               ╲     ".to_string(),
                "    ╱   ⚡ KINDLY ⚡   ╲    ".to_string(),
                "    │                 │    ".to_string(),
                "    │     GUARD       │    ".to_string(),
                "    ╲                 ╱    ".to_string(),
                "     ╲               ╱     ".to_string(),
                "      ╰─────────────╯      ".to_string(),
            ],
            
            // Frame 2: Mid expansion
            vec![
                "     ╭───────────────╮     ".to_string(),
                "    ╱                 ╲    ".to_string(),
                "   ╱   ⚡ KINDLY ⚡    ╲   ".to_string(),
                "   │                   │   ".to_string(),
                "   │      GUARD        │   ".to_string(),
                "   ╲                   ╱   ".to_string(),
                "    ╲                 ╱    ".to_string(),
                "     ╰───────────────╯     ".to_string(),
            ],
            
            // Frame 3: Full expansion
            vec![
                "    ╭─────────────────╮    ".to_string(),
                "   ╱                   ╲   ".to_string(),
                "  ╱   ⚡  KINDLY  ⚡    ╲  ".to_string(),
                "  │                     │  ".to_string(),
                "  │       GUARD         │  ".to_string(),
                "  ╲                     ╱  ".to_string(),
                "   ╲                   ╱   ".to_string(),
                "    ╰─────────────────╯    ".to_string(),
            ],
            
            // Frame 4: Max expansion with glow
            vec![
                "   ╭───────────────────╮   ".to_string(),
                "  ╱                     ╲  ".to_string(),
                " ╱   ⚡  KINDLY  ⚡      ╲ ".to_string(),
                " │                       │ ".to_string(),
                " │       GUARD           │ ".to_string(),
                " ╲                       ╱ ".to_string(),
                "  ╲                     ╱  ".to_string(),
                "   ╰───────────────────╯   ".to_string(),
            ],
            
            // Frame 5: Start contraction
            vec![
                "    ╭─────────────────╮    ".to_string(),
                "   ╱                   ╲   ".to_string(),
                "  ╱   ⚡  KINDLY  ⚡    ╲  ".to_string(),
                "  │                     │  ".to_string(),
                "  │       GUARD         │  ".to_string(),
                "  ╲                     ╱  ".to_string(),
                "   ╲                   ╱   ".to_string(),
                "    ╰─────────────────╯    ".to_string(),
            ],
            
            // Frame 6: Mid contraction
            vec![
                "     ╭───────────────╮     ".to_string(),
                "    ╱                 ╲    ".to_string(),
                "   ╱   ⚡ KINDLY ⚡    ╲   ".to_string(),
                "   │                   │   ".to_string(),
                "   │      GUARD        │   ".to_string(),
                "   ╲                   ╱   ".to_string(),
                "    ╲                 ╱    ".to_string(),
                "     ╰───────────────╯     ".to_string(),
            ],
            
            // Frame 7: Near base
            vec![
                "      ╭─────────────╮      ".to_string(),
                "     ╱               ╲     ".to_string(),
                "    ╱   ⚡ KINDLY ⚡   ╲    ".to_string(),
                "    │                 │    ".to_string(),
                "    │     GUARD       │    ".to_string(),
                "    ╲                 ╱    ".to_string(),
                "     ╲               ╱     ".to_string(),
                "      ╰─────────────╯      ".to_string(),
            ],
        ]
    }

    /// Get current frame without advancing animation
    pub fn current_frame(&self) -> AnimationFrame {
        let mut temp_self = Self {
            config: self.config.clone(),
            start_time: self.start_time,
            current_intensity: self.current_intensity,
            target_intensity: self.target_intensity,
            transition_start: self.transition_start,
            transition_duration: self.transition_duration,
            base_frames: self.base_frames.clone(),
        };
        temp_self.next_frame()
    }
}

impl Default for LightningShieldAnimator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_breathing_cycle() {
        let animator = LightningShieldAnimator::new();
        let frame1 = animator.current_frame();
        std::thread::sleep(Duration::from_millis(100));
        let frame2 = animator.current_frame();
        
        // Scale should change between frames
        assert!((frame1.scale - frame2.scale).abs() > 0.001);
    }

    #[test]
    fn test_intensity_transition() {
        let mut animator = LightningShieldAnimator::new();
        animator.set_intensity(Intensity::Active);
        
        let frame = animator.next_frame();
        assert!(frame.glow > 0.5); // Active intensity has higher glow
    }
}