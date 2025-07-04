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
//! Complete Lightning Shield Visualization Example
//!
//! Demonstrates the full animation system with particles, effects, and rendering.
//! Run with: cargo run --example shield_visualization --features premium

#[cfg(feature = "premium")]
use kindly_guard_core::premium::lightning_shield::{
    LightningShieldAnimator, AnimationConfig, Intensity, 
    ParticleSystem, SharedShieldState, ShieldRenderer,
    GlowRenderer, EffectType, Effect,
};
use std::time::{Duration, Instant};
use std::thread;
use std::io::{stdout, Write};

#[cfg(not(feature = "premium"))]
fn main() {
    println!("This example requires the 'premium' feature. Run with:");
    println!("cargo run --example shield_visualization --features premium");
}

#[cfg(feature = "premium")]
fn main() {
    println!("\x1B[2J\x1B[1;1H"); // Clear screen
    println!("=== KindlyGuard Lightning Shield Visualization ===");
    println!("Premium security animations with particle effects\n");
    
    // Wait a moment for user to see intro
    thread::sleep(Duration::from_secs(2));
    
    // Create shared shield state
    let shield_state = SharedShieldState::new();
    let mut renderer = ShieldRenderer::new(30); // 30 FPS
    let glow_renderer = GlowRenderer::new();
    
    // Simulation scenarios
    let scenarios = vec![
        ("Starting Protection", Intensity::Idle, 3),
        ("Scanning for Threats", Intensity::Alert, 4),
        ("Threat Detected!", Intensity::Active, 5),
        ("Neutralizing Threat", Intensity::Active, 3),
        ("Victory!", Intensity::Victory, 4),
        ("Returning to Normal", Intensity::Idle, 3),
    ];
    
    println!("Running shield animation demo...\n");
    
    for (description, intensity, duration_secs) in scenarios {
        println!("\n>>> {}", description);
        thread::sleep(Duration::from_millis(500));
        
        // Update shield state based on scenario
        match intensity {
            Intensity::Alert => {
                // Simulate minor threat
                shield_state.threat_detected(0.3);
            }
            Intensity::Active => {
                // Simulate major threat
                shield_state.threat_detected(0.9);
            }
            Intensity::Victory => {
                // Threat neutralized
                shield_state.threat_neutralized();
            }
            _ => {}
        }
        
        let scenario_start = Instant::now();
        
        while scenario_start.elapsed() < Duration::from_secs(duration_secs) {
            // Check if we should render this frame
            if renderer.should_render() {
                // Update particle system
                shield_state.update_particles();
                
                // Get current animation frame
                if let Some(frame) = shield_state.get_frame() {
                    // Clear screen and render
                    print!("\x1B[2J\x1B[1;1H");
                    
                    // Title
                    println!("=== {} ===\n", description);
                    
                    // Render the shield
                    render_shield_with_effects(&frame, &glow_renderer, intensity);
                    
                    // Show stats
                    let stats = shield_state.get_stats();
                    println!("\n╔══════════════════════════════════════╗");
                    println!("║ Status: {:?}                    ║", stats.current_intensity);
                    println!("║ Threats Blocked: {:>20} ║", stats.threat_count);
                    println!("║ Active Particles: {:>19} ║", stats.particle_count);
                    println!("║ Shield Scale: {:>23.2} ║", frame.scale);
                    println!("║ Glow Intensity: {:>21.2} ║", frame.glow);
                    println!("╚══════════════════════════════════════╝");
                    
                    // Flush output
                    stdout().flush().unwrap();
                }
            }
            
            thread::sleep(Duration::from_millis(16)); // ~60 FPS check rate
        }
    }
    
    println!("\n\n=== Demo Complete ===");
    println!("\nThe Lightning Shield provides:");
    println!("✓ Smooth 2.5-second breathing animation");
    println!("✓ Dynamic particle effects");
    println!("✓ Threat-responsive intensity levels");
    println!("✓ Premium visual feedback");
    println!("✓ Real-time threat visualization");
}

#[cfg(feature = "premium")]
fn render_shield_with_effects(frame: &kindly_guard_core::premium::lightning_shield::AnimationFrame, 
                              glow_renderer: &GlowRenderer, 
                              intensity: Intensity) {
    // Apply color based on intensity
    let color = match intensity {
        Intensity::Idle => "\x1B[34m",     // Blue
        Intensity::Alert => "\x1B[33m",    // Yellow
        Intensity::Active => "\x1B[31m",   // Red
        Intensity::Victory => "\x1B[32m",  // Green
    };
    
    // Render shield with color
    print!("{}", color);
    for line in &frame.lines {
        println!("{}", line);
    }
    print!("\x1B[0m"); // Reset color
    
    // Show lightning bolts if present
    if !frame.lightning_bolts.is_empty() {
        println!("\nLightning Effects:");
        for bolt in &frame.lightning_bolts {
            println!("  {} at ({}, {}) intensity: {:.1}", 
                     bolt.character, bolt.start.0, bolt.start.1, bolt.intensity);
        }
    }
    
    // Simulate glow effect with characters
    if frame.glow > 0.5 {
        let glow_chars = vec!['·', '∙', '•', '●'];
        let glow_index = ((frame.glow - 0.5) * 8.0) as usize % glow_chars.len();
        let glow_char = glow_chars[glow_index];
        
        println!("\nGlow Effect: {}{}{}", glow_char, glow_char, glow_char);
    }
}