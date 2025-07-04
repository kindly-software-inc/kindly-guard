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
//! Lightning Shield Demo
//!
//! Demonstrates the premium lightning shield renderer with various display modes.

#![cfg(feature = "enhanced")]

use kindly_guard_core::premium::lightning_shield::{
    LightningRenderer, RenderConfig, ShieldStats, Intensity,
};
use std::io::{self, Write};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    println!("KindlyGuard Lightning Shield Demo");
    println!("=================================\n");
    
    // Create renderer with default config
    let mut renderer = LightningRenderer::new(RenderConfig::default())?;
    
    // Demo 1: Status Bar
    println!("1. Mini Status Bar:");
    let stats = ShieldStats {
        threats_blocked: 42,
        session_duration: 300,
        avg_response_time: 150,
        protection_level: "Enhanced".to_string(),
        active_scanners: 5,
    };
    
    let status = renderer.render_status_bar(&stats, Intensity::Idle);
    println!("{}", status);
    
    // Demo 2: Compact Shield
    println!("\n2. Compact Shield View:");
    let compact = renderer.render_compact(Intensity::Alert);
    print!("{}", compact);
    
    // Demo 3: Threat Alert
    println!("\n3. Threat Alert:");
    let alert = renderer.render_threat_alert(
        "SQL Injection Detected",
        "Malicious SQL pattern found in user input. The attempt has been blocked and logged."
    );
    println!("{}", alert);
    
    // Demo 4: Interactive Dashboard
    println!("\n4. Full Dashboard (press Ctrl+C to exit):");
    println!("   Press Enter to start...");
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    
    // Clear screen for dashboard
    print!("\x1b[2J\x1b[H");
    
    let start_time = Instant::now();
    let mut last_frame = Instant::now();
    let mut threats_blocked = 0u64;
    let mut current_intensity = Intensity::Idle;
    
    loop {
        let now = Instant::now();
        let delta = now.duration_since(last_frame).as_secs_f32();
        last_frame = now;
        
        // Update animation
        renderer.update(delta);
        
        // Simulate threat detection
        let elapsed = now.duration_since(start_time).as_secs();
        if elapsed % 5 == 0 && elapsed > 0 {
            threats_blocked += 1;
            current_intensity = match (elapsed / 5) % 4 {
                0 => Intensity::Alert,
                1 => Intensity::Active,
                2 => Intensity::Victory,
                _ => Intensity::Idle,
            };
        }
        
        // Update stats
        let current_stats = ShieldStats {
            threats_blocked,
            session_duration: elapsed,
            avg_response_time: 100 + (elapsed % 50) * 2,
            protection_level: match current_intensity {
                Intensity::Idle => "Enhanced".to_string(),
                Intensity::Alert => "Alert".to_string(),
                Intensity::Active => "Active Defense".to_string(),
                Intensity::Victory => "Threat Neutralized".to_string(),
            },
            active_scanners: 5 + (elapsed % 3) as u32,
        };
        
        // Render dashboard
        let dashboard = renderer.render_dashboard(&current_stats, current_intensity);
        print!("{}", dashboard);
        io::stdout().flush()?;
        
        // Sleep to maintain ~30 FPS
        thread::sleep(Duration::from_millis(33));
        
        // Exit after 30 seconds for demo
        if elapsed > 30 {
            break;
        }
    }
    
    // Clear screen and show exit message
    print!("\x1b[2J\x1b[H");
    println!("Demo completed!");
    println!("The Lightning Shield protected against {} threats.", threats_blocked);
    
    Ok(())
}