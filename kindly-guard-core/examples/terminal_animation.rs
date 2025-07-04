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
//! Example demonstrating the terminal animation engine
//!
//! Run with: cargo run --example terminal_animation --features enhanced

#![cfg(feature = "enhanced")]

use kindly_guard_core::premium::terminal::{
    TerminalCanvas, AnimationFrame, Cell,
    Color, GradientGenerator, PURPLE_BASE, ELECTRIC_BLUE, GLOW_WHITE,
    easing,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a terminal canvas (80x24)
    let mut canvas = TerminalCanvas::new(80, 24)?;

    // Create gradient generators
    let purple_gradient = GradientGenerator::purple_gradient();
    let electric_gradient = GradientGenerator::electric_gradient();

    // Animation state
    let mut wave_offset = 0.0;
    let mut pulse_intensity = 0.0;

    // Run the animation loop
    canvas.animate(|canvas, elapsed| {
        // Clear the canvas
        canvas.clear();

        // Create a new frame
        let mut frame = AnimationFrame::new(80, 24);

        // Draw animated background waves
        for y in 0..24 {
            for x in 0..80 {
                let wave = ((x as f32 * 0.1 + wave_offset).sin() * 3.0 + y as f32 * 0.5) / 24.0;
                let color = purple_gradient.get(wave.clamp(0.0, 1.0));
                frame.set_cell(x, y, Cell {
                    ch: '░',
                    fg: color.darken(0.7),
                    bg: color.darken(0.9),
                });
            }
        }

        // Draw the main shield
        let shield_x = 30;
        let shield_y = 5;
        let shield_width = 20;
        let shield_height = 14;

        // Pulsing shield border
        let pulse = (elapsed * 2.0).sin() * 0.5 + 0.5;
        let border_color = ELECTRIC_BLUE.with_glow(pulse * 0.5);
        frame.draw_box(shield_x, shield_y, shield_width, shield_height, border_color, Color::new(0, 0, 0));

        // Shield interior with gradient
        for i in 1..shield_height - 1 {
            let gradient_pos = i as f32 / shield_height as f32;
            let interior_color = electric_gradient.get(gradient_pos);
            for j in 1..shield_width - 1 {
                frame.set_cell(shield_x + j, shield_y + i, Cell {
                    ch: '▓',
                    fg: interior_color.with_glow(pulse * 0.3),
                    bg: Color::new(0, 0, 0),
                });
            }
        }

        // Draw "KINDLY GUARD" text with glow effect
        let text = "KINDLY GUARD";
        let text_x = shield_x + (shield_width - text.len()) / 2;
        let text_y = shield_y + shield_height / 2;
        
        // Draw glow behind text
        for dy in -1..=1 {
            for dx in -1..=1 {
                if dx != 0 || dy != 0 {
                    frame.draw_text(
                        (text_x as i32 + dx).max(0) as usize,
                        (text_y as i32 + dy).max(0) as usize,
                        text,
                        PURPLE_BASE.darken(0.5),
                        Color::new(0, 0, 0),
                    );
                }
            }
        }
        
        // Draw main text
        frame.draw_text(text_x, text_y, text, GLOW_WHITE, Color::new(0, 0, 0));

        // Draw status line
        let status = format!("FPS: 30 | Time: {:.1}s | Press Ctrl+C to exit", elapsed);
        frame.draw_text(2, 22, &status, ELECTRIC_BLUE, Color::new(0, 0, 0));

        // Update animation state
        wave_offset += 0.1;
        pulse_intensity = (pulse_intensity + 0.02) % 1.0;

        // Render the frame
        canvas.render_frame(&frame);

        // Continue animation until 30 seconds
        Ok(elapsed < 30.0)
    })?;

    Ok(())
}

#[cfg(not(feature = "enhanced"))]
fn main() {
    eprintln!("This example requires the 'enhanced' feature. Run with:");
    eprintln!("cargo run --example terminal_animation --features enhanced");
}