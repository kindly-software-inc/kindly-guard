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
//! Simple demo test for terminal animation functionality

#![cfg(all(test, feature = "enhanced"))]

use crate::premium::terminal::{
    AnimationFrame, Cell, Color, GradientGenerator, 
    PURPLE_BASE, ELECTRIC_BLUE, DARK_BG,
    easing,
};

#[test]
fn test_purple_gradient_colors() {
    let gradient = GradientGenerator::purple_gradient();
    let colors = gradient.generate(10);
    
    // Verify we have the correct number of colors
    assert_eq!(colors.len(), 10);
    
    // Verify the gradient goes from dark to light
    let first_brightness = colors[0].r as u32 + colors[0].g as u32 + colors[0].b as u32;
    let last_brightness = colors[9].r as u32 + colors[9].g as u32 + colors[9].b as u32;
    assert!(last_brightness > first_brightness);
    
    // Verify purple tones are maintained (more blue/red than green)
    for color in &colors {
        assert!(color.b > color.g || color.r > color.g);
    }
}

#[test]
fn test_frame_rendering() {
    let mut frame = AnimationFrame::new(40, 20);
    
    // Draw a box
    frame.draw_box(5, 5, 10, 10, ELECTRIC_BLUE, DARK_BG);
    
    // Verify corners
    assert_eq!(frame.cells[5][5].ch, '┌');
    assert_eq!(frame.cells[5][14].ch, '┐');
    assert_eq!(frame.cells[14][5].ch, '└');
    assert_eq!(frame.cells[14][14].ch, '┘');
    
    // Verify borders
    assert_eq!(frame.cells[5][10].ch, '─');
    assert_eq!(frame.cells[10][5].ch, '│');
}

#[test]
fn test_color_interpolation() {
    let start = Color::new(0, 0, 0);
    let end = PURPLE_BASE;
    
    // Test various interpolation points
    let quarter = start.lerp(&end, 0.25);
    let half = start.lerp(&end, 0.5);
    let three_quarters = start.lerp(&end, 0.75);
    
    // Verify progressive interpolation
    assert!(quarter.r < half.r);
    assert!(half.r < three_quarters.r);
    assert!(three_quarters.r < end.r);
    
    // Test edge cases
    assert_eq!(start.lerp(&end, 0.0), start);
    assert_eq!(start.lerp(&end, 1.0), end);
}

#[test]
fn test_glow_effect() {
    let base = PURPLE_BASE;
    
    // Apply different glow intensities
    let light_glow = base.with_glow(0.25);
    let medium_glow = base.with_glow(0.5);
    let strong_glow = base.with_glow(0.75);
    
    // Verify colors get brighter with more glow
    assert!(light_glow.r > base.r);
    assert!(medium_glow.r > light_glow.r);
    assert!(strong_glow.r > medium_glow.r);
    
    // Verify glow moves towards white
    assert!(strong_glow.r > 200);
    assert!(strong_glow.g > 200);
    assert!(strong_glow.b > 200);
}

#[test]
fn test_easing_functions() {
    // Test linear
    assert_eq!(easing::linear(0.0), 0.0);
    assert_eq!(easing::linear(0.5), 0.5);
    assert_eq!(easing::linear(1.0), 1.0);
    
    // Test ease in quad (starts slow)
    assert!(easing::ease_in_quad(0.25) < 0.25);
    assert_eq!(easing::ease_in_quad(0.5), 0.25);
    
    // Test ease out quad (ends slow)
    assert!(easing::ease_out_quad(0.75) > 0.75);
    
    // Test elastic (bouncy)
    let elastic_mid = easing::elastic_out(0.5);
    assert!(elastic_mid > 0.0 && elastic_mid < 2.0);
}

#[test]
fn test_ansi_color_codes() {
    // Test foreground color
    let purple_fg = PURPLE_BASE.to_ansi_fg();
    assert!(purple_fg.starts_with("\x1b[38;2;"));
    assert!(purple_fg.contains("139;92;246"));
    
    // Test background color
    let blue_bg = ELECTRIC_BLUE.to_ansi_bg();
    assert!(blue_bg.starts_with("\x1b[48;2;"));
    assert!(blue_bg.contains("96;165;250"));
}

#[test]
fn test_animation_frame_text() {
    let mut frame = AnimationFrame::new(20, 10);
    
    // Draw some text
    frame.draw_text(5, 5, "SHIELD", ELECTRIC_BLUE, DARK_BG);
    
    // Verify text was written correctly
    assert_eq!(frame.cells[5][5].ch, 'S');
    assert_eq!(frame.cells[5][6].ch, 'H');
    assert_eq!(frame.cells[5][7].ch, 'I');
    assert_eq!(frame.cells[5][8].ch, 'E');
    assert_eq!(frame.cells[5][9].ch, 'L');
    assert_eq!(frame.cells[5][10].ch, 'D');
    
    // Verify colors
    assert_eq!(frame.cells[5][5].fg, ELECTRIC_BLUE);
    assert_eq!(frame.cells[5][5].bg, DARK_BG);
}