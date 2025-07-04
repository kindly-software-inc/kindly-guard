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
//! Color system for terminal animations
//! 
//! Provides purple gradient system with electric blue accents and glow effects

#![cfg(feature = "enhanced")]

use std::fmt;

/// Base purple color (#8B5CF6)
pub const PURPLE_BASE: Color = Color { r: 139, g: 92, b: 246 };

/// Electric blue accent (#60A5FA)
pub const ELECTRIC_BLUE: Color = Color { r: 96, g: 165, b: 250 };

/// Bright white for glow effects
pub const GLOW_WHITE: Color = Color { r: 255, g: 255, b: 255 };

/// Dark background
pub const DARK_BG: Color = Color { r: 17, g: 24, b: 39 };

/// RGB color representation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Color {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

impl Color {
    /// Create a new color
    pub const fn new(r: u8, g: u8, b: u8) -> Self {
        Color { r, g, b }
    }

    /// Convert to ANSI 24-bit color escape code
    pub fn to_ansi_fg(&self) -> String {
        format!("\x1b[38;2;{};{};{}m", self.r, self.g, self.b)
    }

    /// Convert to ANSI 24-bit background color escape code
    pub fn to_ansi_bg(&self) -> String {
        format!("\x1b[48;2;{};{};{}m", self.r, self.g, self.b)
    }

    /// Interpolate between two colors
    pub fn lerp(&self, other: &Color, t: f32) -> Color {
        let t = t.clamp(0.0, 1.0);
        Color {
            r: (self.r as f32 + (other.r as f32 - self.r as f32) * t) as u8,
            g: (self.g as f32 + (other.g as f32 - self.g as f32) * t) as u8,
            b: (self.b as f32 + (other.b as f32 - self.b as f32) * t) as u8,
        }
    }

    /// Apply glow effect by blending with white
    pub fn with_glow(&self, intensity: f32) -> Color {
        self.lerp(&GLOW_WHITE, intensity)
    }

    /// Darken the color
    pub fn darken(&self, factor: f32) -> Color {
        let factor = factor.clamp(0.0, 1.0);
        Color {
            r: (self.r as f32 * (1.0 - factor)) as u8,
            g: (self.g as f32 * (1.0 - factor)) as u8,
            b: (self.b as f32 * (1.0 - factor)) as u8,
        }
    }

    /// Convert to HSL and back for better color manipulation
    pub fn adjust_hue(&self, degrees: f32) -> Color {
        let (h, s, l) = self.to_hsl();
        let new_h = (h + degrees) % 360.0;
        Color::from_hsl(new_h, s, l)
    }

    fn to_hsl(&self) -> (f32, f32, f32) {
        let r = self.r as f32 / 255.0;
        let g = self.g as f32 / 255.0;
        let b = self.b as f32 / 255.0;

        let max = r.max(g).max(b);
        let min = r.min(g).min(b);
        let l = (max + min) / 2.0;

        if max == min {
            return (0.0, 0.0, l);
        }

        let d = max - min;
        let s = if l > 0.5 {
            d / (2.0 - max - min)
        } else {
            d / (max + min)
        };

        let h = if max == r {
            (g - b) / d + if g < b { 6.0 } else { 0.0 }
        } else if max == g {
            (b - r) / d + 2.0
        } else {
            (r - g) / d + 4.0
        };

        (h * 60.0, s, l)
    }

    fn from_hsl(h: f32, s: f32, l: f32) -> Color {
        if s == 0.0 {
            let gray = (l * 255.0) as u8;
            return Color::new(gray, gray, gray);
        }

        let hue_to_rgb = |p: f32, q: f32, mut t: f32| -> f32 {
            if t < 0.0 { t += 1.0; }
            if t > 1.0 { t -= 1.0; }
            if t < 1.0 / 6.0 { return p + (q - p) * 6.0 * t; }
            if t < 1.0 / 2.0 { return q; }
            if t < 2.0 / 3.0 { return p + (q - p) * (2.0 / 3.0 - t) * 6.0; }
            p
        };

        let q = if l < 0.5 {
            l * (1.0 + s)
        } else {
            l + s - l * s
        };
        let p = 2.0 * l - q;

        let h_norm = h / 360.0;
        let r = hue_to_rgb(p, q, h_norm + 1.0 / 3.0);
        let g = hue_to_rgb(p, q, h_norm);
        let b = hue_to_rgb(p, q, h_norm - 1.0 / 3.0);

        Color::new(
            (r * 255.0) as u8,
            (g * 255.0) as u8,
            (b * 255.0) as u8,
        )
    }
}

impl fmt::Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{:02X}{:02X}{:02X}", self.r, self.g, self.b)
    }
}

/// Gradient generator for smooth color transitions
pub struct GradientGenerator {
    colors: Vec<Color>,
}

impl GradientGenerator {
    /// Create a new gradient generator
    pub fn new(colors: Vec<Color>) -> Self {
        assert!(!colors.is_empty(), "Gradient must have at least one color");
        GradientGenerator { colors }
    }

    /// Create a purple gradient
    pub fn purple_gradient() -> Self {
        Self::new(vec![
            PURPLE_BASE.darken(0.5),
            PURPLE_BASE.darken(0.3),
            PURPLE_BASE,
            PURPLE_BASE.with_glow(0.2),
            PURPLE_BASE.with_glow(0.4),
        ])
    }

    /// Create an electric gradient
    pub fn electric_gradient() -> Self {
        Self::new(vec![
            ELECTRIC_BLUE.darken(0.6),
            ELECTRIC_BLUE.darken(0.3),
            ELECTRIC_BLUE,
            ELECTRIC_BLUE.with_glow(0.3),
            GLOW_WHITE,
        ])
    }

    /// Get color at position (0.0 to 1.0)
    pub fn get(&self, position: f32) -> Color {
        let position = position.clamp(0.0, 1.0);
        
        if self.colors.len() == 1 {
            return self.colors[0];
        }

        let segment_size = 1.0 / (self.colors.len() - 1) as f32;
        let segment = (position / segment_size) as usize;
        let segment = segment.min(self.colors.len() - 2);
        
        let local_t = (position - segment as f32 * segment_size) / segment_size;
        
        self.colors[segment].lerp(&self.colors[segment + 1], local_t)
    }

    /// Generate a gradient with specified number of steps
    pub fn generate(&self, steps: usize) -> Vec<Color> {
        (0..steps)
            .map(|i| {
                let position = i as f32 / (steps - 1).max(1) as f32;
                self.get(position)
            })
            .collect()
    }
}

/// ANSI color helper utilities
pub struct AnsiColor;

impl AnsiColor {
    /// Reset all attributes
    pub const RESET: &'static str = "\x1b[0m";
    
    /// Bold text
    pub const BOLD: &'static str = "\x1b[1m";
    
    /// Dim text
    pub const DIM: &'static str = "\x1b[2m";
    
    /// Clear screen
    pub const CLEAR: &'static str = "\x1b[2J\x1b[H";
    
    /// Hide cursor
    pub const HIDE_CURSOR: &'static str = "\x1b[?25l";
    
    /// Show cursor
    pub const SHOW_CURSOR: &'static str = "\x1b[?25h";
    
    /// Move cursor to position
    pub fn goto(x: u16, y: u16) -> String {
        format!("\x1b[{};{}H", y + 1, x + 1)
    }
    
    /// Save cursor position
    pub const SAVE_CURSOR: &'static str = "\x1b[s";
    
    /// Restore cursor position
    pub const RESTORE_CURSOR: &'static str = "\x1b[u";
}

// Compatibility layer for existing code
pub use Color as RgbColor;

/// Color palette for theming (compatibility layer)
pub struct ColorPalette;

impl ColorPalette {
    pub fn security_theme() -> Self {
        ColorPalette
    }
}

/// Load color profiles (compatibility function)
pub fn load_profiles() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_color_interpolation() {
        let start = Color::new(0, 0, 0);
        let end = Color::new(255, 255, 255);
        
        let mid = start.lerp(&end, 0.5);
        assert_eq!(mid, Color::new(127, 127, 127));
        
        let quarter = start.lerp(&end, 0.25);
        assert_eq!(quarter, Color::new(63, 63, 63));
    }

    #[test]
    fn test_gradient_generation() {
        let gradient = GradientGenerator::purple_gradient();
        let colors = gradient.generate(5);
        assert_eq!(colors.len(), 5);
        
        // Check that colors progress from dark to light
        for i in 1..colors.len() {
            let prev_brightness = colors[i-1].r as u32 + colors[i-1].g as u32 + colors[i-1].b as u32;
            let curr_brightness = colors[i].r as u32 + colors[i].g as u32 + colors[i].b as u32;
            assert!(curr_brightness >= prev_brightness);
        }
    }

    #[test]
    fn test_ansi_codes() {
        let color = PURPLE_BASE;
        assert_eq!(color.to_ansi_fg(), "\x1b[38;2;139;92;246m");
        assert_eq!(color.to_ansi_bg(), "\x1b[48;2;139;92;246m");
    }
}