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
//! Enhanced terminal rendering capabilities
//!
//! Provides advanced terminal manipulation and rendering features
//! for premium UI effects.

#![cfg(feature = "enhanced")]

mod canvas;
mod colors;

pub use canvas::{TerminalCanvas, DrawCommand, Coordinate};
pub use colors::{ColorPalette, RgbColor, AnsiColor};

use anyhow::Result;

/// Initialize terminal subsystem
pub fn initialize() -> Result<()> {
    // Initialize terminal capabilities
    canvas::detect_capabilities()?;
    
    // Load color profiles
    colors::load_profiles()?;
    
    Ok(())
}

/// Terminal capabilities detection
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// True color support (24-bit)
    pub true_color: bool,
    /// Unicode support
    pub unicode: bool,
    /// Terminal dimensions
    pub dimensions: (u16, u16),
    /// Supports alternate screen buffer
    pub alternate_screen: bool,
}

/// Get detected terminal capabilities
pub fn capabilities() -> Capabilities {
    Capabilities {
        true_color: true, // Would be detected dynamically
        unicode: true,
        dimensions: (80, 24),
        alternate_screen: true,
    }
}

#[cfg(test)]
mod test_demo;