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
//! Terminal canvas with double-buffering for smooth animations
//! 
//! Provides 30 FPS animation support with efficient ANSI code generation

#![cfg(feature = "enhanced")]

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::thread;

use crossterm::{
    execute,
    terminal::{self, ClearType},
    cursor,
};

use crate::premium::terminal::colors::{Color, AnsiColor, DARK_BG};

/// Target frame rate for animations
const TARGET_FPS: u32 = 30;
const FRAME_DURATION: Duration = Duration::from_millis((1000 / TARGET_FPS) as u64);

/// A single character cell in the terminal
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Cell {
    pub ch: char,
    pub fg: Color,
    pub bg: Color,
}

impl Default for Cell {
    fn default() -> Self {
        Cell {
            ch: ' ',
            fg: Color::new(255, 255, 255),
            bg: DARK_BG,
        }
    }
}

/// Animation frame that can be rendered
pub struct AnimationFrame {
    pub cells: Vec<Vec<Cell>>,
    pub width: usize,
    pub height: usize,
}

impl AnimationFrame {
    /// Create a new animation frame
    pub fn new(width: usize, height: usize) -> Self {
        let cells = vec![vec![Cell::default(); width]; height];
        AnimationFrame { cells, width, height }
    }

    /// Set a cell at the given position
    pub fn set_cell(&mut self, x: usize, y: usize, cell: Cell) {
        if x < self.width && y < self.height {
            self.cells[y][x] = cell;
        }
    }

    /// Draw text at the given position
    pub fn draw_text(&mut self, x: usize, y: usize, text: &str, fg: Color, bg: Color) {
        for (i, ch) in text.chars().enumerate() {
            self.set_cell(x + i, y, Cell { ch, fg, bg });
        }
    }

    /// Fill a rectangle with a character
    pub fn fill_rect(&mut self, x: usize, y: usize, width: usize, height: usize, cell: Cell) {
        for dy in 0..height {
            for dx in 0..width {
                self.set_cell(x + dx, y + dy, cell);
            }
        }
    }

    /// Draw a box with borders
    pub fn draw_box(&mut self, x: usize, y: usize, width: usize, height: usize, fg: Color, bg: Color) {
        // Corners
        self.set_cell(x, y, Cell { ch: '┌', fg, bg });
        self.set_cell(x + width - 1, y, Cell { ch: '┐', fg, bg });
        self.set_cell(x, y + height - 1, Cell { ch: '└', fg, bg });
        self.set_cell(x + width - 1, y + height - 1, Cell { ch: '┘', fg, bg });

        // Horizontal lines
        for i in 1..width - 1 {
            self.set_cell(x + i, y, Cell { ch: '─', fg, bg });
            self.set_cell(x + i, y + height - 1, Cell { ch: '─', fg, bg });
        }

        // Vertical lines
        for i in 1..height - 1 {
            self.set_cell(x, y + i, Cell { ch: '│', fg, bg });
            self.set_cell(x + width - 1, y + i, Cell { ch: '│', fg, bg });
        }
    }
}

/// Terminal canvas with double-buffering
pub struct TerminalCanvas {
    width: usize,
    height: usize,
    front_buffer: Vec<Vec<Cell>>,
    back_buffer: Vec<Vec<Cell>>,
    running: Arc<AtomicBool>,
    last_frame_time: Instant,
}

impl TerminalCanvas {
    /// Create a new terminal canvas
    pub fn new(width: usize, height: usize) -> CrosstermResult<Self> {
        // Setup terminal
        terminal::enable_raw_mode()?;
        execute!(
            io::stdout(),
            terminal::Clear(ClearType::All),
            cursor::Hide,
            cursor::MoveTo(0, 0)
        )?;

        let default_cell = Cell::default();
        let front_buffer = vec![vec![default_cell; width]; height];
        let back_buffer = vec![vec![default_cell; width]; height];

        Ok(TerminalCanvas {
            width,
            height,
            front_buffer,
            back_buffer,
            running: Arc::new(AtomicBool::new(false)),
            last_frame_time: Instant::now(),
        })
    }

    /// Start the animation loop
    pub fn start(&mut self) {
        self.running.store(true, Ordering::SeqCst);
    }

    /// Stop the animation loop
    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Check if the canvas is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Render a frame to the back buffer
    pub fn render_frame(&mut self, frame: &AnimationFrame) {
        for y in 0..self.height.min(frame.height) {
            for x in 0..self.width.min(frame.width) {
                self.back_buffer[y][x] = frame.cells[y][x];
            }
        }
    }

    /// Swap buffers and display the frame
    pub fn present(&mut self) -> CrosstermResult<()> {
        // Calculate time to maintain 30 FPS
        let elapsed = self.last_frame_time.elapsed();
        if elapsed < FRAME_DURATION {
            thread::sleep(FRAME_DURATION - elapsed);
        }

        // Swap buffers
        std::mem::swap(&mut self.front_buffer, &mut self.back_buffer);

        // Render differences only for efficiency
        self.render_to_terminal()?;

        self.last_frame_time = Instant::now();
        Ok(())
    }

    /// Render the front buffer to the terminal
    fn render_to_terminal(&self) -> CrosstermResult<()> {
        let mut stdout = io::stdout();
        let mut output = String::with_capacity(self.width * self.height * 20);

        // Start from home position
        output.push_str(AnsiColor::goto(0, 0).as_str());

        let mut last_fg = Color::new(0, 0, 0);
        let mut last_bg = Color::new(0, 0, 0);
        let mut first_cell = true;

        for y in 0..self.height {
            if y > 0 {
                output.push_str(&AnsiColor::goto(0, y as u16));
            }

            for x in 0..self.width {
                let cell = &self.front_buffer[y][x];

                // Optimize by only changing colors when needed
                if first_cell || cell.fg != last_fg {
                    output.push_str(&cell.fg.to_ansi_fg());
                    last_fg = cell.fg;
                }

                if first_cell || cell.bg != last_bg {
                    output.push_str(&cell.bg.to_ansi_bg());
                    last_bg = cell.bg;
                }

                output.push(cell.ch);
                first_cell = false;
            }
        }

        // Write everything at once for smoothness
        write!(stdout, "{}", output)?;
        stdout.flush()?;
        Ok(())
    }

    /// Clear the back buffer
    pub fn clear(&mut self) {
        let default_cell = Cell::default();
        for row in &mut self.back_buffer {
            row.fill(default_cell);
        }
    }

    /// Get the canvas dimensions
    pub fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    /// Run an animation loop with a callback
    pub fn animate<F>(&mut self, mut update_fn: F) -> CrosstermResult<()>
    where
        F: FnMut(&mut TerminalCanvas, f32) -> CrosstermResult<bool>,
    {
        self.start();
        let start_time = Instant::now();

        while self.is_running() {
            let elapsed = start_time.elapsed().as_secs_f32();

            // Call the update function
            if !update_fn(self, elapsed)? {
                break;
            }

            // Present the frame
            self.present()?;
        }

        self.stop();
        Ok(())
    }
}

impl Drop for TerminalCanvas {
    fn drop(&mut self) {
        // Restore terminal state
        let _ = execute!(
            io::stdout(),
            cursor::Show,
            terminal::Clear(ClearType::All),
            cursor::MoveTo(0, 0)
        );
        let _ = terminal::disable_raw_mode();
    }
}

/// Easing functions for smooth animations
pub mod easing {
    /// Linear interpolation
    pub fn linear(t: f32) -> f32 {
        t
    }

    /// Ease in quad
    pub fn ease_in_quad(t: f32) -> f32 {
        t * t
    }

    /// Ease out quad
    pub fn ease_out_quad(t: f32) -> f32 {
        t * (2.0 - t)
    }

    /// Ease in out quad
    pub fn ease_in_out_quad(t: f32) -> f32 {
        if t < 0.5 {
            2.0 * t * t
        } else {
            -1.0 + (4.0 - 2.0 * t) * t
        }
    }

    /// Ease in cubic
    pub fn ease_in_cubic(t: f32) -> f32 {
        t * t * t
    }

    /// Ease out cubic
    pub fn ease_out_cubic(t: f32) -> f32 {
        let t = t - 1.0;
        t * t * t + 1.0
    }

    /// Elastic easing for bouncy effects
    pub fn elastic_out(t: f32) -> f32 {
        if t == 0.0 || t == 1.0 {
            return t;
        }
        let p = 0.3;
        let s = p / 4.0;
        (2.0_f32.powf(-10.0 * t) * ((t - s) * (2.0 * std::f32::consts::PI) / p).sin() + 1.0)
    }
}

// Compatibility layer for existing code
pub use AnimationFrame as DrawCommand;
pub type Coordinate = (usize, usize);

/// Detect terminal capabilities (compatibility function)
pub fn detect_capabilities() -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_animation_frame() {
        let mut frame = AnimationFrame::new(10, 10);
        let color = Color::new(255, 0, 0);
        
        frame.draw_text(0, 0, "Hello", color, DARK_BG);
        assert_eq!(frame.cells[0][0].ch, 'H');
        assert_eq!(frame.cells[0][1].ch, 'e');
        assert_eq!(frame.cells[0][0].fg, color);
    }

    #[test]
    fn test_fill_rect() {
        let mut frame = AnimationFrame::new(10, 10);
        let cell = Cell {
            ch: '#',
            fg: Color::new(255, 255, 255),
            bg: Color::new(0, 0, 0),
        };
        
        frame.fill_rect(2, 2, 3, 3, cell);
        
        for y in 2..5 {
            for x in 2..5 {
                assert_eq!(frame.cells[y][x], cell);
            }
        }
    }

    #[test]
    fn test_easing_functions() {
        assert_eq!(easing::linear(0.5), 0.5);
        assert_eq!(easing::ease_in_quad(0.5), 0.25);
        assert!(easing::elastic_out(0.5) > 0.0 && easing::elastic_out(0.5) < 2.0);
    }
}