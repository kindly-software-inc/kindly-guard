#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![forbid(unsafe_code)]

pub mod config;
pub mod core;
pub mod ipc;
pub mod protocol;
pub mod security;
pub mod tray;
pub mod websocket;