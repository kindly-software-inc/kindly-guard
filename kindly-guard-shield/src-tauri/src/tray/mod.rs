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
use tauri::{
    AppHandle, Manager,
    menu::{Menu, MenuItem},
    tray::{TrayIcon, TrayIconBuilder, TrayIconEvent},
};
use tracing::{debug, error, info};

pub struct TrayManager {
    app_handle: AppHandle,
}

impl TrayManager {
    pub fn new(app_handle: AppHandle) -> Self {
        Self { app_handle }
    }
    
    pub fn setup(&self) -> Result<(), Box<dyn std::error::Error>> {
        debug!("Setting up system tray");
        
        // Create tray menu
        let menu = self.create_menu()?;
        
        // Create tray icon
        let _tray = TrayIconBuilder::new()
            .menu(&menu)
            .tooltip("KindlyGuard Security Shield")
            .on_tray_icon_event(|tray, event| {
                match event {
                    TrayIconEvent::Click {
                        button,
                        button_state,
                        ..
                    } => {
                        debug!("Tray clicked: {:?} {:?}", button, button_state);
                        
                        // Left click shows the shield
                        if button == tauri::tray::MouseButton::Left {
                            if let Some(window) = tray.app_handle().get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                    }
                    TrayIconEvent::Enter { .. } => {
                        debug!("Mouse entered tray icon");
                    }
                    TrayIconEvent::Leave { .. } => {
                        debug!("Mouse left tray icon");
                    }
                    _ => {}
                }
            })
            .build(&self.app_handle)?;
        
        info!("System tray setup complete");
        Ok(())
    }
    
    fn create_menu(&self) -> Result<Menu<AppHandle>, Box<dyn std::error::Error>> {
        let app_handle = &self.app_handle;
        let menu = Menu::new(app_handle)?;
        
        // Show Shield
        let show_shield = MenuItem::with_id(
            app_handle,
            "show_shield",
            "Show Shield",
            true,
            None::<&str>,
        )?;
        
        // Toggle Protection
        let toggle_protection = MenuItem::with_id(
            app_handle,
            "toggle_protection",
            "Toggle Protection",
            true,
            None::<&str>,
        )?;
        
        // View Statistics
        let view_stats = MenuItem::with_id(
            app_handle,
            "view_stats",
            "View Statistics",
            true,
            None::<&str>,
        )?;
        
        // Separator
        let separator = tauri::menu::PredefinedMenuItem::separator(app_handle)?;
        
        // About
        let about = MenuItem::with_id(
            app_handle,
            "about",
            "About KindlyGuard",
            true,
            None::<&str>,
        )?;
        
        // Quit
        let quit = MenuItem::with_id(
            app_handle,
            "quit",
            "Quit",
            true,
            None::<&str>,
        )?;
        
        // Build menu
        menu.append(&show_shield)?;
        menu.append(&toggle_protection)?;
        menu.append(&view_stats)?;
        menu.append(&separator)?;
        menu.append(&about)?;
        menu.append(&quit)?;
        
        // Handle menu events
        menu.on_event(|app_handle, event| {
            match event.id.as_ref() {
                "show_shield" => {
                    debug!("Show shield menu clicked");
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "toggle_protection" => {
                    debug!("Toggle protection menu clicked");
                    // Emit event to frontend
                    let _ = app_handle.emit("toggle-protection", ());
                }
                "view_stats" => {
                    debug!("View stats menu clicked");
                    if let Some(window) = app_handle.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                        // Emit event to show stats view
                        let _ = window.emit("show-stats", ());
                    }
                }
                "about" => {
                    debug!("About menu clicked");
                    // Emit event to show about dialog
                    let _ = app_handle.emit("show-about", ());
                }
                "quit" => {
                    debug!("Quit menu clicked");
                    info!("Quitting application");
                    app_handle.exit(0);
                }
                _ => {}
            }
        });
        
        Ok(menu)
    }
    
    pub fn update_tooltip(&self, text: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(tray) = self.app_handle.tray_by_id("main") {
            tray.set_tooltip(Some(text))?;
        }
        Ok(())
    }
    
    pub fn update_menu_item(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(tray) = self.app_handle.tray_by_id("main") {
            if let Some(menu) = tray.menu() {
                if let Some(item) = menu.get(id) {
                    match item {
                        tauri::menu::MenuEntry::Item(menu_item) => {
                            menu_item.set_enabled(enabled)?;
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_tray_manager_creation() {
        // This is a basic test that would require a full Tauri app context
        // In real tests, you'd use Tauri's testing utilities
    }
}