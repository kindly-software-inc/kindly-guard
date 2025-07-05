// Example: Test wrap configuration

use kindly_tools::config::{WrapConfig, WrapMode};
use std::path::Path;

fn main() -> anyhow::Result<()> {
    println!("Testing KindlyGuard Wrap Configuration\n");

    // Test 1: Default configuration
    println!("1. Default Configuration:");
    let default_config = WrapConfig::default();
    println!("   Enabled: {}", default_config.enabled);
    println!("   Mode: {:?}", default_config.mode);
    println!("   Commands: {:?}", default_config.commands.len());
    println!();

    // Test 2: Check if commands should be wrapped
    println!("2. Should wrap tests:");
    let commands_to_test = vec!["claude", "openai", "ls", "cat", "/usr/bin/claude"];
    for cmd in commands_to_test {
        println!("   Should wrap '{}': {}", cmd, default_config.should_wrap(cmd));
    }
    println!();

    // Test 3: Load from template
    println!("3. Loading from template:");
    let template_path = Path::new("templates/wrap.toml");
    if template_path.exists() {
        let loaded_config = WrapConfig::load_from_path(template_path)?;
        println!("   Successfully loaded!");
        println!("   Mode: {:?}", loaded_config.mode);
        println!("   Server: {}", loaded_config.server);
    } else {
        println!("   Template not found at: {}", template_path.display());
    }
    println!();

    // Test 4: Create and modify config
    println!("4. Modifying configuration:");
    let mut config = WrapConfig::default();
    config.mode = WrapMode::Blocking;
    config.add_command("my-custom-ai".to_string());
    println!("   Changed mode to: {:?}", config.mode);
    println!("   Added custom command: my-custom-ai");
    println!("   Should wrap 'my-custom-ai': {}", config.should_wrap("my-custom-ai"));

    Ok(())
}