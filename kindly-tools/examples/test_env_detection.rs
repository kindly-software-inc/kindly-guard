// Test environment detection functions
use kindly_tools::{detect_environment, detect_linux_distro, detect_node_managers};

fn main() {
    println!("Testing Environment Detection Functions\n");

    // Test detect_environment
    let env = detect_environment();
    println!("Environment Detection:");
    println!("  🐳 Docker: {}", env.is_docker);
    println!("  🪟 WSL: {}", env.is_wsl);
    println!("  🔄 CI: {}", env.is_ci);
    println!("  🔐 SSH: {}", env.is_ssh);
    println!("  🌐 Proxy: {}", env.has_proxy);

    // Test detect_linux_distro
    #[cfg(target_os = "linux")]
    {
        println!("\nLinux Distribution:");
        let distro = detect_linux_distro();
        println!("  {}", distro.display_name());
        println!("  Package Manager: {}", distro.package_manager());
    }

    // Test detect_node_managers
    println!("\nNode.js Version Managers:");
    let managers = detect_node_managers();
    println!("  📦 nvm: {}", managers.has_nvm);
    println!("  🚀 fnm: {}", managers.has_fnm);
    println!("  ⚡ n: {}", managers.has_n);
    println!("  ⚡ volta: {}", managers.has_volta);
    println!("  🌊 asdf: {}", managers.has_asdf);

    if let Some(recommended) = managers.recommended() {
        println!("\n  ✨ Recommended: {}", recommended);
    }

    println!("\n✅ All detection functions completed successfully!");
}
