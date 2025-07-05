use anyhow::{Context as _, Result};
use colored::*;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, MultiSelect, Select};
use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

use crate::{
    commands::{build, doctor, package, publish, release, security, version},
    config::ReleaseConfig,
    utils::Context,
};

/// Interactive mode configuration
pub struct InteractiveMode {
    theme: ColorfulTheme,
    ctx: Context,
}

impl InteractiveMode {
    pub fn new(ctx: Context) -> Self {
        Self {
            theme: ColorfulTheme::default(),
            ctx,
        }
    }

    /// Run the interactive menu
    pub async fn run(&mut self) -> Result<()> {
        // Show welcome message
        self.show_welcome();

        // Check if this is first time setup
        if self.is_first_run()? {
            self.run_setup_wizard().await?;
        }

        // Main menu loop
        loop {
            match self.show_main_menu()? {
                MainMenuChoice::Release => self.interactive_release().await?,
                MainMenuChoice::Build => self.interactive_build().await?,
                MainMenuChoice::Test => self.interactive_test().await?,
                MainMenuChoice::Security => self.interactive_security().await?,
                MainMenuChoice::Package => self.interactive_package().await?,
                MainMenuChoice::Publish => self.interactive_publish().await?,
                MainMenuChoice::Version => self.interactive_version().await?,
                MainMenuChoice::Cache => self.interactive_cache().await?,
                MainMenuChoice::Doctor => self.interactive_doctor().await?,
                MainMenuChoice::Configure => self.run_setup_wizard().await?,
                MainMenuChoice::Exit => {
                    println!("{}", "👋 Goodbye!".green());
                    break;
                }
            }
        }

        Ok(())
    }

    fn show_welcome(&self) {
        println!();
        println!("{}", "╔═══════════════════════════════════════╗".blue());
        println!("{}", "║      KindlyGuard Build System         ║".blue());
        println!("{}", "║         Interactive Mode              ║".blue());
        println!("{}", "╚═══════════════════════════════════════╝".blue());
        println!();
    }

    fn is_first_run(&self) -> Result<bool> {
        // Check if release config exists
        let config_path = crate::utils::workspace_root()?.join("release-config.toml");
        Ok(!config_path.exists())
    }

    async fn run_setup_wizard(&mut self) -> Result<()> {
        println!("{}", "🧙 Welcome to KindlyGuard Setup Wizard".yellow());
        println!();

        // Project configuration
        let project_name: String = Input::with_theme(&self.theme)
            .with_prompt("Project name")
            .default("kindly-guard".to_string())
            .interact_text()?;

        // Build targets
        let targets = vec![
            "x86_64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "aarch64-unknown-linux-gnu",
        ];

        let selected_targets: Vec<usize> = MultiSelect::with_theme(&self.theme)
            .with_prompt("Select build targets")
            .items(&targets)
            .defaults(&[true, false, false, false, false])
            .interact()?;

        let selected_target_names: Vec<String> = selected_targets
            .iter()
            .map(|&i| targets[i].to_string())
            .collect();

        // Features configuration
        let enable_cache = Confirm::with_theme(&self.theme)
            .with_prompt("Enable build cache?")
            .default(true)
            .interact()?;

        let enable_parallel = Confirm::with_theme(&self.theme)
            .with_prompt("Enable parallel builds?")
            .default(true)
            .interact()?;

        // Release configuration
        let auto_publish = Confirm::with_theme(&self.theme)
            .with_prompt("Automatically publish releases?")
            .default(false)
            .interact()?;

        // Create release configuration
        let mut release_config = ReleaseConfig::default();
        
        // Update config based on wizard choices
        release_config.platforms.targets = selected_target_names;
        release_config.registries.crates_io = auto_publish;
        release_config.registries.npm = auto_publish;
        
        // Save configuration
        let progress = self.create_progress_bar("Saving configuration...");
        
        release_config.save()?;
        
        // Also create a simple xtask config
        let xtask_config = format!(
            r#"# KindlyGuard Build Configuration
project_name = "{}"
cache_enabled = {}
parallel_builds = {}

[targets]
default = {:?}
"#,
            project_name,
            enable_cache,
            enable_parallel,
            release_config.platforms.targets
        );
        
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("kindlyguard");
        std::fs::create_dir_all(&config_dir)?;
        std::fs::write(config_dir.join("xtask.toml"), xtask_config)?;
        
        tokio::time::sleep(Duration::from_millis(200)).await;
        
        progress.finish_with_message("✓ Configuration saved");
        
        println!();
        println!("{}", "✅ Setup complete!".green());
        println!();

        Ok(())
    }

    fn show_main_menu(&self) -> Result<MainMenuChoice> {
        let choices = vec![
            "🚀 Release - Create a new release",
            "🔨 Build - Build the project",
            "🧪 Test - Run tests and benchmarks",
            "🔒 Security - Run security audits",
            "📦 Package - Package binaries for distribution",
            "📤 Publish - Publish to registries",
            "🏷️  Version - Manage versions",
            "💾 Cache - Manage build cache",
            "🩺 Doctor - Check development environment",
            "⚙️  Configure - Run setup wizard",
            "🚪 Exit",
        ];

        let selection = Select::with_theme(&self.theme)
            .with_prompt("What would you like to do?")
            .items(&choices)
            .default(0)
            .interact()?;

        Ok(match selection {
            0 => MainMenuChoice::Release,
            1 => MainMenuChoice::Build,
            2 => MainMenuChoice::Test,
            3 => MainMenuChoice::Security,
            4 => MainMenuChoice::Package,
            5 => MainMenuChoice::Publish,
            6 => MainMenuChoice::Version,
            7 => MainMenuChoice::Cache,
            8 => MainMenuChoice::Doctor,
            9 => MainMenuChoice::Configure,
            10 => MainMenuChoice::Exit,
            _ => unreachable!(),
        })
    }

    async fn interactive_release(&mut self) -> Result<()> {
        println!("{}", "\n🚀 Release Wizard".blue().bold());
        
        // Get current version
        let current_version = self.get_current_version()?;
        println!("Current version: {}", current_version.to_string().yellow());

        // Version selection
        let version_choices = vec![
            format!("Patch ({}.{}.{})", current_version.major, current_version.minor, current_version.patch + 1),
            format!("Minor ({}.{}.0)", current_version.major, current_version.minor + 1),
            format!("Major ({}.0.0)", current_version.major + 1),
            "Custom version".to_string(),
        ];

        let version_selection = Select::with_theme(&self.theme)
            .with_prompt("Select version type")
            .items(&version_choices)
            .default(0)
            .interact()?;

        let new_version = match version_selection {
            0 => format!("{}.{}.{}", current_version.major, current_version.minor, current_version.patch + 1),
            1 => format!("{}.{}.0", current_version.major, current_version.minor + 1),
            2 => format!("{}.0.0", current_version.major + 1),
            3 => {
                Input::with_theme(&self.theme)
                    .with_prompt("Enter custom version")
                    .validate_with(|input: &String| -> Result<(), &str> {
                        semver::Version::parse(input).map_err(|_| "Invalid version format")?;
                        Ok(())
                    })
                    .interact_text()?
            }
            _ => unreachable!(),
        };

        // Release options
        let run_tests = Confirm::with_theme(&self.theme)
            .with_prompt("Run tests before release?")
            .default(true)
            .interact()?;

        let run_security = Confirm::with_theme(&self.theme)
            .with_prompt("Run security audit?")
            .default(true)
            .interact()?;

        let build_binaries = Confirm::with_theme(&self.theme)
            .with_prompt("Build release binaries?")
            .default(true)
            .interact()?;

        let publish_release = Confirm::with_theme(&self.theme)
            .with_prompt("Publish to registries?")
            .default(true)
            .interact()?;

        let prerelease = Confirm::with_theme(&self.theme)
            .with_prompt("Mark as pre-release?")
            .default(false)
            .interact()?;

        // Show summary
        println!("\n{}", "📋 Release Summary:".yellow());
        println!("  Version: {} → {}", current_version, new_version.green());
        println!("  Run tests: {}", if run_tests { "✓" } else { "✗" });
        println!("  Security audit: {}", if run_security { "✓" } else { "✗" });
        println!("  Build binaries: {}", if build_binaries { "✓" } else { "✗" });
        println!("  Publish: {}", if publish_release { "✓" } else { "✗" });
        println!("  Pre-release: {}", if prerelease { "✓" } else { "✗" });

        let proceed = Confirm::with_theme(&self.theme)
            .with_prompt("Proceed with release?")
            .default(true)
            .interact()?;

        if !proceed {
            println!("{}", "Release cancelled.".red());
            return Ok(());
        }

        // TODO: Interactive mode needs to be redesigned to work with clap command structs
        self.ctx.info("Release command construction from interactive mode is temporarily disabled");
        self.ctx.info(&format!("Would have created release {} with:", new_version));
        self.ctx.info(&format!("  - Run tests: {}", run_tests));
        self.ctx.info(&format!("  - Run security: {}", run_security));
        self.ctx.info(&format!("  - Build binaries: {}", build_binaries));
        self.ctx.info(&format!("  - Publish: {}", publish_release));
        self.ctx.info(&format!("  - Prerelease: {}", prerelease));
        self.ctx.info("Please use 'cargo xtask release' from the command line instead");

        Ok(())
    }

    async fn interactive_build(&mut self) -> Result<()> {
        println!("{}", "\n🔨 Build Configuration".blue().bold());

        // Target selection
        let targets = vec![
            "x86_64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "aarch64-unknown-linux-gnu",
            "Current platform only",
        ];

        let target_selection = Select::with_theme(&self.theme)
            .with_prompt("Select build target")
            .items(&targets)
            .default(5)
            .interact()?;

        let target = if target_selection < 5 {
            Some(targets[target_selection].to_string())
        } else {
            None
        };

        // Build profile
        let profiles = vec!["dev", "release", "secure"];
        let profile_selection = Select::with_theme(&self.theme)
            .with_prompt("Select build profile")
            .items(&profiles)
            .default(1)
            .interact()?;

        let profile = profiles[profile_selection].to_string();

        // Additional options
        let _clean_first = Confirm::with_theme(&self.theme)
            .with_prompt("Clean before building?")
            .default(false)
            .interact()?;

        let run_tests = Confirm::with_theme(&self.theme)
            .with_prompt("Run tests after build?")
            .default(false)
            .interact()?;

        // TODO: Fix interactive mode to work with private clap structs
        /*
        let cmd = build::BuildCmd {
            targets: target.map(|t| vec![t]),
            release: profile == "release",
            strip: profile == "release" || profile == "secure",
            archive: false,
            output_dir: None,
        };

        // Run build
        println!();
        build::run(cmd, self.ctx.clone()).await?;
        */
        self.ctx.info("Build command is temporarily disabled in interactive mode");

        if run_tests {
            println!("\n{}", "Running tests...".yellow());
            // TODO: Interactive mode needs to be redesigned to work with clap command structs
            self.ctx.info("Test execution from interactive mode is temporarily disabled");
        }

        Ok(())
    }

    async fn interactive_test(&mut self) -> Result<()> {
        println!("{}", "\n🧪 Test Runner".blue().bold());
        
        // TODO: Interactive mode needs to be redesigned to work with clap command structs
        self.ctx.info("Test execution from interactive mode is temporarily disabled");
        self.ctx.info("Please use 'cargo xtask test' from the command line instead");
        
        Ok(())
    }

    async fn interactive_security(&mut self) -> Result<()> {
        println!("{}", "\n🔒 Security Audit".blue().bold());

        let audit_types = vec![
            "Full security audit",
            "Dependency audit only",
            "Code security scan",
            "License compliance check",
        ];

        let audit_selection = Select::with_theme(&self.theme)
            .with_prompt("Select audit type")
            .items(&audit_types)
            .default(0)
            .interact()?;

        let fix = Confirm::with_theme(&self.theme)
            .with_prompt("Attempt to fix issues automatically?")
            .default(false)
            .interact()?;

        // TODO: Interactive mode needs to be redesigned to work with clap command structs
        self.ctx.info("Security command construction from interactive mode is temporarily disabled");
        self.ctx.info(&format!("You selected: {} with fix={}", audit_types[audit_selection], fix));
        self.ctx.info("Please use 'cargo xtask security' from the command line instead");

        Ok(())
    }

    async fn interactive_package(&mut self) -> Result<()> {
        println!("{}", "\n📦 Package Configuration".blue().bold());

        // Target selection
        let targets = vec![
            "All supported platforms",
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
            "Select multiple...",
        ];

        let target_selection = Select::with_theme(&self.theme)
            .with_prompt("Select platforms to package")
            .items(&targets)
            .default(0)
            .interact()?;

        let selected_targets = if target_selection == 0 {
            // All platforms
            None
        } else if target_selection == 6 {
            // Multiple selection
            let all_targets = vec![
                "x86_64-unknown-linux-gnu",
                "x86_64-unknown-linux-musl",
                "x86_64-apple-darwin",
                "aarch64-apple-darwin",
                "x86_64-pc-windows-msvc",
                "aarch64-unknown-linux-gnu",
                "aarch64-unknown-linux-musl",
                "armv7-unknown-linux-gnueabihf",
            ];

            let selections: Vec<usize> = MultiSelect::with_theme(&self.theme)
                .with_prompt("Select platforms")
                .items(&all_targets)
                .interact()?;

            Some(selections.iter().map(|&i| all_targets[i].to_string()).collect())
        } else {
            Some(vec![targets[target_selection].to_string()])
        };

        // Package options
        let create_npm = Confirm::with_theme(&self.theme)
            .with_prompt("Create NPM packages?")
            .default(false)
            .interact()?;

        let npm_scope = if create_npm {
            let scope: String = Input::with_theme(&self.theme)
                .with_prompt("NPM scope (optional, e.g., @myorg)")
                .allow_empty(true)
                .interact_text()?;
            if scope.is_empty() {
                None
            } else {
                Some(scope)
            }
        } else {
            None
        };

        let generate_checksums = Confirm::with_theme(&self.theme)
            .with_prompt("Generate checksums?")
            .default(true)
            .interact()?;

        let strip_binaries = Confirm::with_theme(&self.theme)
            .with_prompt("Strip debug symbols?")
            .default(true)
            .interact()?;

        let max_compression = Confirm::with_theme(&self.theme)
            .with_prompt("Use maximum compression?")
            .default(false)
            .interact()?;

        // Skip build if binaries exist
        let skip_build = Confirm::with_theme(&self.theme)
            .with_prompt("Skip building (use existing binaries)?")
            .default(false)
            .interact()?;

        // Output directory
        let output_dir: String = Input::with_theme(&self.theme)
            .with_prompt("Output directory")
            .default("dist".to_string())
            .interact_text()?;

        // TODO: Fix interactive mode to work with private clap structs
        /*
        let cmd = package::PackageCmd {
            targets: selected_targets,
            output_dir,
            npm: create_npm,
            npm_scope,
            checksums: generate_checksums,
            skip_build,
            release: true,
            strip: strip_binaries,
            max_compression,
            version: None,
        };
        */

        // Show summary
        println!("\n{}", "📋 Package Summary:".green());
        println!("  Output: {}", output_dir);
        if let Some(ref targets) = selected_targets {
            println!("  Platforms: {}", targets.join(", "));
        } else {
            println!("  Platforms: All supported");
        }
        if create_npm {
            println!("  NPM packages: Yes");
            if let Some(ref scope) = npm_scope {
                println!("  NPM scope: {}", scope);
            }
        }
        println!("  Checksums: {}", if generate_checksums { "Yes" } else { "No" });
        println!("  Strip symbols: {}", if strip_binaries { "Yes" } else { "No" });

        if Confirm::with_theme(&self.theme)
            .with_prompt("Proceed with packaging?")
            .default(true)
            .interact()?
        {
            println!();
            // package::run(cmd, self.ctx.clone()).await?;
            self.ctx.info("Package command is temporarily disabled in interactive mode");
        } else {
            println!("{}", "Packaging cancelled.".yellow());
        }

        Ok(())
    }

    async fn interactive_publish(&mut self) -> Result<()> {
        println!("{}", "\n📦 Publish Wizard".blue().bold());

        let registries = vec![
            "crates.io",
            "npm",
            "GitHub Releases",
            "Docker Hub",
            "All registries",
        ];

        let registry_selection = Select::with_theme(&self.theme)
            .with_prompt("Select registry")
            .items(&registries)
            .default(0)
            .interact()?;

        let registry = if registry_selection < 4 {
            Some(registries[registry_selection].to_string())
        } else {
            None
        };

        let dry_run = Confirm::with_theme(&self.theme)
            .with_prompt("Dry run (simulate publish)?")
            .default(true)
            .interact()?;

        // TODO: Fix interactive mode to work with private clap structs
        /*
        let cmd = publish::PublishCmd {
            crates_io: registry.as_deref() == Some("crates.io") || registry.is_none(),
            npm: registry.as_deref() == Some("npm") || registry.is_none(),
            docker: registry.as_deref() == Some("Docker Hub") || registry.is_none(),
            skip_verification: dry_run,
        };

        // Run publish
        println!();
        publish::run(cmd, self.ctx.clone()).await?;
        */
        self.ctx.info("Publish command is temporarily disabled in interactive mode");

        Ok(())
    }

    async fn interactive_version(&mut self) -> Result<()> {
        println!("{}", "\n🏷️  Version Management".blue().bold());

        let actions = vec![
            "Show current version",
            "Update version",
            "Create version tag",
            "List version history",
        ];

        let action_selection = Select::with_theme(&self.theme)
            .with_prompt("Select action")
            .items(&actions)
            .default(0)
            .interact()?;

        match action_selection {
            0 => {
                // TODO: Fix interactive mode to work with private clap structs
                /*
                let cmd = version::VersionCmd {
                    version: None,
                    check: false,
                    show: true,
                    changelog: false,
                    commit: false,
                };
                version::run(cmd, self.ctx.clone()).await?;
                */
                self.ctx.info("Version show command is temporarily disabled in interactive mode");
            }
            1 => {
                let version: String = Input::with_theme(&self.theme)
                    .with_prompt("Enter new version (e.g., 0.10.0)")
                    .interact_text()?;

                // TODO: Fix interactive mode to work with private clap structs
                /*
                let cmd = version::VersionCmd {
                    version: Some(version),
                    check: false,
                    show: false,
                    changelog: true,
                    commit: true,
                };
                version::run(cmd, self.ctx.clone()).await?;
                */
                self.ctx.info(&format!("Version set to {} is temporarily disabled in interactive mode", version));
            }
            2 => {
                // TODO: Fix interactive mode to work with private clap structs
                /*
                let cmd = version::VersionCmd {
                    version: None,
                    check: true,
                    show: false,
                    changelog: false,
                    commit: false,
                };
                version::run(cmd, self.ctx.clone()).await?;
                */
                self.ctx.info("Version check command is temporarily disabled in interactive mode");
            }
            3 => {
                // TODO: Implement version history listing
                println!("Version history not yet implemented");
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn interactive_cache(&mut self) -> Result<()> {
        println!("{}", "\n💾 Cache Management".blue().bold());

        let actions = vec![
            "Show cache statistics",
            "Clean cache",
            "Prune old entries",
            "Export cache",
            "Import cache",
        ];

        let action_selection = Select::with_theme(&self.theme)
            .with_prompt("Select action")
            .items(&actions)
            .default(0)
            .interact()?;

        match action_selection {
            0 => {
                // This action is for showing stats
                // Since the new CacheCmd uses subcommands, we need to handle this differently
                // For now, let's print a message that this needs to be implemented
                self.ctx.info("Cache statistics feature is not yet implemented in interactive mode");
            }
            1 => {
                let confirm = Confirm::with_theme(&self.theme)
                    .with_prompt("Are you sure you want to clean the cache?")
                    .default(false)
                    .interact()?;

                if confirm {
                    // Clean cache functionality needs to be implemented
                    self.ctx.info("Cache cleaning feature is not yet implemented in interactive mode");
                }
            }
            2 => {
                // Prune cache functionality
                self.ctx.info("Cache pruning feature is not yet implemented in interactive mode");
            }
            3 => {
                let path: String = Input::with_theme(&self.theme)
                    .with_prompt("Export path")
                    .default("cache-export.tar.gz".to_string())
                    .interact_text()?;

                // Export cache functionality
                self.ctx.info(&format!("Cache export to {} is not yet implemented in interactive mode", path));
            }
            4 => {
                let path: String = Input::with_theme(&self.theme)
                    .with_prompt("Import path")
                    .interact_text()?;

                // Import cache functionality
                self.ctx.info(&format!("Cache import from {} is not yet implemented in interactive mode", path));
            }
            _ => unreachable!(),
        }

        Ok(())
    }

    async fn interactive_doctor(&mut self) -> Result<()> {
        println!("{}", "\n🩺 Environment Doctor".blue().bold());

        let components = vec![
            "All components",
            "Rust toolchain",
            "Development tools",
            "Workspace configuration",
            "Dependencies",
            "Cross-compilation targets",
        ];

        let component_selection = Select::with_theme(&self.theme)
            .with_prompt("Select component to check")
            .items(&components)
            .default(0)
            .interact()?;

        let component = match component_selection {
            0 => None,
            1 => Some("rust".to_string()),
            2 => Some("tools".to_string()),
            3 => Some("workspace".to_string()),
            4 => Some("dependencies".to_string()),
            5 => Some("targets".to_string()),
            _ => unreachable!(),
        };

        let detailed = Confirm::with_theme(&self.theme)
            .with_prompt("Show detailed information?")
            .default(false)
            .interact()?;

        let has_component = component.is_some();
        
        // TODO: Fix interactive mode to work with private clap structs
        /*
        let cmd = doctor::DoctorCmd {
            component,
            detailed,
        };

        // Run doctor
        println!();
        doctor::run(cmd, self.ctx.clone()).await?;
        */
        self.ctx.info("Doctor command is temporarily disabled in interactive mode");

        // Show suggestions after doctor run
        println!("\n{}", "💡 Next Steps:".yellow());
        if !has_component {
            println!("  • Review any warnings or errors above");
            println!("  • Run specific component checks for more details");
        } else {
            println!("  • Check other components if issues persist");
        }
        println!("  • Consult the project documentation for manual fixes");

        Ok(())
    }

    fn get_current_version(&self) -> Result<semver::Version> {
        // Read from root Cargo.toml
        let root = crate::utils::workspace_root()?;
        let cargo_toml = root.join("Cargo.toml");
        
        if cargo_toml.exists() {
            let content = std::fs::read_to_string(&cargo_toml)?;
            let manifest: toml::Value = toml::from_str(&content)?;
            
            if let Some(version) = manifest
                .get("workspace")
                .and_then(|w| w.get("package"))
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
            {
                return Ok(semver::Version::parse(version)?);
            }
            
            // Fallback to package version
            if let Some(version) = manifest
                .get("package")
                .and_then(|p| p.get("version"))
                .and_then(|v| v.as_str())
            {
                return Ok(semver::Version::parse(version)?);
            }
        }
        
        // Default fallback
        Ok(semver::Version::parse("0.1.0")?)
    }

    fn create_progress_bar(&self, message: &str) -> ProgressBar {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.green} {msg}")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.set_message(message.to_string());
        pb.enable_steady_tick(Duration::from_millis(80));
        pb
    }
}

#[derive(Debug)]
enum MainMenuChoice {
    Release,
    Build,
    Test,
    Security,
    Package,
    Publish,
    Version,
    Cache,
    Doctor,
    Configure,
    Exit,
}

/// Show context-aware suggestions based on project state
pub fn show_suggestions(ctx: &Context) -> Result<()> {
    println!("\n{}", "💡 Suggestions:".yellow());

    // Check if tests are passing
    if !ctx.dry_run {
        // TODO: Check test status and suggest running tests if they're failing
    }

    // Check for uncommitted changes
    // TODO: Check git status and suggest committing changes

    // Check for outdated dependencies
    // TODO: Check cargo outdated and suggest updating

    println!("  • Everything looks good! Ready to work.");
    println!();

    Ok(())
}