// Copyright 2025 Kindly Software Inc.
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

//! Self-update functionality

use anyhow::Result;
use colored::Colorize;
use semver::Version;
use serde::Deserialize;

/// GitHub release information
#[derive(Debug, Deserialize)]
struct Release {
    tag_name: String,
    name: String,
    published_at: String,
    body: String,
    assets: Vec<Asset>,
}

#[derive(Debug, Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Run the update command
pub async fn run_update(check_only: bool, _target_version: Option<String>) -> Result<()> {
    println!("{}", "KindlyGuard Self-Updater".bright_blue().bold());
    println!();

    // Get current version
    let current_version = env!("CARGO_PKG_VERSION");
    println!("Current version: {}", current_version.bright_white());

    // Check for updates
    let latest = check_for_updates().await?;
    
    if let Some(release) = latest {
        let latest_version = release.tag_name.trim_start_matches('v');
        
        println!("Latest version:  {}", latest_version.bright_green());
        println!();

        // Compare versions
        let current = Version::parse(current_version)?;
        let latest = Version::parse(latest_version)?;

        if latest > current {
            println!("{} Update available!", "🎉".bright_green());
            println!();
            println!("Release notes:");
            println!("{}", release.body.bright_cyan());
            println!();

            if !check_only {
                println!("Would you like to update? (y/N)");
                // TODO: Implement actual update
                println!("{} Update functionality coming soon!", "🚧".yellow());
                println!("For now, please use:");
                println!("  {}", "cargo install --force kindlyguard".bright_cyan());
            }
        } else if latest < current {
            println!("{} You're running a newer version than the latest release!", "🚀".bright_cyan());
        } else {
            println!("{} You're up to date!", "✅".bright_green());
        }
    } else {
        println!("{} Could not check for updates", "⚠️".yellow());
    }

    Ok(())
}

/// Check for available updates
async fn check_for_updates() -> Result<Option<Release>> {
    let client = reqwest::Client::new();
    
    let response = client
        .get("https://api.github.com/repos/samduchaine/kindly-guard/releases/latest")
        .header("User-Agent", "kindlyguard")
        .send()
        .await?;

    if response.status().is_success() {
        let release = response.json::<Release>().await?;
        Ok(Some(release))
    } else {
        Ok(None)
    }
}

/// Download and install update
async fn install_update(_release: &Release) -> Result<()> {
    // TODO: Implement actual update installation
    // 1. Find correct asset for platform
    // 2. Download to temporary location
    // 3. Verify checksum
    // 4. Replace current binary
    // 5. Restart if needed
    
    println!("Update installation not yet implemented");
    Ok(())
}