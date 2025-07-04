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
use kindly_guard_server::config::Config;

fn main() {
    println!("Testing enhanced mode configuration...");
    
    let mut config = Config::default();
    println!("Default enhanced mode: {:?}", config.resilience.enhanced_mode);
    
    config.resilience.enhanced_mode = true;
    println!("After setting enhanced mode: {:?}", config.resilience.enhanced_mode);
    
    // Check if enhanced feature is available
    #[cfg(feature = "enhanced")]
    {
        println!("Enhanced feature is ENABLED");
    }
    
    #[cfg(not(feature = "enhanced"))]
    {
        println!("Enhanced feature is DISABLED");
    }
}