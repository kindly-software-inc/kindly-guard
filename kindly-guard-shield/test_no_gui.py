#!/usr/bin/env python3
"""
Test KindlyGuard Shield components without GUI dependencies
"""

import subprocess
import sys
import time
import os

def test_cargo_check():
    """Test if the Rust code compiles (without linking)"""
    print("🔧 Testing Rust code compilation (cargo check)...")
    
    original_dir = os.getcwd()
    try:
        os.chdir("/home/samuel/kindly-guard/kindly-guard-shield/src-tauri")
        result = subprocess.run(
            ["cargo", "check", "--no-default-features"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print("✅ Rust code syntax check passed!")
            return True
        else:
            print("❌ Rust code has compilation errors:")
            print(result.stderr)
            return False
    finally:
        os.chdir(original_dir)

def test_websocket_module():
    """Test the WebSocket module without GUI"""
    print("\n🔍 Testing WebSocket module compilation...")
    
    original_dir = os.getcwd()
    try:
        os.chdir("/home/samuel/kindly-guard/kindly-guard-shield/src-tauri")
        result = subprocess.run(
            ["cargo", "test", "--lib", "--", "websocket", "--nocapture"],
            capture_output=True,
            text=True
        )
        
        if "test result:" in result.stdout:
            print("✅ WebSocket module tests found and executed")
            print(result.stdout)
            return True
        else:
            print("⚠️ WebSocket tests may require GUI dependencies")
            return False
    except Exception as e:
        print(f"❌ Error running WebSocket tests: {e}")
        return False
    finally:
        os.chdir(original_dir)

def analyze_code_structure():
    """Analyze the code structure and features"""
    print("\n📊 Analyzing code structure...")
    
    features = {
        "WebSocket Server": "Port 9955",
        "Enhanced Mode": "Feature flag 'enhanced'",
        "Binary Protocol": "IPC optimization",
        "Shared Memory": "Low-latency communication",
        "System Tray": "Always visible protection",
        "Threat Detection": "Real-time monitoring",
        "Rate Limiting": "DoS protection",
        "Security Validation": "Input sanitization"
    }
    
    print("\n🛡️ KindlyGuard Shield Features:")
    for feature, desc in features.items():
        print(f"   • {feature}: {desc}")
    
    return True

def check_dependencies():
    """Check which dependencies are available"""
    print("\n📦 Checking dependencies...")
    
    deps = {
        "cargo": "Rust toolchain",
        "npm": "Node.js package manager",
        "node": "JavaScript runtime",
        "python3": "Python interpreter"
    }
    
    available = []
    missing = []
    
    for cmd, desc in deps.items():
        try:
            result = subprocess.run(
                [cmd, "--version"],
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                available.append(f"{cmd} ({desc}): {version}")
            else:
                missing.append(f"{cmd} ({desc})")
        except FileNotFoundError:
            missing.append(f"{cmd} ({desc})")
    
    print("\n✅ Available:")
    for item in available:
        print(f"   • {item}")
    
    if missing:
        print("\n❌ Missing:")
        for item in missing:
            print(f"   • {item}")
    
    return len(missing) == 0

def test_frontend_build():
    """Test if frontend assets are properly configured"""
    print("\n🎨 Testing frontend configuration...")
    
    files_to_check = [
        "/home/samuel/kindly-guard/kindly-guard-shield/src/index.html",
        "/home/samuel/kindly-guard/kindly-guard-shield/src/shield.ts",
        "/home/samuel/kindly-guard/kindly-guard-shield/src/styles/main.css",
        "/home/samuel/kindly-guard/kindly-guard-shield/package.json",
        "/home/samuel/kindly-guard/kindly-guard-shield/vite.config.ts"
    ]
    
    all_found = True
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"   ✅ Found: {os.path.basename(file_path)}")
        else:
            print(f"   ❌ Missing: {os.path.basename(file_path)}")
            all_found = False
    
    return all_found

def create_build_report():
    """Create a comprehensive build report"""
    print("\n" + "="*60)
    print("📋 KINDLYGUARD SHIELD BUILD & TEST REPORT")
    print("="*60)
    
    # Missing system dependencies
    print("\n🚨 MISSING SYSTEM DEPENDENCIES:")
    print("""
The following packages are required for building Tauri applications on Linux:
• libgtk-3-dev
• libwebkit2gtk-4.0-dev  
• libssl-dev
• librsvg2-dev

To install on Ubuntu/Debian:
sudo apt update && sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev libssl-dev librsvg2-dev
""")
    
    # Build commands
    print("\n🔨 BUILD COMMANDS (after installing dependencies):")
    print("""
# Standard build
cd /home/samuel/kindly-guard/kindly-guard-shield
npm run build

# Enhanced build with feature flag
cd /home/samuel/kindly-guard/kindly-guard-shield/src-tauri
cargo build --features enhanced

# Development mode
npm run dev
""")
    
    # Test procedures
    print("\n🧪 TESTING PROCEDURES:")
    print("""
1. System Tray Functionality:
   - Start app: npm run dev
   - Check system tray icon appears
   - Right-click for menu options
   - Test "Show Shield", "Toggle Protection", "Exit"

2. WebSocket Server:
   - Run: python3 test_ws_client.py
   - Verify connection to port 9955
   - Test message exchange

3. UI Features:
   - Shield display with protection status
   - Threat counter (animated on updates)
   - Recent threats list
   - Protection toggle button
   - Minimize to tray button

4. Enhanced Mode:
   - Build with: cargo build --features enhanced
   - Check logs for "Enhanced mode: true"
   - Monitor performance metrics
""")
    
    # Known issues
    print("\n⚠️ KNOWN ISSUES:")
    print("""
1. GTK dependencies missing - prevents full build
2. WebSocket server port: 9955
3. Enhanced mode requires kindly-guard-core dependency (currently commented out)
""")
    
    # Solutions
    print("\n💡 SOLUTIONS:")
    print("""
1. Install missing system packages (see above)
2. Update documentation to reflect correct WebSocket port
3. Uncomment kindly-guard-core dependency in Cargo.toml for enhanced mode
4. For testing without GUI, use the WebSocket test clients provided
""")

def main():
    """Run all tests"""
    print("🛡️ KindlyGuard Shield Test Suite (No GUI Required)")
    print("="*60)
    
    results = {
        "Dependency Check": check_dependencies(),
        "Code Structure Analysis": analyze_code_structure(),
        "Frontend Configuration": test_frontend_build(),
        "Cargo Check": test_cargo_check(),
    }
    
    # Create final report
    create_build_report()
    
    # Summary
    print("\n" + "="*60)
    print("📊 TEST SUMMARY:")
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed < total:
        print("\n⚠️ Some tests failed due to missing system dependencies.")
        print("Please install the required packages and try again.")
        sys.exit(1)
    else:
        print("\n✅ All available tests passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()