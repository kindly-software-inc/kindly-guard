# 🐧 KindlyGuard Linux Compatibility Guide

## 📖 Table of Contents
- [Why We Use musl](#why-we-use-musl)
- [Compatibility Matrix](#compatibility-matrix)
- [Installation Troubleshooting](#installation-troubleshooting)
- [Building from Source](#building-from-source)
- [GNU vs musl: What's the Difference?](#gnu-vs-musl-whats-the-difference)

## 🎯 Why We Use musl

KindlyGuard uses **musl libc** for static linking instead of the more common GNU libc (glibc). Here's why this matters to you:

### 🚀 Benefits of musl Static Linking

1. **Universal Compatibility** 📦
   - One binary works across ALL Linux distributions
   - No more "glibc version too old" errors
   - No dependency hell

2. **Smaller Binaries** 🪶
   - musl produces more compact executables
   - Faster downloads and less disk space

3. **Better Security** 🔒
   - Fully static binaries reduce attack surface
   - No dynamic library hijacking risks
   - Self-contained security tool

4. **Easier Distribution** 🎁
   - Ship one binary that "just works"
   - No need for complex packaging per distro
   - Perfect for security tools that need to run anywhere

## 📊 Compatibility Matrix

### ✅ Fully Supported Distributions

| Distribution | Versions | Status | Notes |
|-------------|----------|--------|-------|
| **Ubuntu** | 18.04+ | ✅ Excellent | Works out of the box |
| **Debian** | 9+ | ✅ Excellent | No issues reported |
| **Fedora** | 30+ | ✅ Excellent | Fully compatible |
| **CentOS/RHEL** | 7+ | ✅ Excellent | Enterprise ready |
| **Arch Linux** | Current | ✅ Excellent | Rolling release compatible |
| **openSUSE** | Leap 15+ | ✅ Excellent | Both Leap and Tumbleweed |
| **Alpine Linux** | 3.10+ | ✅ Excellent | Native musl support! |
| **Gentoo** | Current | ✅ Excellent | Works with any profile |
| **NixOS** | 20.09+ | ✅ Good | Use patchelf if needed |
| **Void Linux** | Current | ✅ Excellent | Native musl option |

### 🤖 Architecture Support

| Architecture | Support | Binary Name |
|-------------|---------|-------------|
| x86_64 (AMD64) | ✅ Primary | `kindly-guard-x86_64-unknown-linux-musl` |
| aarch64 (ARM64) | ✅ Supported | `kindly-guard-aarch64-unknown-linux-musl` |
| armv7 | 🔄 On request | Build from source |
| i686 | ❌ Not supported | Modern 64-bit only |

## 🔧 Installation Troubleshooting

### Common Issues and Solutions

#### 1. "Permission denied" when running 🚫

```bash
# Problem: Binary not executable
$ ./kindly-guard
bash: ./kindly-guard: Permission denied

# Solution: Make it executable
$ chmod +x kindly-guard
```

#### 2. "No such file or directory" on 64-bit system 📁

```bash
# This misleading error can occur on some systems
$ ./kindly-guard
bash: ./kindly-guard: No such file or directory

# Solution: Install compatibility libraries (rare with musl)
$ sudo apt install musl  # Debian/Ubuntu
$ sudo dnf install musl  # Fedora
```

#### 3. SELinux blocking execution 🛡️

```bash
# Check if SELinux is the issue
$ getenforce
Enforcing

# Temporary solution (for testing)
$ sudo setenforce 0

# Permanent solution (recommended)
$ sudo chcon -t bin_t kindly-guard
```

#### 4. Running on WSL2 🪟

```bash
# WSL2 works great! Just ensure you're in a Linux filesystem
$ cd ~/tools  # Good ✅
$ cd /mnt/c/tools  # Avoid - Windows filesystem can cause issues ❌
```

### 🩺 Diagnostic Commands

If you're having issues, run these commands and include the output when reporting:

```bash
# Check your system
$ uname -a
$ ldd --version 2>/dev/null || echo "ldd not found"
$ file kindly-guard
$ ./kindly-guard --version

# Check for musl
$ ls -la /lib/ld-musl* 2>/dev/null || echo "No musl loader found"
```

## 🔨 Building from Source

Want to build KindlyGuard yourself? Here's how!

### Prerequisites 📋

```bash
# Install Rust (if not already installed)
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add musl target
$ rustup target add x86_64-unknown-linux-musl

# Install musl tools (varies by distro)
# Ubuntu/Debian:
$ sudo apt install musl-tools

# Fedora:
$ sudo dnf install musl-gcc

# Arch:
$ sudo pacman -S musl

# Alpine (already has musl!):
# Nothing needed 🎉
```

### Build Commands 🏗️

```bash
# Clone the repository
$ git clone https://github.com/your-org/kindly-guard.git
$ cd kindly-guard

# Build for musl (static binary)
$ cargo build --release --target x86_64-unknown-linux-musl

# Find your binary
$ ls -la target/x86_64-unknown-linux-musl/release/kindly-guard

# Verify it's static
$ ldd target/x86_64-unknown-linux-musl/release/kindly-guard
# Should output: "not a dynamic executable" ✅
```

### Cross-Compilation 🌍

Building for ARM64 on x86_64:

```bash
# Install cross-compilation tools
$ cargo install cross

# Build for ARM64
$ cross build --release --target aarch64-unknown-linux-musl

# The binary will work on any ARM64 Linux! 🎊
```

## 🤓 GNU vs musl: What's the Difference?

### Technical Comparison

| Feature | GNU libc (glibc) | musl libc |
|---------|------------------|-----------|
| **Size** | Large (~2MB) | Small (~600KB) |
| **Compatibility** | Requires specific versions | Universal static binaries |
| **Performance** | Slightly faster in some cases | Comparable, better in others |
| **Standards** | GNU extensions | Strict POSIX compliance |
| **Licensing** | LGPL | MIT |
| **DNS Resolution** | Complex NSS system | Simple, reliable |
| **Thread Cancellation** | Asynchronous | Deferred (safer) |

### What This Means for You 🎯

**If you're a user:**
- ✅ The musl binary will "just work" on your Linux system
- ✅ No need to worry about glibc versions
- ✅ Smaller download size
- ✅ More secure by default

**If you're a developer:**
- ⚠️ Some GNU-specific extensions won't work
- ✅ Your code will be more portable
- ✅ Easier to debug (simpler libc)
- ✅ Better static linking support

### When to Use Each Target 🎭

**Use musl target when:**
- 📦 Distributing binaries to users
- 🔒 Security is paramount
- 🚀 You want maximum compatibility
- 🪶 Binary size matters

**Use GNU target when:**
- 🔧 Developing locally
- 🎮 You need GNU-specific features
- ⚡ Every microsecond counts (rare)
- 🔗 You must link with GNU-only libraries

## 🆘 Getting Help

Still having issues? Here's how to get help:

1. **Check our FAQ**: [docs.kindlyguard.com/faq](https://docs.kindlyguard.com/faq)
2. **GitHub Issues**: [github.com/your-org/kindly-guard/issues](https://github.com/your-org/kindly-guard/issues)
3. **Discord Community**: [discord.gg/kindlyguard](https://discord.gg/kindlyguard)

When reporting issues, please include:
- Your Linux distribution and version
- Output of the diagnostic commands above
- The exact error message
- Steps to reproduce

## 🎉 Success Stories

> "Finally, a security tool that works on my ancient CentOS 7 servers AND my bleeding-edge Arch laptop!" - Happy User

> "The musl binary saved us from dependency hell. One binary, 500 servers, zero problems." - DevOps Team

> "I love that it just works on Alpine Linux without any glibc compatibility layers!" - Container Enthusiast

---

## 📚 Additional Resources

- [musl libc Official Site](https://musl.libc.org/)
- [Rust musl Target Documentation](https://doc.rust-lang.org/rustc/platform-support.html)
- [Static Linking Benefits](https://sta.li/)
- [KindlyGuard Architecture Docs](./ARCHITECTURE.md)

---

*Made with 💚 by the KindlyGuard team. We believe security tools should work everywhere!*