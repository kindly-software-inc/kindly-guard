# Quick Fix for Musl/OpenSSL Build Issues

## If OpenSSL Error on Musl

### Option 1: Fix in GitHub Actions (Current Solution)
```yaml
- name: Setup musl tools and OpenSSL
  if: matrix.target == 'x86_64-unknown-linux-musl'
  run: |
    sudo apt-get update
    sudo apt-get install -y musl-tools musl-dev pkg-config libssl-dev
    echo "OPENSSL_STATIC=1" >> $GITHUB_ENV
    echo "PKG_CONFIG_ALLOW_CROSS=1" >> $GITHUB_ENV
```

### Option 2: Switch to rustls (Better Solution)
In Cargo.toml:
```toml
# BAD - uses OpenSSL
reqwest = "0.11"

# GOOD - uses rustls
reqwest = { version = "0.11", default-features = false, features = ["json", "rustls-tls"] }
```

### Option 3: Use cargo-zigbuild (Easiest)
```bash
cargo install cargo-zigbuild
cargo zigbuild --release --target x86_64-unknown-linux-musl
```

## Common Issues

1. **"Could not find OpenSSL"** - Missing OPENSSL_STATIC=1
2. **"pkg-config not found"** - Missing PKG_CONFIG_ALLOW_CROSS=1
3. **"cannot find -lssl"** - Missing libssl-dev
4. **Dynamic linking** - Need musl-tools installed

## Test Locally
```bash
# Install musl target
rustup target add x86_64-unknown-linux-musl

# Test build
OPENSSL_STATIC=1 cargo build --target x86_64-unknown-linux-musl

# Or use Docker
docker run --rm -v "$PWD":/volume -w /volume rust:alpine cargo build --release
```

## Verify Static Binary
```bash
ldd target/x86_64-unknown-linux-musl/release/kindlyguard
# Should output: "not a dynamic executable"
```