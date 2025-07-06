#!/bin/bash
# Wrapper script to run parallel CI with proper OpenSSL configuration

# Set up OpenSSL environment
export OPENSSL_DIR=/usr
export OPENSSL_LIB_DIR=/usr/lib/x86_64-linux-gnu
export OPENSSL_INCLUDE_DIR=/usr/include
export PKG_CONFIG_PATH=/usr/lib/x86_64-linux-gnu/pkgconfig:$PKG_CONFIG_PATH
export PKG_CONFIG_ALLOW_CROSS=1

# Print environment for debugging
echo "OpenSSL Environment:"
echo "  OPENSSL_DIR: $OPENSSL_DIR"
echo "  OPENSSL_LIB_DIR: $OPENSSL_LIB_DIR"
echo "  OPENSSL_INCLUDE_DIR: $OPENSSL_INCLUDE_DIR"
echo "  PKG_CONFIG_PATH: $PKG_CONFIG_PATH"
echo ""

# Run the parallel CI command
cargo xtask parallel-ci "$@"