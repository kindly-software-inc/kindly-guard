#!/bin/bash

# KindlyGuard npm package publishing script
# This script helps publish the placeholder package to reserve the npm name

echo "========================================"
echo "KindlyGuard NPM Package Publishing Guide"
echo "========================================"
echo ""
echo "This script will guide you through publishing the kindlyguard placeholder package."
echo ""

# Check if user is logged in to npm
echo "Step 1: Checking npm login status..."
npm whoami &> /dev/null
if [ $? -ne 0 ]; then
    echo "❌ You are not logged in to npm"
    echo ""
    echo "Please login with your npm account 'samuelduchaine':"
    echo "Run: npm login"
    echo ""
    echo "After logging in, run this script again."
    exit 1
else
    CURRENT_USER=$(npm whoami)
    echo "✅ Logged in as: $CURRENT_USER"
    echo ""
    if [ "$CURRENT_USER" != "samuelduchaine" ]; then
        echo "⚠️  Warning: You're logged in as '$CURRENT_USER', not 'samuelduchaine'"
        echo "   Make sure this is the correct account to publish under."
        echo ""
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Publishing cancelled."
            exit 1
        fi
    fi
fi

# Check package validity
echo "Step 2: Validating package..."
cd "$(dirname "$0")"
npm pack --dry-run > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ Package validation failed"
    echo "Please fix any errors and try again."
    exit 1
else
    echo "✅ Package is valid"
fi

echo ""
echo "Step 3: Package contents that will be published:"
echo "------------------------------------------------"
npm pack --dry-run 2>&1 | grep -E "^npm notice"
echo ""

# Show current package info
echo "Step 4: Current package.json info:"
echo "----------------------------------"
echo "Name:        $(node -p "require('./package.json').name")"
echo "Version:     $(node -p "require('./package.json').version")"
echo "Description: $(node -p "require('./package.json').description")"
echo "Author:      $(node -p "require('./package.json').author")"
echo ""

# Confirm publication
echo "⚠️  IMPORTANT: This will publish the package to npm publicly!"
echo "   This action cannot be undone for this version number."
echo ""
read -p "Do you want to publish 'kindlyguard' version 0.0.1? (y/N): " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Publishing package..."
    npm publish --access public
    
    if [ $? -eq 0 ]; then
        echo ""
        echo "🎉 Success! The 'kindlyguard' package has been published!"
        echo ""
        echo "Next steps:"
        echo "1. Verify the package at: https://www.npmjs.com/package/kindlyguard"
        echo "2. The name is now reserved for your account"
        echo "3. When ready to publish the full version:"
        echo "   - Update to version 1.0.0 or higher"
        echo "   - Replace placeholder content with actual implementation"
        echo "   - Run 'npm publish' again"
    else
        echo ""
        echo "❌ Publishing failed!"
        echo "Common issues:"
        echo "- Package name might already be taken"
        echo "- You might not have permissions"
        echo "- Network issues"
        echo ""
        echo "Please check the error message above and try again."
    fi
else
    echo "Publishing cancelled."
fi