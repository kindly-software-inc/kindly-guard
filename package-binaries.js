#!/usr/bin/env node

/**
 * KindlyGuard Binary Packaging Script
 * 
 * This script handles:
 * - Reading compiled binaries from build output
 * - Updating version numbers across all packages
 * - Preparing packages for npm publishing
 * - Validating package contents
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

// Configuration
const CONFIG = {
    version: process.env.VERSION || getVersionFromGit() || '0.2.0',
    projectRoot: path.join(__dirname),
    npmDir: path.join(__dirname, 'npm-package'),
    distDir: path.join(__dirname, 'dist'),
    releaseDir: path.join(__dirname, 'release'),
    platforms: [
        { platform: 'linux', arch: 'x64', target: 'x86_64-unknown-linux-gnu' },
        { platform: 'linux', arch: 'arm64', target: 'aarch64-unknown-linux-gnu' },
        { platform: 'darwin', arch: 'x64', target: 'x86_64-apple-darwin' },
        { platform: 'darwin', arch: 'arm64', target: 'aarch64-apple-darwin' },
        { platform: 'win32', arch: 'x64', target: 'x86_64-pc-windows-msvc' }
    ]
};

// Colors for console output
const colors = {
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    red: '\x1b[31m',
    blue: '\x1b[34m',
    reset: '\x1b[0m'
};

// Logging utilities
const log = {
    status: (msg) => console.log(`${colors.green}[✓]${colors.reset} ${msg}`),
    info: (msg) => console.log(`${colors.blue}[i]${colors.reset} ${msg}`),
    warning: (msg) => console.log(`${colors.yellow}[!]${colors.reset} ${msg}`),
    error: (msg) => console.log(`${colors.red}[✗]${colors.reset} ${msg}`),
    header: (msg) => {
        console.log('');
        console.log(`${colors.blue}==== ${msg} ====${colors.reset}`);
        console.log('');
    }
};

// Get version from git tag
function getVersionFromGit() {
    try {
        const version = execSync('git describe --tags --abbrev=0', { encoding: 'utf8' }).trim();
        return version.replace(/^v/, '');
    } catch (e) {
        return null;
    }
}

// Ensure directory exists
function ensureDir(dir) {
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

// Calculate file checksum
function calculateChecksum(filePath) {
    const hash = crypto.createHash('sha256');
    const data = fs.readFileSync(filePath);
    hash.update(data);
    return hash.digest('hex');
}

// Get file size in human-readable format
function getFileSize(filePath) {
    const stats = fs.statSync(filePath);
    const bytes = stats.size;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
}

// Validate binary file
function validateBinary(filePath) {
    if (!fs.existsSync(filePath)) {
        return { valid: false, reason: 'File not found' };
    }

    const stats = fs.statSync(filePath);
    
    if (stats.size === 0) {
        return { valid: false, reason: 'File is empty' };
    }

    if (stats.size < 1024) {
        return { valid: false, reason: 'File too small to be a valid binary' };
    }

    // Check if file is executable on Unix platforms
    if (process.platform !== 'win32') {
        try {
            fs.accessSync(filePath, fs.constants.X_OK);
        } catch (e) {
            return { valid: false, reason: 'File is not executable' };
        }
    }

    return { valid: true };
}

// Update version in package.json files
function updatePackageVersions() {
    log.header('Updating Package Versions');

    const packagesToUpdate = [
        path.join(CONFIG.npmDir, 'package.json'),
        path.join(CONFIG.projectRoot, 'package.json'),
        path.join(CONFIG.projectRoot, 'kindly-guard-shield', 'package.json'),
        path.join(CONFIG.projectRoot, 'claude-code-kindlyguard', 'package.json')
    ];

    packagesToUpdate.forEach(packagePath => {
        if (fs.existsSync(packagePath)) {
            try {
                const pkg = JSON.parse(fs.readFileSync(packagePath, 'utf8'));
                const oldVersion = pkg.version;
                pkg.version = CONFIG.version;

                // Update dependencies if they reference @kindlyguard packages
                ['dependencies', 'devDependencies', 'optionalDependencies'].forEach(depType => {
                    if (pkg[depType]) {
                        Object.keys(pkg[depType]).forEach(dep => {
                            if (dep.startsWith('@kindlyguard/')) {
                                pkg[depType][dep] = CONFIG.version;
                            }
                        });
                    }
                });

                fs.writeFileSync(packagePath, JSON.stringify(pkg, null, 2) + '\n');
                log.status(`Updated ${path.basename(path.dirname(packagePath))} from ${oldVersion} to ${CONFIG.version}`);
            } catch (e) {
                log.warning(`Failed to update ${packagePath}: ${e.message}`);
            }
        }
    });
}

// Process platform binaries
function processPlatformBinaries() {
    log.header('Processing Platform Binaries');

    const results = {
        success: [],
        failed: []
    };

    CONFIG.platforms.forEach(({ platform, arch, target }) => {
        const platformKey = `${platform}-${arch}`;
        log.info(`Processing ${platformKey}`);

        const ext = platform === 'win32' ? '.exe' : '';
        const sourceDir = path.join(CONFIG.projectRoot, 'target', target, 'release');
        const destDir = path.join(CONFIG.npmDir, 'npm', platformKey);
        
        ensureDir(destDir);

        // Binaries to process
        const binaries = [
            { source: `kindly-guard${ext}`, dest: `kindlyguard${ext}` },
            { source: `kindly-guard-cli${ext}`, dest: `kindlyguard-cli${ext}` }
        ];

        const platformResult = {
            platform: platformKey,
            binaries: [],
            valid: true
        };

        binaries.forEach(({ source, dest }) => {
            const sourcePath = path.join(sourceDir, source);
            const destPath = path.join(destDir, dest);

            if (fs.existsSync(sourcePath)) {
                const validation = validateBinary(sourcePath);
                
                if (validation.valid) {
                    fs.copyFileSync(sourcePath, destPath);
                    
                    // Make executable on Unix
                    if (platform !== 'win32') {
                        fs.chmodSync(destPath, 0o755);
                    }

                    const checksum = calculateChecksum(destPath);
                    const size = getFileSize(destPath);

                    platformResult.binaries.push({
                        name: dest,
                        size,
                        checksum
                    });

                    log.status(`  ${dest} (${size})`);
                } else {
                    log.error(`  ${source}: ${validation.reason}`);
                    platformResult.valid = false;
                }
            } else {
                log.warning(`  ${source}: Not found`);
            }
        });

        if (platformResult.binaries.length > 0) {
            // Create checksums file
            const checksumContent = platformResult.binaries
                .map(b => `${b.checksum}  ${b.name}`)
                .join('\n');
            
            fs.writeFileSync(path.join(destDir, 'checksums.txt'), checksumContent + '\n');

            // Create platform package.json
            createPlatformPackage(platform, arch, destDir);
            
            results.success.push(platformResult);
        } else {
            results.failed.push(platformKey);
        }
    });

    return results;
}

// Create platform-specific package.json
function createPlatformPackage(platform, arch, destDir) {
    const packageJson = {
        name: `@kindlyguard/${platform}-${arch}`,
        version: CONFIG.version,
        description: `KindlyGuard binaries for ${platform}-${arch}`,
        author: "samduchaine",
        license: "MIT",
        repository: {
            type: "git",
            url: "git+https://github.com/samduchaine/kindly-guard.git"
        },
        files: [
            "kindlyguard*",
            "checksums.txt",
            "README.md"
        ],
        os: [platform],
        cpu: [arch],
        publishConfig: {
            access: "public"
        }
    };

    fs.writeFileSync(
        path.join(destDir, 'package.json'), 
        JSON.stringify(packageJson, null, 2) + '\n'
    );

    // Create README
    const readme = `# KindlyGuard Binaries for ${platform}-${arch}

This package contains pre-built KindlyGuard binaries for ${platform} ${arch}.

Version: ${CONFIG.version}

## Installation

This package is automatically installed as an optional dependency of the main \`kindlyguard\` package.

### Direct Installation

\`\`\`bash
npm install @kindlyguard/${platform}-${arch}
\`\`\`

### Main Package Installation

For normal usage, install the main package:

\`\`\`bash
npm install -g kindlyguard
\`\`\`

## Files

- \`kindlyguard\` - Main KindlyGuard server binary
- \`kindlyguard-cli\` - Command-line interface
- \`checksums.txt\` - SHA256 checksums for verification

## Verification

To verify the integrity of the binaries:

\`\`\`bash
# On Linux/macOS
sha256sum -c checksums.txt

# On Windows (PowerShell)
Get-Content checksums.txt | ForEach-Object {
    $parts = $_ -split '  '
    $hash = (Get-FileHash -Path $parts[1] -Algorithm SHA256).Hash
    if ($hash -eq $parts[0].ToUpper()) {
        Write-Host "$($parts[1]): OK" -ForegroundColor Green
    } else {
        Write-Host "$($parts[1]): FAILED" -ForegroundColor Red
    }
}
\`\`\`

## License

MIT
`;

    fs.writeFileSync(path.join(destDir, 'README.md'), readme);
}

// Validate all packages
function validatePackages() {
    log.header('Validating Packages');

    const npmPackagesDir = path.join(CONFIG.npmDir, 'npm');
    const validationResults = [];

    if (!fs.existsSync(npmPackagesDir)) {
        log.error('No npm packages directory found');
        return false;
    }

    fs.readdirSync(npmPackagesDir).forEach(platformDir => {
        const platformPath = path.join(npmPackagesDir, platformDir);
        
        if (fs.statSync(platformPath).isDirectory()) {
            const result = {
                platform: platformDir,
                valid: true,
                issues: []
            };

            // Check for required files
            const requiredFiles = ['package.json', 'README.md', 'checksums.txt'];
            const hasKindlyguard = fs.existsSync(path.join(platformPath, 'kindlyguard')) || 
                                 fs.existsSync(path.join(platformPath, 'kindlyguard.exe'));

            if (!hasKindlyguard) {
                result.valid = false;
                result.issues.push('Missing kindlyguard binary');
            }

            requiredFiles.forEach(file => {
                if (!fs.existsSync(path.join(platformPath, file))) {
                    result.valid = false;
                    result.issues.push(`Missing ${file}`);
                }
            });

            // Validate package.json
            try {
                const pkg = JSON.parse(fs.readFileSync(path.join(platformPath, 'package.json'), 'utf8'));
                
                if (pkg.version !== CONFIG.version) {
                    result.issues.push(`Version mismatch: ${pkg.version} != ${CONFIG.version}`);
                }

                if (!pkg.name.startsWith('@kindlyguard/')) {
                    result.issues.push('Invalid package name');
                    result.valid = false;
                }
            } catch (e) {
                result.valid = false;
                result.issues.push(`Invalid package.json: ${e.message}`);
            }

            validationResults.push(result);

            if (result.valid) {
                log.status(`${platformDir}: Valid`);
            } else {
                log.error(`${platformDir}: Invalid - ${result.issues.join(', ')}`);
            }
        }
    });

    return validationResults.every(r => r.valid);
}

// Generate summary report
function generateSummary(results) {
    log.header('Packaging Summary');

    console.log(`Version: ${CONFIG.version}`);
    console.log(`Platform: ${process.platform}-${process.arch}`);
    console.log('');

    if (results.success.length > 0) {
        console.log('Successfully packaged:');
        results.success.forEach(platform => {
            console.log(`  ${platform.platform}:`);
            platform.binaries.forEach(binary => {
                console.log(`    - ${binary.name} (${binary.size})`);
            });
        });
    }

    if (results.failed.length > 0) {
        console.log('');
        console.log('Failed platforms:');
        results.failed.forEach(platform => {
            console.log(`  - ${platform}`);
        });
    }

    console.log('');
    console.log('NPM packages ready for publishing:');
    
    const npmPackagesDir = path.join(CONFIG.npmDir, 'npm');
    if (fs.existsSync(npmPackagesDir)) {
        fs.readdirSync(npmPackagesDir).forEach(dir => {
            const pkgPath = path.join(npmPackagesDir, dir, 'package.json');
            if (fs.existsSync(pkgPath)) {
                const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
                console.log(`  - ${pkg.name}@${pkg.version}`);
            }
        });
    }

    console.log('');
    log.status('Packaging complete!');
    console.log('');
    console.log('Next steps:');
    console.log('  1. Test packages locally: npm run test-packages');
    console.log('  2. Publish to npm: npm run publish-all');
    console.log('  3. Create GitHub release with tag: v' + CONFIG.version);
}

// Main execution
async function main() {
    try {
        log.header('KindlyGuard Binary Packaging');
        console.log(`Version: ${CONFIG.version}`);

        // Update versions
        updatePackageVersions();

        // Process binaries
        const results = processPlatformBinaries();

        // Validate packages
        const isValid = validatePackages();

        if (!isValid) {
            log.error('Package validation failed!');
            process.exit(1);
        }

        // Generate summary
        generateSummary(results);

    } catch (error) {
        log.error(`Fatal error: ${error.message}`);
        console.error(error.stack);
        process.exit(1);
    }
}

// Run if called directly
if (require.main === module) {
    main();
}

module.exports = {
    CONFIG,
    updatePackageVersions,
    processPlatformBinaries,
    validatePackages
};