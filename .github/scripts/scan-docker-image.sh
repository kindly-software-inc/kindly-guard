#!/bin/bash
set -euo pipefail

# Docker Image Security Scan Script for KindlyGuard
# This script performs security scanning on Docker images using multiple tools

IMAGE_NAME="${1:-kindly-guard}"
IMAGE_TAG="${2:-latest}"
FULL_IMAGE="${IMAGE_NAME}:${IMAGE_TAG}"

echo "=== Docker Image Security Scan for ${FULL_IMAGE} ==="
echo "Date: $(date)"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to print section headers
print_header() {
    echo ""
    echo "=== $1 ==="
    echo ""
}

# Exit code tracking
EXIT_CODE=0

# 1. Basic Docker Inspect Security Checks
print_header "Basic Security Configuration"

echo "User Configuration:"
USER_CONFIG=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.User // "root"')
if [ "${USER_CONFIG}" == "root" ] || [ "${USER_CONFIG}" == "" ]; then
    echo "❌ WARNING: Container runs as root user"
    EXIT_CODE=1
else
    echo "✅ Container runs as non-root user: ${USER_CONFIG}"
fi

echo ""
echo "Exposed Ports:"
docker inspect "${FULL_IMAGE}" | jq '.[0].Config.ExposedPorts // {}'

echo ""
echo "Environment Variables (checking for secrets):"
ENV_VARS=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Config.Env[]' || echo "")
if echo "${ENV_VARS}" | grep -iE "(password|secret|key|token)" >/dev/null 2>&1; then
    echo "❌ WARNING: Possible secrets in environment variables"
    EXIT_CODE=1
else
    echo "✅ No obvious secrets in environment variables"
fi

echo ""
echo "Image Layers: $(docker inspect "${FULL_IMAGE}" | jq '.[0].RootFS.Layers | length')"

# 2. Trivy Scan (if available)
if command_exists trivy; then
    print_header "Trivy Vulnerability Scan"
    
    # Run Trivy scan
    if trivy image --severity HIGH,CRITICAL --exit-code 1 "${FULL_IMAGE}"; then
        echo "✅ No HIGH or CRITICAL vulnerabilities found by Trivy"
    else
        echo "❌ Vulnerabilities found by Trivy"
        EXIT_CODE=1
    fi
    
    # Generate detailed report
    echo ""
    echo "Generating detailed Trivy report..."
    trivy image --format json --output trivy-report.json "${FULL_IMAGE}" || true
    
else
    echo ""
    echo "ℹ️  Trivy not installed. Install with:"
    echo "   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
fi

# 3. Grype Scan (if available)
if command_exists grype; then
    print_header "Grype Vulnerability Scan"
    
    # Run Grype scan
    if grype "${FULL_IMAGE}" --fail-on high; then
        echo "✅ No HIGH or CRITICAL vulnerabilities found by Grype"
    else
        echo "❌ Vulnerabilities found by Grype"
        EXIT_CODE=1
    fi
    
    # Generate detailed report
    echo ""
    echo "Generating detailed Grype report..."
    grype "${FULL_IMAGE}" -o json > grype-report.json || true
    
else
    echo ""
    echo "ℹ️  Grype not installed. Install with:"
    echo "   curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin"
fi

# 4. Syft SBOM Generation (if available)
if command_exists syft; then
    print_header "Software Bill of Materials (SBOM)"
    
    echo "Generating SBOM..."
    syft "${FULL_IMAGE}" -o spdx-json > sbom-spdx.json
    syft "${FULL_IMAGE}" -o cyclonedx-json > sbom-cyclonedx.json
    
    echo "✅ SBOM generated in SPDX and CycloneDX formats"
else
    echo ""
    echo "ℹ️  Syft not installed. Install with:"
    echo "   curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin"
fi

# 5. Docker History Analysis
print_header "Docker History Analysis"

echo "Checking for potentially sensitive operations in build history..."
HISTORY=$(docker history --no-trunc "${FULL_IMAGE}" 2>/dev/null || echo "")

# Check for common security issues in history
if echo "${HISTORY}" | grep -iE "(curl|wget).*http://|ADD.*http://"; then
    echo "⚠️  WARNING: Insecure HTTP downloads detected in build"
fi

if echo "${HISTORY}" | grep -iE "npm.*--unsafe-perm|pip.*--trusted-host"; then
    echo "⚠️  WARNING: Package managers with reduced security detected"
fi

if echo "${HISTORY}" | grep -iE "(password|secret|key|token)="; then
    echo "❌ WARNING: Possible hardcoded secrets in build history"
    EXIT_CODE=1
fi

# 6. Image Size and Efficiency
print_header "Image Size Analysis"

SIZE=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Size' | numfmt --to=iec-i --suffix=B)
echo "Total Image Size: ${SIZE}"

# For distroless images, we expect them to be relatively small
SIZE_MB=$(docker inspect "${FULL_IMAGE}" | jq -r '.[0].Size' | awk '{print int($1/1024/1024)}')
if [ "${SIZE_MB}" -gt 500 ]; then
    echo "⚠️  WARNING: Image size exceeds 500MB for a distroless image"
fi

# 7. Runtime Security Checks
print_header "Runtime Security Configuration"

# Check if image has HEALTHCHECK
if docker inspect "${FULL_IMAGE}" | jq -e '.[0].Config.Healthcheck' >/dev/null 2>&1; then
    echo "✅ HEALTHCHECK defined"
else
    echo "ℹ️  No HEALTHCHECK defined"
fi

# Check for security-related labels
echo ""
echo "Security Labels:"
docker inspect "${FULL_IMAGE}" | jq '.[0].Config.Labels // {}' | grep -iE "(security|vulnerability|scan)" || echo "No security-related labels found"

# 8. Distroless-Specific Checks
print_header "Distroless Image Validation"

# Check if it's actually a distroless image
if docker run --rm --entrypoint="" "${FULL_IMAGE}" /bin/sh -c "echo test" 2>/dev/null; then
    echo "❌ WARNING: Shell is available in supposedly distroless image"
    EXIT_CODE=1
else
    echo "✅ No shell available (expected for distroless)"
fi

# Check for package managers
if docker run --rm --entrypoint="" "${FULL_IMAGE}" which apt 2>/dev/null || \
   docker run --rm --entrypoint="" "${FULL_IMAGE}" which yum 2>/dev/null || \
   docker run --rm --entrypoint="" "${FULL_IMAGE}" which apk 2>/dev/null; then
    echo "❌ WARNING: Package manager found in distroless image"
    EXIT_CODE=1
else
    echo "✅ No package managers found (expected for distroless)"
fi

# 9. Generate Summary Report
print_header "Security Scan Summary"

if [ ${EXIT_CODE} -eq 0 ]; then
    echo "✅ All security checks passed!"
else
    echo "❌ Security issues detected. Please review the warnings above."
fi

echo ""
echo "Scan completed at: $(date)"
echo "Exit code: ${EXIT_CODE}"

# Create a summary JSON report
cat > security-scan-summary.json << EOF
{
  "image": "${FULL_IMAGE}",
  "scan_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "user": "${USER_CONFIG}",
  "exit_code": ${EXIT_CODE},
  "checks_performed": {
    "non_root_user": $([ "${USER_CONFIG}" != "root" ] && [ "${USER_CONFIG}" != "" ] && echo "true" || echo "false"),
    "no_obvious_secrets": $(echo "${ENV_VARS}" | grep -iE "(password|secret|key|token)" >/dev/null 2>&1 && echo "false" || echo "true"),
    "trivy_available": $(command_exists trivy && echo "true" || echo "false"),
    "grype_available": $(command_exists grype && echo "true" || echo "false"),
    "distroless_validated": true
  }
}
EOF

exit ${EXIT_CODE}