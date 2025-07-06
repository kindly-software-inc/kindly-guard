# Docker Hub Publishing Guide

This guide documents the manual process for publishing KindlyGuard to Docker Hub and GitHub Container Registry.

## Prerequisites

1. **Docker Hub Account**: Create at [hub.docker.com](https://hub.docker.com)
2. **Docker CLI**: Installed and configured
3. **Docker Buildx**: For multi-platform builds
4. **Repository Access**: Push permissions to `kindlysoftware/kindlyguard`

## Authentication Setup

### Docker Hub

```bash
# Option 1: Interactive login
docker login

# Option 2: Token-based login (recommended)
export DOCKER_TOKEN="your-docker-hub-access-token"
echo $DOCKER_TOKEN | docker login --username kindlysoftware --password-stdin
```

To create an access token:
1. Go to [Docker Hub Account Settings](https://hub.docker.com/settings/security)
2. Click "New Access Token"
3. Give it a descriptive name (e.g., "kindlyguard-publish")
4. Copy the token and store it securely

### GitHub Container Registry (Optional)

```bash
export GITHUB_TOKEN="your-github-personal-access-token"
echo $GITHUB_TOKEN | docker login ghcr.io --username kindlysoftware --password-stdin
```

## Automated Publishing

Use the provided script for the easiest publishing experience:

```bash
# Publish latest version
./docker-publish.sh

# Publish specific version
./docker-publish.sh 0.1.0
```

## Manual Publishing Process

If you prefer to publish manually or the script fails:

### 1. Setup Multi-Platform Builder

```bash
# Create a new builder instance
docker buildx create --name kindlyguard-builder --use

# Bootstrap the builder
docker buildx inspect --bootstrap
```

### 2. Build and Push to Docker Hub

```bash
# Set version
VERSION="0.1.0"  # or "latest"

# Build and push multi-platform image
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t kindlysoftware/kindlyguard:${VERSION} \
  -t kindlysoftware/kindlyguard:latest \
  --push \
  .
```

### 3. Build and Push to GitHub Container Registry (Optional)

```bash
# Build and push to ghcr.io
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/kindlysoftware/kindlyguard:${VERSION} \
  -t ghcr.io/kindlysoftware/kindlyguard:latest \
  --push \
  .
```

### 4. Update Docker Hub README

The Docker Hub README can be updated in two ways:

#### Via Web Interface
1. Go to [Docker Hub Repository](https://hub.docker.com/r/kindlysoftware/kindlyguard)
2. Click on the repository
3. Update the description and full description fields

#### Via API
```bash
# Set your credentials
DOCKERHUB_USER="kindlysoftware"
DOCKERHUB_PASS="${DOCKER_TOKEN}"
DOCKERHUB_REPO="kindlyguard"

# Get auth token
TOKEN=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"${DOCKERHUB_USER}\", \"password\": \"${DOCKERHUB_PASS}\"}" \
  https://hub.docker.com/v2/users/login/ | jq -r .token)

# Update README
curl -X PATCH \
  -H "Authorization: JWT ${TOKEN}" \
  -H "Content-Type: application/json" \
  -d "{\"full_description\": $(cat DOCKER_HUB_README.md | jq -Rs .)}" \
  https://hub.docker.com/v2/repositories/${DOCKERHUB_USER}/${DOCKERHUB_REPO}/
```

## Testing Published Images

After publishing, always test the images:

```bash
# Test Docker Hub image
docker run --rm kindlysoftware/kindlyguard:latest --version

# Test specific architecture
docker run --rm --platform linux/arm64 kindlysoftware/kindlyguard:latest --version

# Test ghcr.io image
docker run --rm ghcr.io/kindlysoftware/kindlyguard:latest --version
```

## Troubleshooting

### Builder Issues

```bash
# List builders
docker buildx ls

# Remove old builder
docker buildx rm kindlyguard-builder

# Create fresh builder
docker buildx create --name kindlyguard-builder --use
```

### Authentication Issues

```bash
# Check current login status
docker info | grep Username

# Logout and login again
docker logout
docker login
```

### Platform Build Failures

If multi-platform builds fail, try building platforms separately:

```bash
# Build AMD64 only
docker buildx build --platform linux/amd64 -t kindlysoftware/kindlyguard:test-amd64 --push .

# Build ARM64 only
docker buildx build --platform linux/arm64 -t kindlysoftware/kindlyguard:test-arm64 --push .
```

## Security Best Practices

1. **Never commit tokens**: Always use environment variables
2. **Use access tokens**: Not your Docker Hub password
3. **Limit token scope**: Create tokens with minimal required permissions
4. **Rotate tokens**: Regularly update access tokens
5. **Review images**: Scan published images for vulnerabilities

```bash
# Scan with Docker Scout
docker scout cves kindlysoftware/kindlyguard:latest
```

## CI/CD Integration

For GitHub Actions integration, add these secrets to your repository:

- `DOCKERHUB_USERNAME`: Your Docker Hub username
- `DOCKERHUB_TOKEN`: Docker Hub access token
- `GITHUB_TOKEN`: Already provided by GitHub Actions

Example workflow snippet:

```yaml
- name: Login to Docker Hub
  uses: docker/login-action@v3
  with:
    username: ${{ secrets.DOCKERHUB_USERNAME }}
    password: ${{ secrets.DOCKERHUB_TOKEN }}

- name: Build and push
  uses: docker/build-push-action@v5
  with:
    context: .
    platforms: linux/amd64,linux/arm64
    push: true
    tags: |
      kindlysoftware/kindlyguard:latest
      kindlysoftware/kindlyguard:${{ github.ref_name }}
```

## Maintenance

- **Update README**: Keep DOCKER_HUB_README.md in sync with main README
- **Version tags**: Always tag releases with semantic versions
- **Platform testing**: Test on both amd64 and arm64 before release
- **Security scanning**: Run security scans on each release