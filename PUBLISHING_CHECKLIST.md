# Publishing Checklist for KindlyGuard

## Pre-Publishing Tasks

### 1. Version Consistency ✅
- [ ] Update version in root `Cargo.toml` to 0.1.0
- [ ] Ensure all workspace crates use `version.workspace = true`
- [ ] Update npm package version to match

### 2. Dependencies ✅
- [x] Fix path dependency in kindly-guard-cli
- [ ] Verify all dependencies are published crates
- [ ] No git dependencies

### 3. Documentation ✅
- [x] README.md exists for all crates
- [x] License file present (Apache-2.0)
- [ ] Update repository URLs to kindly-software-inc

### 4. Tokens Setup ✅
- [x] CARGO_REGISTRY_TOKEN in .env
- [x] NPM_TOKEN in .env
- [x] DOCKER_USERNAME and DOCKER_TOKEN in .env
- [ ] GitHub secrets configured

### 5. Testing
- [ ] Run `cargo test --all`
- [ ] Run `cargo clippy --all`
- [ ] Test npm package locally
- [ ] Build Docker image locally

## Publishing Order

1. **crates.io**
   ```bash
   ./scripts/publish-crates.sh
   ```
   - First: kindly-guard-server
   - Then: kindly-guard-cli

2. **npm**
   ```bash
   ./scripts/publish-npm.sh
   ```

3. **Docker Hub**
   ```bash
   ./scripts/publish-docker.sh
   ```

Or use the master script:
```bash
./scripts/publish-all.sh
```

## Post-Publishing

- [ ] Create GitHub release with changelog
- [ ] Update documentation site
- [ ] Announce on social media
- [ ] Update README badges

## Troubleshooting

### Crates.io Issues
- If "crate name already taken": Choose different name or contact support
- If "version already exists": Bump version number
- If "dependency not found": Ensure dependencies are published first

### npm Issues
- If "name already taken": We're using `kindly-guard`
- If "authentication failed": Check NPM_TOKEN
- Platform packages must be published after main package

### Docker Issues
- If "multi-platform build fails": Ensure Docker buildx is installed
- If "push denied": Check DOCKER_TOKEN permissions
- If "manifest error": Rebuild with `--no-cache`