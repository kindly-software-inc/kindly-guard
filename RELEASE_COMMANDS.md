# Release Commands for v0.9.0

## 1. Push to GitHub

```bash
# Push commits and tags
git push origin main
git push origin v0.9.0
```

## 2. Create GitHub Release

Use GitHub UI or CLI:

```bash
gh release create v0.9.0 \
  --title "KindlyGuard v0.9.0 - Initial Open Source Release" \
  --notes-file RELEASE_NOTES_v0.9.0.md \
  --prerelease \
  target/release/kindly-guard
```

## 3. Build and Push Docker Image

```bash
# Build image
sudo docker build -t kindlyguard/kindly-guard:0.9.0 -t kindlyguard/kindly-guard:latest .

# Push to Docker Hub
docker login
docker push kindlyguard/kindly-guard:0.9.0
docker push kindlyguard/kindly-guard:latest
```

## 4. Publish to crates.io

```bash
# Dry run first
cd kindly-guard-server
cargo publish --dry-run

# Publish
cargo publish
```

## 5. npm Package (if applicable)

```bash
# Update package.json version to 0.9.0
# Then publish
npm publish
```

## 6. Social Media Announcements

### Twitter/X
Post the content from ANNOUNCEMENT.md with link to GitHub

### Reddit
- r/rust - Focus on Rust implementation
- r/netsec - Focus on security features
- r/programming - General announcement

### Hacker News
Title: "Show HN: KindlyGuard – Open Source Security for AI Interactions"
Link to GitHub repo

### Discord/Slack
Post in relevant security and Rust communities

## 7. Update Documentation Site

If docs site exists, update with:
- Installation instructions
- v0.9.0 API documentation
- Migration guide (if needed)

## 8. Monitor

- Watch GitHub issues for early feedback
- Monitor social media for questions
- Be ready to release v0.9.3 for critical fixes

## Verification Checklist

- [ ] Tag created and pushed
- [ ] GitHub release created with binaries
- [ ] Docker image published
- [ ] crates.io package published  
- [ ] Social media announced
- [ ] Documentation updated
- [ ] Community notified