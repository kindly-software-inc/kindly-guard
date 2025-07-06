# CI Fix for v0.11.14 - The Real Issue

## The Problem That Took 10 Versions to Find

After fixing numerous build issues from v0.11.3 to v0.11.13, the actual problem was:

**The workflow was using the deprecated `actions/create-release@v1` action**

## What We Fixed

### Before (Broken)
```yaml
- name: Create Release
  uses: actions/create-release@v1  # Deprecated since 2022!
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  with:
    tag_name: ${{ github.ref }}
    release_name: Release ${{ github.ref }}
    draft: true
    prerelease: false
```

### After (Fixed)
```yaml
- name: Create Release
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: |
    # Use gh CLI which respects modern permissions
    gh release create ${{ github.ref_name }} \
      --title "Release ${{ github.ref_name }}" \
      --draft \
      --generate-notes
```

## Why This Works

1. The `gh` CLI is GitHub's official tool
2. It respects the `permissions: contents: write` we already had
3. It's actively maintained unlike the deprecated action
4. It generates release notes automatically

## Lessons Learned

1. **Check deprecated actions first** - The error message was misleading
2. **Use official GitHub tools** - `gh` CLI over third-party actions
3. **Read the actual error location** - We fixed build issues when the release creation was failing

## What's Next

1. This fix is in place for v0.11.14
2. The workflow should now successfully create releases
3. All the build improvements from v0.11.3-v0.11.13 are still valuable

## The Journey

- v0.11.3-v0.11.7: Fixed workspace and compilation issues
- v0.11.8-v0.11.10: Fixed cross-compilation and dependencies
- v0.11.11-v0.11.13: Migrated from OpenSSL to rustls
- v0.11.14: Finally fixed the actual CI issue!

Sometimes the simplest problems hide behind complex error messages.