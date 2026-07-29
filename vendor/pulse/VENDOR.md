# Vendored Pulse (GenDec)

Snapshot of [onixus/GenDec](https://github.com/onixus/GenDec) used by the
scanner/AIO Dockerfiles so CI can build when GenDec is private.

## Refresh

```bash
# From a checkout of GenDec (or GenA/pulse):
rsync -a --delete \
  --exclude target --exclude macos --exclude dist --exclude .git \
  --exclude docs --exclude scripts --exclude vendor \
  /path/to/GenDec/ ./vendor/pulse/
# Keep this note:
# (re-add VENDOR.md if wiped)
```

Or copy `Cargo.toml`, `Cargo.lock`, `src/` only.

Do **not** commit `target/` or macOS app artifacts.
