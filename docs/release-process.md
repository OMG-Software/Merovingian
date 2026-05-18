# Release process

This document describes the current release path for The Merovingian.

## Alpha prereleases

Alpha packages are published from Git tags that match this pattern:

```text
v*-alpha*
```

Pushing a matching tag triggers [release.yml](../.github/workflows/release.yml).
That workflow:

- builds Linux and FreeBSD packages with the hardened profile
- runs the full Meson test suite on both platforms
- runs Linux phase 1 configuration validation
- runs the unsafe-source gate
- runs release-readiness metadata checks
- packages `merovingian-server` and `merovingian-db-migrate`
- attaches SHA-256 checksum files
- publishes a GitHub prerelease with the built assets

The packaged tarballs include:

- `bin/merovingian-server`
- `bin/merovingian-db-migrate`
- `config/merovingian.conf.example`
- `docs/01-progress-tracker.md`
- `docs/configuration.md`
- `docs/release-process.md`
- `docs/security-review-checklist.md`
- Linux and BSD packaging scaffolds
- `README.md`
- `LICENSE`

## Production work that remains open

Alpha prerelease publication is not the same as a production release.
The current workflow does not yet attach:

- SBOM output
- dependency or license reports
- artifact signatures
- provenance attestations

Those remain tracked production gaps in `docs/01-progress-tracker.md`.

## Operator sequence

The release operator should still run the normal local evidence path before
creating the tag:

```sh
sh scripts/setup-dev-env.sh --check-only
meson setup build -Dbuild_tests=true -Dbuild_fuzz=true
meson compile -C build
meson test -C build --print-errorlogs
sh scripts/reject-unsafe.sh
sh scripts/check-release-readiness.sh
```

After that, create and push an alpha tag:

```sh
git tag v<version>-alpha.1
git push origin v<version>-alpha.1
```

GitHub Actions publishes the prerelease assets for that tag.
