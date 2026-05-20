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

Published releases also trigger [sbom.yml](../.github/workflows/sbom.yml),
which attaches SPDX and CycloneDX JSON SBOM files to the GitHub release.
Repository changes are additionally covered by:

- [secret-scan.yml](../.github/workflows/secret-scan.yml) for Gitleaks-based
  history scanning
- [dependency-vulnerability-triage.yml](../.github/workflows/dependency-vulnerability-triage.yml)
  for PR dependency review and SBOM-backed vulnerability triage

The packaged tarballs include:

- `bin/merovingian-server`
- `bin/merovingian-db-migrate`
- `config/merovingian.conf.example`
- `docs/01-progress-tracker.md`
- `docs/configuration.md`
- `docs/release-process.md`
- `docs/security-review-checklist.md`
- Linux and BSD packaging scaffolds, including Debian control metadata, RPM
  spec metadata, FreeBSD manifest metadata, OpenBSD packing-list metadata, and
  NetBSD/pkgsrc Makefile metadata
- `README.md`
- `LICENSE`

## Production work that remains open

Alpha prerelease publication is not the same as a production release.
The current workflow does not yet attach:

- artifact signatures
- provenance attestations
- a release-attached dependency or license report

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
The matching release event also publishes the SBOM assets, and the scheduled
dependency-triage workflow keeps a separate vulnerability report artifact.

## Rolling latest packages

Pushes to `main` also trigger [packages.yml](../.github/workflows/packages.yml).
That workflow rebuilds the Debian, Fedora RPM, FreeBSD, and static Linux
fallback packages, replaces the rolling `latest` GitHub prerelease, and uploads
fresh package checksums.
The publish step resolves and deletes the existing `latest` release with an
explicit `--repo "${{ github.repository }}"` scope before recreating it so the
artifact-only job does not depend on checkout state.

The static Linux fallback artifact is built on Alpine/musl with `-static-pie`
and packaged as `merovingian-<version>-linux-static-x86_64.tar.gz`. It is a
portability fallback for older Linux distributions that cannot easily consume
the `.deb` or `.rpm`; distro packages remain preferred where available because
their OpenSSL, libsodium, and libpq dependencies receive normal OS security
updates.
