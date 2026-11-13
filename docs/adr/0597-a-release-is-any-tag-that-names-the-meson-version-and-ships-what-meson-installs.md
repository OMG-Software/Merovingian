# A release is any tag that names the meson.build version, and ships what Meson installs

* Status: accepted (the tarball of the tag's own build is superseded by [ADR-0742](0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md): a tag ships the `latest` package set, and its only tarball is the static one)
* Date: 2026-11-10

## Context and Problem Statement

`release.yml` published a GitHub release only for tags matching `v*-alpha*`. Any other tag published nothing, though the
project's versions are plain `0.MINOR.PATCH` (docs/versioning.md) and 1.0.0 is the production release. The owner asked
for releases from plain `v*` tags.

Widening the pattern to `v*` means any tag starting with `v` would build and publish, including one that does not match
the version the commit's binaries report. Every release was also marked `prerelease: true` by a constant.

The release tarballs were assembled by copying `merovingian-server` and `merovingian-db-migrate` by name. That list missed
both workers that a build installs to `<prefix>/libexec/merovingian`, `merovingian-fed-worker` and
`merovingian-thumbnail-worker`. The Linux job did not install libpng or libjpeg-turbo either, so it never built the
thumbnail worker. A release with the shipped example configuration had no federation worker to start.

## Considered Options

* Trigger on `v*`, and refuse a tag that is not exactly `v<meson.build version>` before anything is built
* Trigger on `v*` and publish whatever is tagged
* Trigger on a strict pattern such as `v[0-9]+.[0-9]+.[0-9]+`

For the tarball contents:

* Stage from `meson install --destdir`, and require the four executables a release carries
* Keep the hand-written copy list and add the two workers to it

## Decision Outcome

Chosen: any `v*` tag starts `release.yml`, and its first job, `check-tag`, fails unless the tag is exactly
`v<meson.build version>`. Every other job needs it. A suffixed tag such as `v0.12.90-alpha.1` is refused. GitHub's tag
filters are globs, not regular expressions, so they cannot express "the version in this commit's meson.build". That check
has to run in the workflow.

`check-tag` also sets the release's prerelease flag: true for any `0.x` version, false from 1.0.0. A 0.x tag does not
replace the rolling `latest` as GitHub's "Latest release" before production, and nobody has to remember to flip a
constant at 1.0.

Tarballs are staged by `scripts/stage-release-tarball.sh`. It runs `meson install --destdir` and copies everything
installed under `bin/` and `libexec/merovingian/`, so an executable added to the build ships without editing the
workflow. It refuses a build that did not install all four of `merovingian-server`, `merovingian-db-migrate`,
`merovingian-fed-worker` and `merovingian-thumbnail-worker`. The Linux release job installs `libpng-dev` and
`libturbojpeg0-dev` so the thumbnail worker builds; the FreeBSD job already installed `png` and `libjpeg-turbo`.

The thumbnail worker's path is fixed at compile time (`<prefix>/libexec/merovingian`), and only the federation worker's
can be changed (`federation.worker.binary`). The tarball therefore records the build's prefix in `INSTALL-PREFIX`, and
the release notes say to install `bin/` and `libexec/` there.

### Positive Consequences

* A release cannot be published under a tag that disagrees with the version its binaries report.
* Release tarballs carry every executable the build installs, and a build that silently lost a worker fails staging
  instead of shipping without it.

### Negative Consequences

* A mistyped tag still triggers a workflow run, which fails at `check-tag`. The tag has to be deleted by hand.
* The tarballs only work at their build prefix (`/usr/local`) unless the thumbnail worker gains a configurable path.

## Pros and Cons of the Options

### Trigger on `v*` and publish whatever is tagged

* Good, because it is the smallest change.
* Bad, because `v-test` or a tag on the wrong commit publishes a signed release whose name disagrees with its binaries.

### Trigger on a strict glob such as `v[0-9]+.[0-9]+.[0-9]+`

* Bad, because GitHub's filter glob has no repetition operator, and no pattern can compare the tag with `meson.build`.

### Keep the hand-written copy list and add the two workers

* Good, because it is the smallest diff.
* Bad, because it is how the workers were lost: the next installed executable would be missed the same way.

## Links

* [ADR-0598](0598-the-release-sbom-is-generated-from-the-licence-inventory-and-wrap-pins-inside-each-publishing-workflow.md)
  attaches the SBOM to these releases.
* [docs/release-process.md](../release-process.md), [docs/versioning.md](../versioning.md)
