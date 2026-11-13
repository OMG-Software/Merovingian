# Fixed build-and-test and package platform lists, and a tag ships what latest ships

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-12

## Context and Problem Statement

The workflows had drifted apart. `ci.yml` built and tested Ubuntu 24.04 and 26.04 on runners and
`ubuntu:rolling` in a container, and Fedora on `fedora:44` and `fedora:latest`. `packages.yml` built
`latest` from moving tags too, and named some packages after their platform only at staging time
(OpenBSD, NetBSD, Debian) or not at all (FreeBSD's `.pkg`, openSUSE Tumbleweed's `.opensuse`). A
tagged release shipped a different set again: its own glibc Linux and FreeBSD tarballs, the
Ubuntu, Fedora, RHEL and openSUSE packages, and no Debian, static, FreeBSD `.pkg`, OpenBSD or
NetBSD package. The three RPM specs built with `%meson`'s `--buildtype=plain` while every other
package used the hardened profile. Which platforms does CI build and test, which does it package,
and how is a tag kept identical to `latest`?

## Decision Drivers

* The owner's lists, which differ on purpose:
  * build and test: RHEL 10, openSUSE Leap 16 and Tumbleweed, Fedora 44 and 45, Ubuntu 26.04 and
    26.10, Debian 13, FreeBSD 15, OpenBSD, NetBSD;
  * package, for `latest` and every tag, x86_64 only: the same plus Ubuntu 24.04 and the static
    Linux tarball, with FreeBSD as a `.pkg`, not a tarball.
* Every published package names the platform it installs on.
* `latest` and tag packages are built with the hardened profile.
* A required check (matched by exact name in the `main` ruleset) is never renamed.

## Considered Options

* Release stages its own list beside `packages.yml`'s (as before), with the lists kept in step by hand.
* Release calls `packages.yml` and reuses its staging and signing for the tag.
* Debian 12 packaged with clang from apt.llvm.org.
* Debian 12 not packaged.

## Decision Outcome

Chosen options: release reuses `packages.yml`'s staging and signing, and Debian 12 is not
packaged.

**Images are pinned by release.** No job builds on `ubuntu:rolling` or `fedora:latest`: the
interim Ubuntu job builds `ubuntu:26.10` (job `ubuntu-interim-build-and-test`, check
`ubuntu-26.10-build-and-test`, expected-skip job `ubuntu-interim`), Fedora builds `fedora:44` and
`fedora:45`, and the FreeBSD VMs run `release: '15'` (the newest 15.x). A moving tag let the
release CI tested differ from the release a package was published for; a pinned one is moved by
editing the workflow when a release ships. OpenBSD and NetBSD keep their action's default
release: the owner named no version.

**Ubuntu 24.04 is packaged but not built and tested.** Its `ubuntu-24.04-build-and-test` leg is
gone; it was not a required check. Its package is still built, installed and booted through the
startup hardening gate by the `deb` job.

**A tag ships exactly `latest`'s set.** `release.yml` calls `packages.yml` with `secrets: inherit`,
and `stage-package-assets` and `sign-package-assets` run for a `refs/tags/v*` push as for `main`;
`publish-latest` stays main-only. The release downloads the `signed-packages` artifact the called
workflow uploaded in the same run. One list in one job means the two cannot drift again. A second,
hand-kept list in `release.yml` was rejected: that is how they drifted. `release.yml` no longer
publishes tarballs of its own builds; `linux-release-evidence` and `freebsd-release-evidence` still
build and test with the hardened profile, run the release gates and collect the release evidence.
Per-file `.sha256` files gave way to the `SHA256SUMS` staging already wrote.
`scripts/check-release-readiness.sh` now looks for attestations, `SHA256SUMS`, signing and the
SBOM in `packages.yml`, and for the call in `release.yml`.

**Every package names its platform, and is named by the job that built it**, before it is
attested, so the attested name is the published one: `-ubuntu<release>.deb`, `-debian13.deb`,
`.fc44`/`.fc45`, `.el10`, `.tumbleweed` (was `.opensuse`, which did not say which openSUSE),
`.leap16`, `-linux-static-x86_64.tar.gz`, `-freebsd15.pkg`, `-openbsd<release>.tgz`,
`-netbsd<release>.tgz`. A BSD package's own name is in its metadata (`+CONTENTS`, `+MANIFEST`),
so renaming the file does not change what `pkg add` / `pkg_add` installs. Staging no longer
renames anything.

**Complement.** The tag release now carries its own `-debian13.deb`. The Complement step tests the
`-debian13.deb` of the `latest` built from the same commit, and `publish_complement_evidence.py`
never replaces an asset, so it attaches the tested bytes as `merovingian_<v>_<arch>-debian.deb`
(and its `.asc`). A rename changes no byte: the results' SHA-256 and the maintainer signature
still hold. It refuses a package not named as `latest` names one.

**The hardened profile everywhere.** The three RPM specs pass `--buildtype=release` after
`%meson`, whose `--buildtype=plain` it overrides (the later option wins), beside the
`-Dhardening=true` they already had. `test_packages_workflow.py` checks every package build for
both.

**Debian 12 is not packaged.** Bookworm ships clang 14 and glibc 2.36, below the clang 18 and
glibc 2.39 the project needs; building it would mean a third-party compiler repository in the
release chain. Debian 13 stays the minimum and the static tarball covers older Linux.

### Positive Consequences

* `tests/tooling/test_ci_workflow.py` and `test_packages_workflow.py` pin both lists exactly, so a
  platform cannot be added or dropped from one workflow alone.
* A tagged release has a Debian, static, FreeBSD `.pkg`, OpenBSD and NetBSD package for the first time.

### Negative Consequences

* The pinned interim release (26.10) and Fedora 45 must be moved by hand when their successors ship.
* A tag no longer offers a glibc Linux or FreeBSD tarball; `scripts/stage-release-tarball.sh` is
  kept but no workflow runs it.
* The RPM `--buildtype=release` override relies on Meson taking the last `--buildtype`; the RPM jobs
  on the pull request prove it.
* Partly supersedes [ADR-0376](0376-build-an-rpm-for-fedora-44-and-for-fedora-latest.md): Fedora 45 replaces `fedora:latest`.
