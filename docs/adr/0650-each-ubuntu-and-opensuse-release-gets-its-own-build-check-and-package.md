# Each Ubuntu and openSUSE release gets its own build, check and package

* Status: accepted
* Date: 2026-11-11

Technical Story: GitHub moved `ubuntu-latest` to Ubuntu 26.04 from 19 October 2026 and deprecated Node 20 for actions;
the owner asked for separate builds and packages for Ubuntu LTS and the latest Ubuntu, and for openSUSE Leap and
Tumbleweed, published in tagged releases as well as `latest`.

## Context and Problem Statement

CI built and tested Ubuntu on `ubuntu-latest` and packaged it in `ubuntu:latest`, so the label migration silently
replaced Ubuntu 24.04 (the documented minimum) with 26.04: nothing built for 24.04 any more. openSUSE was Tumbleweed
only. A `.deb` or `.rpm` links against the sonames of the release it was built on and installs only there (the Fedora
case, [ADR-0376](0376-build-an-rpm-for-fedora-44-and-for-fedora-latest.md)), so one package per distribution does not
serve its other releases. Tagged releases shipped only tarballs.

The main ruleset requires checks by exact name, among them `ubuntu-build-and-test`, `opensuse-build-and-test`,
`Debian package` (the Ubuntu package job's old name) and `OpenSUSE Tumbleweed RPM`.

## Considered Options

* Separate jobs per release, copied from one another
* Matrix jobs with `name: ${{ matrix.check }}` (or a name built from the matrix), one leg keeping each required name
* Matrix jobs with GitHub's default per-leg names and an aggregator for every required check
* For releases: build packages again in `release.yml`; call `packages.yml` from it; copy `latest`'s assets

## Decision Outcome

Chosen option: matrix jobs whose name comes from the matrix, and `release.yml` calling `packages.yml`.

* CI `ubuntu-build-and-test` runs one leg per LTS on GitHub's runner image for that release (`ubuntu-26.04`,
  `ubuntu-24.04`), never `ubuntu-latest`, so a later label migration cannot drop a release unnoticed. The 26.04 leg
  reports `ubuntu-build-and-test`, the 24.04 leg `ubuntu-24.04-build-and-test`. GitHub has runner images for LTS
  releases only, so the interim release builds in `ubuntu:rolling` as `ubuntu-rolling-build-and-test`.
* CI `opensuse-build-and-test` runs Tumbleweed under that name and Leap 16.0 as `opensuse-leap-build-and-test`. Leap
  takes `zypper update`, not `dup`: a distribution upgrade belongs to the rolling release only. The dependency step
  now fails when its third attempt does, rather than going on to a build that fails for want of a package.
* `packages.yml` `deb` builds in `ubuntu:24.04`, `ubuntu:26.04` and `ubuntu:rolling`, each leg reported as
  `Ubuntu <release> package`, and names its package `-ubuntu<VERSION_ID>.deb` from the image's `/etc/os-release`, so
  `rolling` becomes the number of the release it is that day. Every leg still installs and boots its package through
  the startup hardening gate. A matrix job reports no check under the bare job name, so `deb-all-releases` reports the
  required `Debian package` and passes only when every leg did, as `rpm-all-images` does for Fedora.
* `opensuse-rpm` builds Tumbleweed (`OpenSUSE Tumbleweed RPM`, dist `.opensuse`, unchanged) and Leap 16.0
  (`OpenSUSE Leap 16.0 RPM`, dist `.leap16`). `build-opensuse-rpm.sh` takes the tag from `MEROVINGIAN_RPM_DIST` and
  refuses one that is not a dot, a lower-case letter, then lower-case letters, digits and dots, because it lands in an
  `rpmbuild --define`.
* `release.yml` calls `packages.yml` (`distro-packages`, after `check-tag`) and stages every Ubuntu, Fedora,
  RHEL-compatible and openSUSE package with a `.sha256`. The call needs `contents: write` as a ceiling because
  `publish-latest` declares it; every called job names its own permissions, and staging, signing and publishing
  `latest` run only for a push to `main`, so a tag never touches `latest`.
* The Debian trixie package is not staged by the release: `publish_complement_evidence.py` attaches the trixie package
  Complement tested under `merovingian_<version>_amd64-debian.deb` and never replaces an asset, so a release-built
  copy under that name would make the evidence upload fail.

### Rejected

* **Copied jobs per release.** Six near-identical jobs drift apart; the Fedora and RHEL retry loops already did.
* **Default per-leg names plus aggregators for everything.** Workable, but adds an aggregator per required check;
  a matrix-built name keeps one required name on a real leg.
* **Building packages a second time in `release.yml`.** Two definitions of each package job drift apart, and the
  tag's packages would skip the gates the pull request ran.
* **Copying `latest`'s assets into the release.** `latest` is built from whatever `main` was last, not necessarily
  the tagged commit.

### Negative Consequences

* Six more jobs per pull request (two Ubuntu and one openSUSE in each of CI and packages) under the account's
  20-runner cap; the queue gate (ADR-0580) still lets Sonar and CodeQL start first.
* The new checks (`ubuntu-24.04-build-and-test`, `ubuntu-rolling-build-and-test`, `opensuse-leap-build-and-test`,
  the three `Ubuntu <release> package` checks, `OpenSUSE Leap 16.0 RPM`) are not required until the owner adds them
  to the ruleset. `Ubuntu <release> package` is covered through `Debian package` already.
* `ubuntu:rolling` and Leap 16.0 are new to CI; a package name that differs there fails the leg, which is the point.
* A tagged release runs every `packages.yml` job, the BSD packages and the Docker gate included, though it ships only
  the `.deb` and `.rpm` packages. A job's `if` must stay `${{ !cancelled() }}` (ADR-0580), so they cannot be skipped
  for a tag without changing that rule.

## Node 24 actions

The same change moves every action to a release that runs on Node 24 (`actions/checkout@v7`, `upload-artifact@v7`,
`download-artifact@v8`, `setup-python@v7`, `cache@v6`, `deploy-pages@v5`, `upload-pages-artifact@v5`,
`attest-build-provenance@v4`, and the SHA-pinned `codecov-action` v7.1.1, `ghaction-import-gpg` v7.0.0,
`action-gh-release` v3.0.4, `ccache-action` v1.2.24). Every input the workflows pass was checked against each target
release's `action.yml`. A future pin must name a release whose `runs.using` is `node24` or later.

`ccache-action` v1.2.24 installs a missing ccache without refreshing the package index unless `update-package-index` is
set, and GitHub's Ubuntu images do not ship ccache. Every job that uses it therefore installs ccache in its own
dependency step first, which already refreshes the index; the action then finds ccache and installs nothing. Turning on
`update-package-index` was rejected: it would refresh the index a second time in each job. `test_ci_workflow.py`
checks the order.

## Package-index refresh on Ubuntu

Every Ubuntu job, on a host runner or in an Ubuntu container, refreshes the package index with
`scripts/ci-apt-update.sh`. It runs `apt-get update --error-on=any`, so a refresh that reached nothing fails there and
not at the install; plain `apt-get update` exits 0 having fetched nothing. When that refresh fails, the script points
`/etc/resolv.conf` at Cloudflare (`1.1.1.1`, `1.0.0.1`) and Google (`8.8.8.8`) for the rest of the job and retries
three times. On 2026-11-11 the resolver GitHub's runners use, which Docker also hands their containers, answered
nothing for `*.ubuntu.com` for hours, on host runners and in containers alike, while Cloudflare still resolved it.
DNS carries no integrity here: apt verifies the archive's signed `Release` files whichever resolver found the mirror.

* On a host runner `/etc/resolv.conf` is a symlink to systemd-resolved's stub, which forwards to the failing
  resolver, so the script replaces the link with a file. In a container it is a bind mount that cannot be removed,
  so it is rewritten in place.
* `ubuntu-rolling-build-and-test` installs `git` before its checkout, because the tooling tests run `git ls-files`,
  so the script is not on disk when it refreshes. That job carries the same fallback inline, and
  `test_ci_workflow.py` checks it names the script's resolvers.
* The Debian trixie jobs keep plain `apt-get update`: they fetch from `deb.debian.org`, which the outage did not
  touch.

### Rejected

* **Public resolvers always** (`container.options: --dns`, or rewriting `resolv.conf` up front): ties every job to
  one outside resolver even while GitHub's works. The fallback changes nothing until a refresh has failed.
* **`azure.archive.ubuntu.com`, the mirror GitHub's Ubuntu runner images use**, as the fallback: tried and
  withdrawn. During the outage the runners could not resolve that host either.
* **Retrying through the same resolver:** the outage lasted hours, longer than any retry budget a job can spend.
