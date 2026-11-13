# Build an RPM for Fedora 44 and for fedora:latest

* Status: accepted (the `fedora:latest` image is superseded by `fedora:45` in [ADR-0742](0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md))
* Deciders: James Chapman
* Date: 2026-11-03

## Context and Problem Statement

An RPM depends on the sonames of the release it was built on. The only Fedora RPM
was built on `fedora:latest`, so when that image moved to Fedora 45 and OpenSSL 4,
the published package stopped installing on Fedora 44 with `nothing provides
libcrypto.so.4`. No code or workflow change caused this, and the build stayed green.

## Considered Options

* Build on a pinned `fedora:44` and on `fedora:latest`
* Pin to a single release
* Keep only `fedora:latest`, and send other hosts to the static tarball
* Build every release since Fedora 40

## Decision Outcome

Chosen option: build on a pinned `fedora:44` and on `fedora:latest`, in both the
`rpm` package job and `fedora-build-and-test`, because hosts on either release get
a package that CI has run the suite against, and `fedora:latest` keeps warning of
changes in a new Fedora as soon as they reach the image, as it did for OpenSSL 4.

Pinning to one release looks tidier and makes builds more repeatable, but it loses
that warning and strands hosts on the newer release. The static tarball does not
receive OpenSSL or libsodium fixes through `dnf`. Older releases add CI time for
hosts nobody has asked to support.

### Consequences

* The published set covers exactly two Fedora releases. When `fedora:latest` moves
  to Fedora 46, nothing publishes a Fedora 45 RPM until the pin is changed by hand,
  so a new Fedora release means deciding whether to move or add a pin.
* The dist tag keeps the file names apart. If `fedora:latest` were ever Fedora 44,
  both builds would produce the same file name and one would overwrite the other in
  the staged assets.
* The `main` ruleset requires checks called `fedora-build-and-test` and `Fedora RPM
  package`, and a matrix job reports one check per image, none with those names. The
  `fedora-build-and-test` and `rpm-all-images` jobs report those names and pass only
  when every image passed, so adding an image needs no ruleset change.
* The full suite runs twice on Fedora, which adds CI time to every pull request.
