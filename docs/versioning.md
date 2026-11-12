# Versioning

## Scheme

From 1.0.0 Merovingian uses **`MAJOR.MINOR.BUILD`**
([ADR-0647](adr/0647-versions-from-1-0-0-are-major-minor-build.md)).

`BUILD` is the working counter: feature, fix, and packaging branches increment
it by one, exactly as `PATCH` did before 1.0.0. The bump policy below is
unchanged. Documentation-only changes do not require a version bump
([ADR-0464](adr/0464-documentation-only-changes-do-not-require-a-version-bump.md)).

`MINOR` and `MAJOR` change only when the owner decides. The decision states the
version that follows.

**Project phase is declared in `README.md` and `CHANGELOG.md`, never encoded in
the version number** ([ADR-0647](adr/0647-versions-from-1-0-0-are-major-minor-build.md), which restates the rule
of the superseded [ADR-0047](adr/0047-keep-project-phase-out-of-the-version-string.md)).

The version is a plain string. There is no pre-release suffix, build metadata,
or epoch. All three numbers are always present (e.g. `1.0.1`, never `1.0`).

### History: the 0.x scheme

Before 1.0.0 the scheme was `0.MINOR.PATCH`. `PATCH` was the working counter.
`MINOR` was a series marker, not a milestone: it rolled over when a series grew
long, and a new series did not restart at `.0` (`0.9.25` to `0.10.1`, `0.10.63`
to `0.11.4`). `1.0.0` was cut when the project reached production. Beta was
declared at `v0.10.59`. These rules no longer apply.

## Bump policy

**One bump per branch, when the branch is created, except for documentation-only changes.** Update `CHANGELOG.md`
and every version location below together before the branch's first commit.
Do not increment again on intermediate commits. Before raising the PR, verify
that the version remains consistent with the base branch; if another branch
has used that version in the meantime, update all locations together to the
next available build number. There is no separate merge-time bump.

The one exception is the `release.yml` fix that let 1.0.0 publish: the owner
kept it at 1.0.0 and moved the unpublished `v1.0.0` tag to it
([ADR-0651](adr/0651-the-v1-0-0-tag-moves-to-the-release-workflow-fix-without-a-version-bump.md)).
It is not a precedent.

For a documentation-only branch, keep the current version and add the change
notes as bullets in its `CHANGELOG.md` entry: new guidance under `Features`, a
correction under `Bug fixes`. Changes to coding
guidance and `AGENTS.md` files are documentation changes. If the branch later
includes code, build, or packaging changes, apply the bump policy before
committing those changes.

## Changelog format

`CHANGELOG.md` opens with a short note pointing at this section and at the frozen
`CHANGELOG-pre-release.md`, then holds one entry per version, newest first. Every
entry has exactly these headings, in this order, and no others
([ADR-0741](adr/0741-each-changelog-version-has-features-security-fixes-bug-fixes-and-release-notes.md)):

```markdown
# Version x.y.z

## Features

* bullet point features list (max 2 lines per point)

## Security Fixes

* bullet point security fixes (max 2 lines per point)

## Bug fixes

* bullet point bug fixes (max 2 lines per point)

## Release notes

short paragraph about the release.
```

- **Bullets** start with `* `, wrap at 120 columns with a two-space indent, and
  run to two lines at most. Say what changed for an operator or a client, not
  how the code does it; the detail belongs in the ADR, so end the bullet with the
  ADR or audit finding it rests on, for example `(C01, ADR-0719)`. Related fixes
  may share a bullet when it still fits in two lines.
- **Features** are new behaviour: a capability, a config key, a package or a
  documented procedure. **Security Fixes** close a vulnerability or a
  denial-of-service path, including an audit finding. **Bug fixes** are every
  other correction, including a fix to a test or to CI.
- **A section with nothing in it** says `* None.`, or one bullet naming where the
  work shipped instead; a heading is never dropped.
- **Release notes** is one short paragraph: what the release is, and anything an
  operator must do or know before upgrading (a refused config key, a known
  limitation). It holds no list and no subsections.
- `tests/tooling/test_changelog_format.py` (`changelog-format-tooling`) enforces
  the headings, their order, the bullet length and the line width, and checks
  that the newest entry is the version `meson.build` declares.

## Canonical source of truth

`meson.build` — the `version:` field in the `project()` call — is the single
authoritative version. Everything else copies from it.

## Every location that must be updated

Update all of the following in one commit when the version changes. Missing any
one of them will produce a package or binary that reports a different version
than the others.

| File | What to change |
|------|---------------|
| `meson.build` | `version: 'X.Y.Z'` in the `project()` call |
| `src/main.cpp` | `constexpr auto version = std::string_view{"X.Y.Z"};` |
| `src/db_migrate.cpp` | `constexpr auto version = std::string_view{"X.Y.Z"};` |
| `packaging/freebsd/+MANIFEST` | `version: "X.Y.Z"` |
| `packaging/netbsd/Makefile` | `DISTNAME= merovingian-X.Y.Z` |
| `packaging/rpm/merovingian.spec` | `Version: X.Y.Z` **and** add a new `%changelog` entry at the top |
| `packaging/rhel/merovingian.spec` | `Version: X.Y.Z` **and** add a new `%changelog` entry at the top |
| `packaging/opensuse/merovingian.spec` | `Version: X.Y.Z` **and** add a new `%changelog` entry at the top |
| `scripts/build-deb.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-rpm.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-rhel-rpm.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-opensuse-rpm.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-freebsd-pkg.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-netbsd-pkg.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-openbsd-pkg.sh` | Comment line and `VERSION="X.Y.Z"` |
| `scripts/build-static-linux.sh` | `VERSION="${MEROVINGIAN_VERSION:-X.Y.Z}"` |
| `CHANGELOG.md` | New `# Version X.Y.Z` entry at the top in the [changelog format](#changelog-format) (never in `CHANGELOG-pre-release.md`, ADR-0740) |

### Notes

- The `.deb` `DEBIAN/control` version is generated at build time from the
  `VERSION` variable in `scripts/build-deb.sh` — it does not need a separate
  edit.
- The `packaging/deb/control` template has no version field; it is used only
  for `Depends` and other metadata, not the package version.
- The RPM-family `%changelog` (the `rpm`, `rhel`, and `opensuse` specs) requires
  a new dated entry for every version — the `Version:` field alone is not
  sufficient for `rpmbuild` to accept the spec.
- Historical version strings in `CHANGELOG.md`, `CHANGELOG-pre-release.md` and every spec
  `%changelog` are records, not live values; do not edit them when bumping.
- `CHANGELOG.md` starts at 1.0.0. The 0.x entries are in `CHANGELOG-pre-release.md`, a frozen record that
  nothing is added to ([ADR-0740](adr/0740-the-changelog-starts-at-1-0-0-and-the-pre-release-entries-are-a-frozen-record.md)).
- `tests/tooling/test_packages_workflow.py` enforces that every file in the table
  above carries the current `meson.build` version. Run it (or `python build.py
  wsl`) after a bump to catch any location that was missed.

## Release process

1. Update `main` from `origin`, then create a feature or fix branch from it.
2. Unless the changes are documentation-only, increment the build number in every location above and add its changelog section.
3. Make the changes and keep that version for intermediate commits.
4. Before raising the PR, check version consistency and conflicts with the base branch.
5. Raise a PR. CI builds the configured platform artifacts and runs the test suite;
   see [platform-support.md](platform-support.md) for the artifact matrix.
6. Merge to `main`. The `publish-latest` CI job replaces the rolling GitHub
   `latest` pre-release with the new artifacts automatically.
7. For a versioned release, push a `vX.Y.Z` tag naming the `meson.build`
   version. The `release` workflow (`release.yml`, tags matching `v*`) refuses
   any other tag, builds the packages and publishes the versioned GitHub
   release. A `0.x` tag is marked as a prerelease; from 1.0.0 a tag publishes a
   full release (ADR-0597); see [release-process.md](release-process.md).
