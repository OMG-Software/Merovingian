# Versioning

## Scheme

Merovingian uses **`0.MINOR.PATCH`** before `1.0`.

`PATCH` is the working counter: feature, fix, and packaging branches increment
it by one. Documentation-only changes do not require a version bump
([ADR-0464](adr/0464-documentation-only-changes-do-not-require-a-version-bump.md)).

`MINOR` is a **series marker, not a milestone.** It rolls over when a `PATCH`
series has grown long enough to be unwieldy, or at a natural grouping of work.
A new series does **not** restart at `.0`; it continues from wherever the
rollover happened. Both rollovers to date worked that way — `0.9.25` → `0.10.1`
and `0.10.63` → `0.11.4` — and no `0.10.0` or `0.11.0` was ever cut.

`1.0.0` is the one version number that carries a meaning: it is cut when the
project reaches **production**, as defined by
[`todos/production-milestone.md`](todos/production-milestone.md).

**Project phase is declared in `README.md` and `CHANGELOG.md`, never encoded in
the version number.** Beta was declared at `v0.10.59` — mid-series, which is
what the rules above imply. Do not read a phase transition into a `MINOR`
rollover, and do not hold a rollover back waiting for one.

The version is a plain string — there is no pre-release suffix, build metadata,
or epoch. All three numbers are always present (e.g. `0.11.4`, never `0.11`).

## Bump policy

**One bump per branch, when the branch is created, except for documentation-only changes.** Update `CHANGELOG.md`
and every version location below together before the branch's first commit.
Do not increment again on intermediate commits. Before raising the PR, verify
that the version remains consistent with the base branch; if another branch
has used that version in the meantime, update all locations together to the
next available patch version. There is no separate merge-time bump.

For a documentation-only branch, keep the current version and add the change
notes to its `Documentation` section in `CHANGELOG.md`. Changes to coding
guidance and `AGENTS.md` files are documentation changes. If the branch later
includes code, build, or packaging changes, apply the bump policy before
committing those changes.

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
| `CHANGELOG.md` | New `## X.Y.Z` section at the top |

### Notes

- The `.deb` `DEBIAN/control` version is generated at build time from the
  `VERSION` variable in `scripts/build-deb.sh` — it does not need a separate
  edit.
- The `packaging/deb/control` template has no version field; it is used only
  for `Depends` and other metadata, not the package version.
- The RPM-family `%changelog` (the `rpm`, `rhel`, and `opensuse` specs) requires
  a new dated entry for every version — the `Version:` field alone is not
  sufficient for `rpmbuild` to accept the spec.
- Historical version strings in `CHANGELOG.md` and every spec `%changelog` are
  records, not live values; do not edit them when bumping.
- `tests/tooling/test_packages_workflow.py` enforces that every file in the table
  above carries the current `meson.build` version. Run it (or `python build.py
  wsl`) after a bump to catch any location that was missed.

## Release process

1. Update `main` from `origin`, then create a feature or fix branch from it.
2. Unless the changes are documentation-only, increment the patch version in every location above and add its changelog section.
3. Make the changes and keep that version for intermediate commits.
4. Before raising the PR, check version consistency and conflicts with the base branch.
5. Raise a PR. CI builds the configured platform artifacts and runs the test suite;
   see [platform-support.md](platform-support.md) for the artifact matrix.
6. Merge to `main`. The `publish-latest` CI job replaces the rolling GitHub
   `latest` pre-release with the new artifacts automatically.
7. For a versioned release, push a `vX.Y.Z` tag naming the `meson.build`
   version. The `release` workflow (`release.yml`, tags matching `v*`) refuses
   any other tag, builds the packages and publishes the versioned GitHub
   release, marked as a prerelease while the version is `0.x` (ADR-0597); see
   [release-process.md](release-process.md).
