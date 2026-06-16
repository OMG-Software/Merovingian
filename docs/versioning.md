# Versioning

## Scheme

Merovingian uses **`0.MINOR.PATCH`** before `1.0`.

The `MINOR` digit is a **phase marker**, not a per-change counter:

- `0.8.PATCH` — current pre-beta phase. **All** changes (features, fixes,
  packaging) bump only `PATCH` while in this phase.
- `0.9.0` — cut when the project reaches **beta**.
- `1.0.0` — cut when the project reaches **production**.

So within the 0.8 phase a branch increments `PATCH` (e.g. `0.8.9` → `0.8.10`)
regardless of whether it adds behaviour; do not advance `MINOR` for a feature.
`MINOR` only moves at the beta and production milestones.

The version is a plain string — there is no pre-release suffix, build metadata,
or epoch. All three numbers are always present (e.g. `0.2.6`, never `0.2`).

## Bump policy

**One bump per branch, at merge time.** Do not increment the version on every
intermediate commit within a feature or fix branch. Record the intended new
version in `CHANGELOG.md` when the branch is created, then update all other
locations in a single commit immediately before (or as part of) raising the PR.

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

1. Create a branch: `feature/…` or `fix/…` from `main`.
2. Make the code changes.
3. Add a `## X.Y.Z` section to `CHANGELOG.md` describing what changed.
4. Update every location in the table above in a single commit.
5. Raise a PR. CI builds all three packages and runs the test suite.
6. Merge to `main`. The `publish-latest` CI job replaces the rolling GitHub
   `latest` pre-release with the new artifacts automatically.
7. For tagged alpha releases, push a `vX.Y.Z` tag — a separate CI workflow
   creates the versioned GitHub release.
