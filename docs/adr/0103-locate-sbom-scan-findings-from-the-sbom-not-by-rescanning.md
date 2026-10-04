# Locate SBOM scan findings from the SBOM, not by rescanning the checkout

* Status: accepted
* Date: 2026-10-04

Technical Story: dependency-triage run 37116890711, where one finding
(GHSA-xvg9-69gf-fjrf in mkdocs-material) made the SARIF upload fail

## Context and Problem Statement

`dependency-vulnerability-triage.yml` builds an SPDX SBOM of the repository
with `anchore/sbom-action`, scans that SBOM with Grype (`anchore/scan-action`),
and uploads the SARIF to GitHub code scanning. SPDX has no field for where in
the source tree a package was found, so Grype writes every SBOM-sourced result
with `physicalLocation.artifactLocation.uri: ""`. Code scanning rejects the
whole file when any result has an empty location ("locationFromSarifResult:
expected artifact location"). A clean scan uploaded fine; the first real
finding broke the upload, so no finding could ever reach code scanning. How do
the results get a location that code scanning accepts?

## Decision Drivers

* Every finding must reach code scanning; a single unlocated result must not
  hide all of them.
* The SBOM archived with the run must be the inventory that was scanned, so a
  reviewer can reproduce a finding from the artifact.
* The gate must not change: `only-fixed`, a `high` cutoff, and
  `fail-build: false`.

## Considered Options

* Scan the checkout (`path: .`) instead of the SBOM.
* Post-process the SARIF, filling each empty location with the manifest the
  SBOM links the package to, and the SBOM file when there is none.
* Switch the SBOM to syft's own JSON format, which keeps file locations.

## Decision Outcome

Chosen option: post-process the SARIF with
`scripts/fill_sarif_artifact_locations.py`. It is the only option that
guarantees no empty location reaches code scanning while still scanning the
archived SPDX SBOM.

syft records which manifest declared each package as an SPDX `OTHER`
relationship whose comment starts `evident-by:`. The script follows those
links from each result's rule `purls`. The primary location is the first
manifest in sorted order, so an alert keeps the same location from run to run;
any further manifests become `relatedLocations`. File names from the SBOM are
used only when they are plain repository-relative paths (no `..`, no leading
`/`, no backslash, no URL scheme); anything else, and any package with no
linked manifest, falls back to `dependency-triage.spdx.json`. That file is not
committed, so such an alert has no code snippet, but its location is not empty.
The raw Grype output is not modified. It is archived next to the
filled copy, which is the only file uploaded.

### Positive Consequences

* Alerts point at the manifest to edit (`requirements-docs.txt`, the workflow
  using a vulnerable action), not at an empty path.
* The scan input and the archived SBOM stay the same file.

### Negative Consequences

* The fix relies on syft's `evident-by` relationship. If syft stops writing it,
  findings still upload but are all located at the SBOM file. The tooling
  tests pin the relationship shape the script expects.
* The workflow gains a step and a script to maintain.

## Pros and Cons of the Options

### Scan the checkout (`path: .`)

* Good, because Grype then reports real file paths itself, with no extra step.
* Bad, because the scanned inventory is no longer the archived SBOM. Grype's
  embedded syft and the SBOM action's syft can differ in version and catalogers.
* Bad, because Grype's SARIF output falls back to the scan input path for a
  package with no location, and that path is empty for `.`, so the upload can
  still fail.

### Post-process the SARIF from the SBOM

* Good, because no result can reach code scanning without a location.
* Good, because it keeps scanning the archived SBOM.
* Bad, because it is another script, which needs tests.

### Switch the SBOM to syft JSON

* Good, because Grype would read package locations straight from the SBOM.
* Bad, because the archived inventory would no longer be a standard SPDX
  document, unlike `sbom.yml`'s release SBOMs.
* Bad, because a package without a location would still produce an empty URI.

## Links

* Related to [ADR-0101](0101-build-the-documentation-site-on-every-branch-but-publish-only-from-main.md),
  which added `requirements-docs.txt`, the manifest of the first finding
