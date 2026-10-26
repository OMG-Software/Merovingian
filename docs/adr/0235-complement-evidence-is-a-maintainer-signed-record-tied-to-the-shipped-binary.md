# Complement evidence is a maintainer-signed record tied to the shipped binary

* Status: accepted
* Date: 2026-10-26

## Context and Problem Statement

The 1.0.0 blocker "Federation conformance is entirely self-attested" is done
when Complement runs green against a release candidate. The production
milestone already decided that Complement is maintainer-run and recorded at tag
time, not a per-PR gate. A claim that a release passed Complement is worth only
what a reader can check: which bytes were tested, against which Complement,
judged by which skip list, and by whom.

What does a Complement result attached to a release contain, and what makes it
release evidence rather than a run someone happened to make?

## Decision Drivers

* The record must tie the verdict to the binary users install, not to an image
  or a build that might differ.
* A reader must be able to verify it offline, as with the packages.
* A partial, unverified or red run must never pass for evidence, including by
  accident in a maintainer's shell history.

## Considered Options

* A results file and the raw log, recorded from the run's work directory,
  signed with the maintainer key and attached to the tag's release.
* Running Complement inside the release workflow and attaching its output.
* Release notes that state the result, with no attached record.

## Decision Outcome

Chosen option: the signed record attached by the maintainer.

* `scripts/record_complement_evidence.py` writes
  `complement-results-<version>.json` and `complement-<version>.jsonl`. It
  refuses to write anything unless:
  * the package is the one the run tested (its SHA-256);
  * the server binary it extracts from that package's `data.tar` is the one
    the run read out of the image (its SHA-256);
  * the skip-list snapshot is the one the run was judged by.
  The results carry the package, server and image digests, how the package
  was verified, the Complement commit, Go and Docker versions, the Landlock
  waiver, the skip list's text and digest, the summary, timestamps, and the
  log's digest. Evidence is never overwritten.
* `release_evidence` is true only for a package verified against the
  maintainer-signed `SHA256SUMS`, an unfiltered run, and a green verdict.
  Otherwise the file says false and lists why. A Landlock waiver does not
  disqualify a run, but it is on the record's face.
* `scripts/publish_complement_evidence.py` refuses results that are not
  evidence, a log that is not the recorded one, a tag for another version, an
  existing signature, or a tag with no release. It signs both files with the
  maintainer key in `tests/complement/run.toml`, checks the signatures verify
  to that key, and uploads the files and signatures with `gh release upload`
  (never `--clobber`).
* The release notes have a Complement section naming the files and how to
  verify them. They say that a release without the files has not been tested
  against Complement.

### Positive Consequences

* A reader can check, from the release alone, that the tested server is the
  shipped server, and can reproduce the run from the recorded commit and skip
  list.
* An unverified or partial run can be recorded for debugging without any risk
  of it being published as evidence.

### Negative Consequences

* Evidence depends on the maintainer doing the run and the upload. The release
  notes make a missing record visible but do not prevent the tag.
* A Docker or kernel difference between the maintainer's machine and a
  reader's can change a result. The Docker version is recorded, not the
  kernel.

## Pros and Cons of the Options

### Complement in the release workflow

* Good, because no step depends on the maintainer.
* Bad, because a full run takes hours on shared runners, a flaky
  infrastructure failure would block the tag, and the milestone already
  decided against a CI gate for it. The `complement-image` job keeps the image
  from rotting in the meantime.

### A statement in the release notes

* Good, because it costs nothing.
* Bad, because it is the self-attestation the blocker exists to remove.

## Links

* [ADR-0233](0233-complement-runs-the-shipped-trixie-package-in-an-image-that-drops-its-own-privileges.md)
* [ADR-0234](0234-a-complement-run-is-judged-by-a-summariser-over-a-checked-in-skip-list.md)
* `docs/release-process.md`, "Complement"
* `docs/todos/production-milestone.md`, "Release evidence, not CI gates"
