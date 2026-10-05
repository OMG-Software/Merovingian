# Default unrecorded directory publication to private

* Status: accepted
* Date: 2026-10-04

## Context and Problem Statement

Publication in the public room directory is independent of whether a room has public join rules. Before schema 18 publication intent existed only in memory and is lost at restart.

## Considered Options

* Persist publication as rooms.directory_public with a false default. Upgrade preserves existing rooms and leaves them unpublished until an authorized user publishes them. Commit a visibility update before changing either in-memory projection.
* Infer publication from join rules; publish all pre-upgrade rooms.

## Decision Outcome

Persist publication as rooms.directory_public with a false default. Upgrade preserves existing rooms and leaves them unpublished until an authorized user publishes them. Commit a visibility update before changing either in-memory projection.

### Consequences

Administrators must republish rooms whose historical intent was not stored. Inferring visibility would disclose rooms that were deliberately unlisted.
