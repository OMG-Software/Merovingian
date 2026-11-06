# CodeQL drops path injection sourced only from command-line arguments

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-06

Technical Story: PR #563's CodeQL check failed on alerts open on `main`, 7 of them `cpp/path-injection` on paths from
`argv`

## Context and Problem Statement

CodeQL's `cpp/path-injection` treats every command-line argument as untrusted user input. Every path it reported on
`main` came from one: the configuration file `merovingian-server --config`, `--check-config` and `--plan-config-reload`
read, the `--log-file` sink, the files `open_secure_secret_file` opens, and the configuration the federation worker is
started with. These paths are the operator's to choose; whoever controls them already controls the process. The opens
are hardened where it matters (`O_NOFOLLOW`, ownership and mode checks for secrets and the log file), but the query has
no sanitizer that clears a string path, so no code change makes the alert go away. A path from any other source, such
as a request, would be a real finding. How should these alerts be cleared without losing that?

## Decision Drivers

* A path a remote peer or client can influence must still be reported.
* Suppression stays in reviewed, tested repository code (ADR-0226), not in alert state on GitHub.
* The process's own arguments are trusted input in this project's threat model: no binary is setuid, and the worker's
  arguments are chosen by the main process.

## Considered Options

* Drop a `cpp/path-injection` result in the SARIF filter only when every source it names is a command-line argument
* Dismiss the alerts on GitHub as "won't fix"
* Drop `cpp/path-injection` under `src/` and `include/`
* Leave them open

## Decision Outcome

Chosen option: "Drop a result only when every source it names is a command-line argument". CodeQL names each source in
the result message as a link, `[user input (<kind>)](<id>)`, to the related location with that id, and puts every source
that reaches one sink in the one result. `sources_are_command_line_arguments` in `scripts/filter_codeql_sarif.py`
drops the result only when the message links at least one source, every link is labelled
`user input (a command-line argument)` and resolves to a related location labelled the same, and no related location
carries any other label. A result that also has a network, file or environment source is kept, and so is anything the
filter cannot read. If a CodeQL release words the label differently, the results come back as alerts rather than
disappearing.

Rules this sets for future work:

* Only `cpp/path-injection` is filtered by source. Do not extend the source test to another rule without an ADR of its
  own: for most rules a command-line source is still worth reporting.
* A path from the command line is trusted as a choice, not as a safe file: code that opens a secret or a file it writes
  keeps checking what it opened (`O_NOFOLLOW`, `fstat` ownership and mode), as `open_secure_secret_file` and
  `LogFileSink::open` do.

### Positive Consequences

* The seven alerts close as fixed at the next analysis of `main`, with the reason in the repository.
* A path that reaches a file function from anywhere but `argv` is still an alert.

### Negative Consequences

* A path from the command line that reaches a file function by mistake, for instance an argument meant as a name used
  as a path, is no longer reported.

## Pros and Cons of the Options

### Dismiss the alerts on GitHub as "won't fix"

* Good, because nothing in CI changes.
* Bad, because moving the code can raise an alert again, and the reasoning lives only in alert state.

### Drop `cpp/path-injection` under `src/` and `include/`

* Good, because it fits ADR-0226's rule-and-directory table.
* Bad, because it would also hide a path that comes from a request, the case the rule exists for.

### Leave them open

* Good, because nothing is hidden.
* Bad, because there is nothing to fix, and every large pull request fails CodeQL on them.

## Links

* Refines [ADR-0226](0226-codeql-drops-unused-static-function-on-catch2-tests-before-upload.md)
* [scripts/AGENTS.md](../../scripts/AGENTS.md) — the filter script
