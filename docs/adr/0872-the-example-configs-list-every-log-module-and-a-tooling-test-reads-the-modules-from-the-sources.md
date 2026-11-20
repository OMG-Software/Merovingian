# The example configs list every log module, and a tooling test reads the modules from the sources

* Status: accepted
* Date: 2026-11-20

## Context and Problem Statement

`log_modules.<name>` accepts any name: the bootstrap passes it to `SingleLog::set_module_log_level` without a registry.
The example configurations (`config/merovingian.conf.example` and its BSD edition) are where an operator learns which
names exist, and their list drifted: twelve modules the server logs under were missing and one, `token`, was logged under
by nothing. How do the examples stay complete without someone remembering to edit them?

## Decision Drivers

* A module added to or removed from the sources must fail a test until both examples agree.
* The check must not need a list kept by hand, which would only move the drift into the test.
* It must not miss a module silently when a logger call takes a form the check does not know.

## Considered Options

* A hand-kept list of modules in the test, compared with the examples.
* A tooling test that reads the module names from the logger calls in `src/` and `include/`.
* A module registry in C++ that the logger, the config parser and a test all read.

## Decision Outcome

Chosen option: "a tooling test that reads the module names from the sources",
`ExampleLogModuleListTests` in `tests/tooling/test_example_config.py`. It blanks C++ comments (a comment that quotes a
call names no module), then reads the first argument of the qualified `observability::log_diagnostic` and
`log_diagnostic_audit` calls and of `SingleLog` level calls, the second argument of the homeserver's
`log_diagnostic_audit(database, "module", ...)` overload, and resolves an identifier through a string constant defined
in the same file. Each example must list exactly that set as `# log_modules.<name>=` lines, each once. A hand-kept list
drifts like the examples did. A registry is the larger change: every logger call site and the config parser would move
to it, for a list that exists to be documented.

### Positive Consequences

* A new module fails the test, with its name, until both examples list it; a module nothing logs under any more fails
  until it is dropped.
* A first argument the scan cannot resolve fails the test instead of shrinking the expected set.

### Negative Consequences

* The scan is text, not a C++ parser: it knows the call forms above, and a new form must be taught to it.
* A module constant shared from another file (a header) is not resolved and fails the test.

## Rules for future code

* Name a logger call's module with a string literal, or with a string constant defined in the same file. A parameter
  that only forwards a caller's module is named `logger`, `mod` or `module` (or is `__func__`), which the scan skips.
* To share a module constant across files, or to log through a new call form, extend `source_log_modules` in the test
  in the same change. Never relax or delete the assertion to get past it.
* The examples list every module the server logs under, not a selection of common ones. Do not trim the list.

## Links

* Refines [ADR-0871](0871-turn-credential-requests-log-under-their-own-turn-module.md)
