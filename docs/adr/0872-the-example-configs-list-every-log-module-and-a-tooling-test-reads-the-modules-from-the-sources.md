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
call names no module) and finds calls and constants only outside string literals (logger-call text inside a string is
no call), then reads the first argument of the qualified `observability::log_diagnostic` and
`log_diagnostic_audit` calls and of `SingleLog` level calls, the second argument of the homeserver's
`log_diagnostic_audit(database, "module", ...)` overload, and resolves an identifier through a string constant defined
in the same file. Each example must list exactly that set as `# log_modules.<name>=` lines, each once. A hand-kept list
drifts like the examples did. A registry is the larger change: every logger call site and the config parser would move
to it, for a list that exists to be documented.

### Positive Consequences

* A new module fails the test, with its name, until both examples list it; a module nothing logs under any more fails
  until it is dropped.
* A first argument the scan cannot resolve fails the test instead of shrinking the expected set, and so does a call
  of a known form whose arguments it cannot read (`(kModule)`, `module_of(rt)`, `database_of(rt)`): each form has an
  opening pattern that finds every call of that form, and an opening the full pattern cannot read is reported with
  the call quoted.

### Negative Consequences

* The scan is text, not a C++ parser: it knows the call forms above, and a new form must be taught to it.
* A module constant shared from another file (a header) is not resolved and fails the test.
* Level calls are recognised by their receiver, so one through a receiver the rule does not name is missed rather than
  failed. Reading every `.info(...)` instead would take other types' methods for modules and demand example lines for
  modules that do not exist; the receiver rule is the price of not doing that.

## Rules for future code

* Name a logger call's module with a string literal, or with a string constant defined in the same file under a name
  given no other value there: the scan does not know scopes, so a name two functions each define with a different value
  is reported as ambiguous. The database audit overload's module argument follows the same rule. A parameter
  that only forwards a caller's module is named `logger`, `mod` or `module`, which the scan skips, but only when the
  file defines no string constant of that name (a constant always resolves first) and declares the name as a string
  parameter or gives it a value only by copying one (`auto const mod = std::string{logger};`), a parameter the file
  never gives another value (`logger = module_for(kind);` makes a copy of it reported). So the skip goes by
  role: a local holding a computed module (`module = module_for(kind)`), or a name the file never declares, is
  reported. `__func__` is skipped on its name alone:
  the legacy `LOG_*` macros log under the calling function's name, which is no module and is not listed in the
  examples. These four identifiers are the only first arguments the scan skips; say so wherever the test is described.
* Call a level method (`info`, `warning`, ...) directly only on `SingleLog::instance()` or on a reference named `log`
  or `logger`. The scan reads level calls on those receivers only, so a method of another type that happens to be named
  `warning` never becomes a module. A level call through any other receiver breaks this rule, and the scan does not
  see it.
* To share a module constant across files, or to log through a new call form, extend `source_log_modules` in the test
  in the same change. Never relax or delete the assertion to get past it.
* The examples list every module a structured logger call names, not a selection of common ones, and say that the
  legacy `LOG_*` macros' function names are left out. Do not trim the list.
* The homeserver's `log_diagnostic_audit(database, module, ...)` is recognised by its shape (an unqualified call that
  is not a declaration and does not open with a literal), never by what the database is called, so an alias such as
  `db` is read. Pass the database as a name, a member expression or `*pointer`; any other first argument (`(db)`,
  `database_of(rt)`) is reported, and so is the module argument of any call when it is neither a literal nor a name.
  Call a file-local wrapper with its event as a literal: one called with a variable event has the same shape and is
  reported as unresolved.

## Links

* See [ADR-0871](0871-turn-credential-requests-log-under-their-own-turn-module.md): the `turn` module it adds is one of
  the modules the examples must list.
