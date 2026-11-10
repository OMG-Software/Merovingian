# A unit test never builds a homeserver runtime

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-10

Technical Story: issue 552 follow-up; unit test files that start a runtime and call service functions directly

## Context and Problem Statement

`tests/unit/AGENTS.md` says unit tests isolate a single module and that anything needing a database or HTTP belongs in
`tests/integration/`. Issue 552 moved every unit scenario that drove the client-server stack through
`handle_client_server_request` to integration. It left out 38 unit files (402 scenarios) that build a runtime with
`start_runtime`, `start_client_server` or `wire_federation_callbacks` and then call service functions, the local router
or the federation handlers directly.

Those files do not isolate one module. `start_runtime` validates the config, opens the persistent store, writes and
reads a master-key file to create the server signing key, derives token keys and wires appservices, push and
federation. A scenario that calls `ban_user` on the result exercises `homeserver`, `config`, `database`, `crypto`,
`auth`, `canonicaljson`, `events`, `federation` and `rooms`. Ten of the files also opened an on-disk SQLite store for
behaviour that is not about the database. The rule had drifted because "request-level" was a judgement made per file.
Should these tests move too, or should the rule be changed so that a service-level test over an in-memory runtime
counts as a unit test?

## Considered Options

* Move them to `tests/integration/` and make the rule one a script can check
* Record that a service-level test over an in-memory runtime (`DatabaseBackend::memory`) is a unit test, and move only
  the files that dispatch requests, open an on-disk store or use sockets

## Decision Outcome

Chosen option: "Move them to `tests/integration/`", by the owner's decision. It continues issue 552's decision to keep
the rule and move the tests, and it turns the rule into a test of what a file names rather than a judgement.

* A file under `tests/unit/` never names `start_runtime`, `start_client_server`, `wire_federation_callbacks`,
  `handle_client_server_request`, `handle_client_server_http_request` or `run_client_server_flow`, in code or comments.
  `scripts/check-unit-test-isolation.sh` enforces it as the `unit-test-isolation` meson test, which runs in every
  platform's suite. An empty `tests/unit/` or a failed `grep` fails the check rather than passing it.
* A scenario that reaches one of those functions, directly or through a helper in its file, lives in
  `tests/integration/test_<name>_flow.cpp`. A file that also holds single-module scenarios is split, and those stay in
  unit. Where the `_flow.cpp` name was already taken, by issue 552's half of the same original file, the scenarios were
  appended to it.
* `tests/unit/test_federation_runtime_callbacks.cpp` moved whole, although most of its scenarios set the federation
  callbacks on a bare `HomeserverRuntime{}` by hand: they drive `handle_federation_http_request`, which is request
  dispatch.
* A bare `HomeserverRuntime{}` without one of those calls is still allowed in unit, for example the client outbound
  proxy policy and the sliding sync builders. That pattern was outside this decision's scope, and the check does not
  name the type.

The time cost was measured before the decision: the moved scenarios ran 42 s in a direct run of the unit binary on WSL,
against 58 s for the scenarios issue 552 added to integration in the same harness. In CI the integration limit is
1800 s on every platform (ADR-0509; the BSDs' 900 s is doubled by `scripts/build-bsd.sh`). OpenBSD, the slowest, took
693 s before issue 552, so both moves together are estimated at about 790 s.

The alternative was rejected although it looks better in isolation: it moves fewer files and keeps fast feedback for
service work in the unit binary. But the files that dispatch requests or open an on-disk store had to move under either
option, and its boundary needs two judgements (which store, which entry point) where the chosen rule needs a grep.

### Positive Consequences

* The unit binary holds single-module tests only, and a new runtime-building unit test fails CI with the file and line.
* About 18% of the unit binary's time moves with the tests.

### Negative Consequences

* Work on `room_service`, `auth_service` and the federation handlers runs its tests in the integration binary. Filter
  by tag (`merovingian-integration-tests "[homeserver][rooms]"`), since the whole suite takes about ten minutes.
* The integration suite grows by about 0.7 times what issue 552 added to it, and the sanitizer jobs grow with it.
* A support header under `tests/support/` that calls the stack is not checked; only the files under `tests/unit/` are.
