# The test binaries hash passwords at minimum cost

* Status: accepted
* Date: 2026-11-05

## Context and Problem Statement

Nearly every scenario registers and logs in users, and each of those is a real Argon2id hash or verification at libsodium's
interactive cost, about 27 ms and 64 MiB. A count on one quiet machine found 15,800 such calls across the three large test
binaries: 113 s of the unit binary's 244 s, 252 s of the conformance binary's 300 s, and 121 s of the integration binary's
720 s. In a homeserver whose first priority is security, how can the tests stop paying for that without making the password
code weaker, or easier to weaken?

## Decision Drivers

* The shipped server must not be able to reach a cheaper hash, by configuration, build option or accident.
* A change that lowers the production cost must fail the tests, not be hidden by them.
* Scenarios must keep checking real passwords against real hashes.

## Considered Options

* A runtime or configuration setting for the hash cost.
* A build option that selects a cheaper cost in the production library.
* A seam in `src/auth/password.cpp` that a test can replace.
* Defining `crypto_pwhash_str` in the test binaries.
* `LD_PRELOAD`.
* `-Wl,--wrap=crypto_pwhash_str` on the three test binaries.

## Decision Outcome

Chosen: `--wrap`, with the definition in `tests/support/password_hash_cost.cpp`. The linker sends the production code's call
there in those three executables, and no production source or library changes.

The override first refuses any cost but `crypto_pwhash_OPSLIMIT_INTERACTIVE` and `crypto_pwhash_MEMLIMIT_INTERACTIVE`, then
hashes with `crypto_pwhash_argon2id_str` at the minimum. The refusal is what makes this safe: lowering the cost in
`password.cpp` fails every scenario that registers or logs in, rather than being overridden unnoticed.

`crypto_pwhash_str_verify` is not replaced. It takes the cost from the stored string, so verifying gets cheap by itself, and a
fixture's stored hash still verifies at whatever cost it was made with.

`merovingian-password-cost-tests` is linked without the override and pins the production cost, including the case the
override cannot see: production calling a different libsodium function.

`RealPasswordHashCost` restores the real hash for a scenario that needs it. A scenario that races another request against the
window in which `runtime.mutex` is released around Argon2id cannot use the minimum: a window of microseconds is too short for
the other thread to land in, so it fails intermittently or stops exercising the race. It holds the guard from its first line,
because verifying costs whatever the stored hash was made with.

Rejected:

* **A runtime or configuration setting.** An operator, or an attacker who can write the config file, could then lower the
  cost of every password on a real server. The setting exists only for tests and would ship to everyone.
* **A build option on the production library.** The binary would be correct only if the right option was passed, and a
  packaging mistake would ship weak hashes and pass every test.
* **A seam in `password.cpp`.** Production code would carry a way to replace its own hash, for the sake of tests.
* **Defining `crypto_pwhash_str` in the test binaries.** It works against a shared libsodium, but a static one defines that
  function in the same object as `crypto_pwhash_str_verify`, so the link fails with a duplicate symbol. `--wrap` works with
  both, gives the real function a name (`__real_crypto_pwhash_str`) for the guard to call, and needs no default visibility,
  because the auth library is static and resolved in the same link.
* **`LD_PRELOAD`.** It depends on the environment each binary is started in, so a run outside Meson silently pays full price,
  and it has no way to reach a static libsodium.

## Consequences

* A new test binary that registers users needs the same link argument and support file, unless it exists to see the real
  cost. `tests/tooling/test_password_hash_override.py` keeps the override to these three binaries.
* The live and load test binaries, `merovingian-server` and anything a package ships keep the real hash. A scenario that
  spawns the real server pays the real cost in that process.
