# The password-hashing concurrency cap is configurable

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-28

Technical Story: Complement `TestLogin` and `TestRegistration`, whose parallel subtests were
answered `429 too many concurrent authentication attempts`. Refines
[ADR-0090](0090-bound-argon2id-work-with-admission.md).

## Context and Problem Statement

ADR-0090 bounds Argon2id work with a counting semaphore that sheds load with 429 instead of
queueing it. Its capacity was fixed at four in code. Each hash uses libsodium's interactive limits
(64 MiB), so four bounds hashing at 256 MiB, which suits a small deployment but not a larger one, nor
a test harness that logs in from many tests at once. The spec allows a 429 here (`/login` and
`/register` are rate-limited), so this is a capacity question, not a conformance one.

## Decision Drivers

* The operator knows the memory and CPU available; the code does not.
* The bound must stay: unbounded memory-hard hashing is what ADR-0090 prevents.
* The owner decided (2026-10-28): a config key whose default stays four.

## Considered Options

* `security.password_hashing.max_concurrent`, default 4, 1 to 128, taken at start-up.
* Derive the cap from the machine (cores or memory).
* Keep the fixed four, and skip-list the Complement subtests.

## Decision Outcome

Chosen option: the config key. 128 is the semaphore's compile-time maximum
(`auth::argon2id_admission_max_capacity`, tied to `config::max_password_hashing_concurrency` by a
`static_assert`); zero and anything above it are startup findings. A change needs a restart, since
the semaphore is built before any request runs. The Complement template sets 32.

Deriving the cap from the machine ignores memory limits a container imposes and other load on the
host, and would change behaviour between machines without the operator saying so. Skip-listing
leaves a deployment with more capacity than four no way to use it.

### Positive Consequences

* A deployment sizes hashing to its memory.
* The default, and so ADR-0090's bound, is unchanged.

### Negative Consequences

* An operator who raises it without the memory to match can run the process out of memory under a
  login flood: 128 concurrent hashes is 8 GiB.
