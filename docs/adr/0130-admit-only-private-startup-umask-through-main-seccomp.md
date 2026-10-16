# Admit only a private startup umask through main's inherited seccomp

* Status: accepted
* Date: 2026-10-11

## Context and Problem Statement

ISO-6 requires each executable to establish `umask(0077)` before initialization.
Both umask and seccomp survive exec: a supervised federation or thumbnail worker
enters its main function under main's seccomp profile before installing its own
stricter profile. Denying every umask in main killed newly spawned workers at
that first startup call; raw syscall tracing and the real startup test exposed it.

## Considered Options

* Admit exactly `umask(0077)` through main's profile, retaining denial in both
  worker profiles after their own hardening is installed.
* Admit arbitrary umask changes in every profile.
* Remove the worker startup call and assume every possible launcher is private.

## Decision Outcome

Chosen option: "Admit exactly `umask(0077)` through main's profile". Main's BPF
program validates the argument and restores the syscall-number accumulator for
subsequent comparisons. Existing executable startup calls remain unchanged.
Federation and decoder profiles continue to deny all umask changes after their
own sandbox installation. Forked kernel tests cover all three profiles and deny
zero, a group/other-readable mask, and other values, while checking that the
admitted call actually establishes the private mask.

### Positive Consequences

* Supervised workers start correctly without weakening their final filters.
* Direct executable launches still establish a private mask before services.
* A compromised main cannot use this grant to enable group/other access in newly
  created ordinary files.

### Negative Consequences

* Main can repeat the private-mask syscall after startup. Seccomp cannot grant
  it only to a future exec child; the mode restriction bounds that capability.
* `0077` need not be stricter for owner bits than every possible prior mask.
  The guarantee is absence of group/other creation permissions, not monotonically
  tightening all nine permission bits. Existing files are unaffected by umask.

## Pros and Cons of the Options

### Admit arbitrary changes

Rejected because changing the mask to zero would undo private-by-default creation
and neither hardened worker needs to change its mask at runtime.

### Remove worker startup calls

Rejected because workers can also be launched directly. An environment marker or
unchecked assumption about their launcher is not a file-creation security policy.

## Links

* [Runtime hardening](../hardening.md)
* [Restrict main's fchmod to owner-only database mode](0129-restrict-main-fchmod-to-owner-only-database-mode.md)
