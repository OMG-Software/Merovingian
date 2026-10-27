# The password policy is configurable, strict by default

* Status: accepted
* Date: 2026-10-27

## Context and Problem Statement

`auth::password_is_acceptable` was a fixed rule: at least 12 bytes, with a
lower-case and an upper-case ASCII letter, an ASCII digit and an ASCII symbol.
The first Complement run against 0.12.57 failed 322 tests, nearly all before
reaching what they test. Complement registers its users with passwords such as
`complement_meets_min_password_req`, `password` and `secret`, and the server
refused every one. Complement's passwords are fixed in its tests.

The refusal also used the wrong error code. The spec ("Password management")
says "Servers MAY reject weak passwords with an error code `M_WEAK_PASSWORD`";
the server answered `400 M_UNKNOWN "password rejected"`.

How can Complement register users without weakening deployments?

## Decision Drivers

* A deployment's password rule must not change unless its operator says so.
* Complement must run against the shipped binary (ADR-0233), so no build flag.
* A weakening must be visible, like the other settings that loosen security
  (ADR-0231, ADR-0232).

## Considered Options

* Two settings, `security.password_policy.min_length` and
  `security.password_policy.require_character_classes`, defaulting to the
  existing rule.
* Removing the rule and leaving password strength to clients, as the spec
  allows ("Clients SHOULD enforce that the password provided is suitably
  complex").
* An acknowledgement flag that turns the rule off entirely.

## Decision Outcome

Chosen option: the two settings, because they keep every deployment exactly as
strict as before while letting an operator choose a different rule, not only
"on" or "off".

* `min_length` counts bytes, 1 to 1024 (default 12). An empty password never
  passes, and validation refuses 0 and anything a client could not reasonably
  meet. `require_character_classes` (default `true`) keeps the four ASCII
  classes.
* The rule applies to passwords a person chooses: registration, the bootstrap
  administrator and `POST /account/password`. Appservice users' generated
  credentials stay exempt, as before.
* A refusal is `400 M_WEAK_PASSWORD`, as the spec names it.
* A policy weaker than the default is logged at CRITICAL on every start, and
  both keys need a restart, so a hot reload cannot loosen it without that line.
* The Complement template sets `min_length=1` and
  `require_character_classes=false` (ADR-0233), and says why.

### Positive Consequences

* Complement can create its users, so a run measures the server rather than
  its password rule.
* An operator can raise the rule (a longer minimum) as well as lower it.

### Negative Consequences

* An operator can now weaken passwords on a public server. The CRITICAL line
  and the restart are the guard, as for the other loosening settings.

## Pros and Cons of the Options

### Removing the rule

* Good, because the spec leaves strength to clients.
* Bad, because every deployment that relied on the server refusing weak
  passwords would silently accept them after an upgrade.

### An acknowledgement flag that turns the rule off

* Good, because it is one key.
* Bad, because "off" is the only weaker choice; an operator wanting a longer or
  shorter minimum would get none.

## Links

* [ADR-0232](0232-open-registration-needs-an-explicit-acknowledgement-and-still-uses-uia.md)
* [ADR-0233](0233-complement-runs-the-shipped-trixie-package-in-an-image-that-drops-its-own-privileges.md)
* `docs/matrix-v1.19-spec/client-server-api.md`, "Password management"
