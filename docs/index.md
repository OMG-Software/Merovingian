# Merovingian

<div class="hero" markdown>

<img class="merovingian-mark" src="assets/merovingian-logo.svg" alt="" width="96" height="96">

<p class="omg-eyebrow">OMG SOFTWARE / MEROVINGIAN</p>

## A security-first Matrix homeserver

Merovingian is a Matrix homeserver written in modern C++26. Its design treats containment, fail-closed validation, narrow trust boundaries, and continuous security verification as core requirements rather than post-hoc hardening.

[Read the user guide](user-manual.md){ .md-button .md-button--primary }
[View the architecture](architecture.md){ .md-button }
[Open the repository](https://github.com/OMG-Software/Merovingian){ .md-button }

</div>

!!! note "Production release"
    Merovingian 1.0.0 is the first production release. Its known limitations are listed in the 1.0.0 section of the [changelog](changelog.md). The [production milestone](todos/production-milestone.md) records the Complement blocker, which stays open for later releases.

## Why Merovingian

<div class="grid cards" markdown>

-   :material-shield-lock:{ .lg .middle } **Security-first boundaries**

    Federation handling, media decoding, secret storage, and configuration validation are designed around explicit trust boundaries and fail-closed behavior.

-   :material-cube-outline:{ .lg .middle } **Process isolation**

    Untrusted work is pushed into sandboxed worker processes with platform-specific confinement and resource limits.

-   :material-memory:{ .lg .middle } **Constrained C++ ownership**

    Raw allocation and ownership primitives are mechanically restricted, with RAII, smart pointers, sanitizers, fuzzing, and static analysis used continuously.

-   :material-lock-check:{ .lg .middle } **Narrow cryptographic surface**

    Cryptography is delegated to libsodium, signing material is encrypted at rest, and secret handling is explicitly bounded.

-   :material-source-branch-check:{ .lg .middle } **Continuous verification**

    CI covers builds, static analysis, sanitizers, fuzzing, CodeQL, SonarQube Cloud, reproducibility, SBOM generation, secret scanning, and package workflows.

-   :material-server-security:{ .lg .middle } **Operator-focused deployment**

    Merovingian is designed for reverse-proxy deployments, strict configuration validation, structured logging, and auditable security-sensitive operations.

</div>

## Start here

For operators, begin with the [User guide](user-manual.md). It covers installation, configuration, reverse proxies, database backends, first-run setup, upgrades, troubleshooting, and the security checklist.

For contributors, begin with the [Development environment](dev-environment.md), then review the [testing standards](testing-standards.md) and [security coding rules](security-coding-rules.md).

For design and security review, see the [architecture](architecture.md), [threat model](threat-model.md), [runtime hardening](hardening.md), [cryptographic boundary](crypto-boundary.md), and the [architecture decision records](adr/index.md) that explain why the code is shaped the way it is.

## Production status

The project has been in production since 1.0.0. Federation, persistence, packaging, and runtime security controls are implemented and covered by CI. 1.0.0 was tagged without a green Complement run.

See [Road to 1.0](todos/production-milestone.md) for the production milestone and the open Complement blocker, [capability gaps](todos/capability-gaps.md) for per-area status, and the [changelog](changelog.md) for what changed in each version.

This site is rebuilt from `main` on every merge, so it always describes the latest merged code. The version it was built from is shown in the footer.
