# Merovingian

**Note: Merovingian is still in active development and is not ready for real-world use yet. Do not deploy it as a production Matrix homeserver.**

Merovingian is a Matrix homeserver written in modern C++26 with a security-first design. The project goal is not just to speak Matrix protocol, but to do it with a narrow attack surface, fail-closed behavior, strong operational visibility, and explicit security boundaries around federation, storage, media, and administration.

[![Build](https://github.com/OMG-Software/Merovingian/actions/workflows/ci.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/OMG-Software/Merovingian/graph/badge.svg)](https://codecov.io/gh/OMG-Software/Merovingian)
[![CodeQL](https://github.com/OMG-Software/Merovingian/actions/workflows/codeql.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/codeql.yml)
[![Code scanning](https://img.shields.io/badge/code%20scanning-CodeQL-blue)](https://github.com/OMG-Software/Merovingian/security/code-scanning)
[![Static analysis](https://github.com/OMG-Software/Merovingian/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/static-analysis.yml)
[![Sanitizers](https://github.com/OMG-Software/Merovingian/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/sanitizers.yml)
[![FreeBSD](https://github.com/OMG-Software/Merovingian/actions/workflows/bsd.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/bsd.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![C++26](https://img.shields.io/badge/C%2B%2B-26-blue.svg)]()
[![Meson](https://img.shields.io/badge/build-Meson-blue.svg)]()


## What Merovingian is

Merovingian is building toward a full Matrix homeserver that treats security as a primary product requirement rather than a later hardening pass. That means:

- secure defaults instead of convenience defaults
- explicit trust boundaries around client, federation, admin, and media paths
- fail-closed validation for configuration, input parsing, and remote traffic
- auditable runtime behavior with structured, redaction-aware diagnostics
- modern C++ RAII-heavy implementation with memory ownership kept narrow and explicit

## Secure by design

Merovingian is intentionally shaped around defensive engineering choices:

- reverse-proxy-first deployment model, with loopback listeners by default
- encrypted-by-default room policy and hardened federation behavior
- bounded parsers and prepared-statement-only persistence paths
- redaction-aware logs so secrets, tokens, and event content do not spill into diagnostics
- security review, static analysis, sanitizers, and packaging gates wired into CI

Open work items, capability gaps, and milestone blockers live in [docs/todos/](C:/dev/Merovingian/docs/todos/). See `priorities.md` for the ordered short list, `capability-gaps.md` for per-area gaps, and `beta-milestone.md` / `production-milestone.md` for milestone gates.

## Deploying And Running

If you want to evaluate or stand up Merovingian locally, start here:

- [docs/getting-started.md](C:/dev/Merovingian/docs/getting-started.md) for the end-to-end first run, admin bootstrap, and client connection flow
- [docs/configuration.md](C:/dev/Merovingian/docs/configuration.md) for listener, reverse-proxy, registration, federation, and runtime configuration details
- [config/merovingian.conf.example](C:/dev/Merovingian/config/merovingian.conf.example) for the annotated example config
- [docs/database-persistence.md](C:/dev/Merovingian/docs/database-persistence.md) for SQLite/PostgreSQL persistence behavior and schema notes

Merovingian is designed to sit behind a reverse proxy such as nginx, Apache httpd, or Caddy. The proxy should own public TLS, while Merovingian stays bound to loopback listeners behind it.

## Getting Started With Development

If you want to build or contribute to the project, start here:

- [docs/dev-environment.md](C:/dev/Merovingian/docs/dev-environment.md) for Linux, BSD, and WSL development setup
- [docs/testing-standards.md](C:/dev/Merovingian/docs/testing-standards.md) for the project’s Given/When/Then testing rules
- [security/coding-rules.md](C:/dev/Merovingian/security/coding-rules.md) for implementation constraints and secure coding expectations
- [docs/release-process.md](C:/dev/Merovingian/docs/release-process.md) for build, test, and release evidence expectations

Typical local setup starts with:

```sh
sh scripts/setup-dev-env.sh   # install toolchain and configure build dir
python build.py linux          # configure, compile, and test
```

`build.py` is the unified build entry point for all platforms. It delegates to
the shell scripts in `scripts/` and handles Meson setup, compilation, and
testing in one step. See [docs/dev-environment.md](C:/dev/Merovingian/docs/dev-environment.md)
for platform-specific targets (`linux`, `bsd`, `wsl`), packaging commands
(`deb`, `rpm`, `pkg`, `static`), and advanced options like build profiles and
dry-run mode.

Sanitizer builds are supported through the unified CLI on every development
target, including WSL. For example:

```sh
python build.py linux --builddir build-asan --buildtype debug --sanitize address,undefined
python build.py wsl --builddir build-tsan --buildtype debug --sanitize thread
```

## Project Status

Merovingian is beyond a toy prototype, but it is still an in-development homeserver with incomplete production gates. Federation, persistence, packaging, and security controls are actively being built out and corrected. The project should be treated as test-only until the blocking items in [docs/todos/production-milestone.md](C:/dev/Merovingian/docs/todos/production-milestone.md) are closed.
