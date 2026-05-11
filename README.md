# The Merovingian

[![Build](https://github.com/James-Chapman/The-Merovingian/actions/workflows/ci.yml/badge.svg)](https://github.com/James-Chapman/The-Merovingian/actions/workflows/ci.yml)
[![Coverage](https://codecov.io/gh/James-Chapman/The-Merovingian/graph/badge.svg)](https://codecov.io/gh/James-Chapman/The-Merovingian)
[![CodeQL](https://github.com/James-Chapman/The-Merovingian/actions/workflows/codeql.yml/badge.svg)](https://github.com/James-Chapman/The-Merovingian/actions/workflows/codeql.yml)
[![Code scanning](https://img.shields.io/badge/code%20scanning-CodeQL-blue)](https://github.com/James-Chapman/The-Merovingian/security/code-scanning)
[![Static analysis](https://github.com/James-Chapman/The-Merovingian/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/James-Chapman/The-Merovingian/actions/workflows/static-analysis.yml)
[![Sanitizers](https://github.com/James-Chapman/The-Merovingian/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/James-Chapman/The-Merovingian/actions/workflows/sanitizers.yml)
[![FreeBSD](https://github.com/James-Chapman/The-Merovingian/actions/workflows/bsd.yml/badge.svg)](https://github.com/James-Chapman/The-Merovingian/actions/workflows/bsd.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![C++26](https://img.shields.io/badge/C%2B%2B-26-blue.svg)]()
[![Meson](https://img.shields.io/badge/build-Meson-blue.svg)]()

Security-first Matrix homeserver written in modern C++26.

## Goals

- encrypted-by-default room policy
- hardened federation
- secure-by-default deployment
- protocol correctness
- high scalability without bypassing checks
- auditable operation

## Engineering rules

- RAII everywhere
- references preferred over pointers
- no raw owning pointers
- no naked allocation
- no custom cryptography
- security before performance
- all tests use Given/When/Then structure

## Build

Set up a Linux or BSD development environment:

```bash
sh scripts/setup-dev-env.sh
```

Preview the setup commands without changing the host:

```bash
sh scripts/setup-dev-env.sh --dry-run
```

Build manually after dependencies are installed:

```bash
meson setup build
meson compile -C build
meson test -C build
```

## Run

Show usage:

```bash
./build/src/merovingian-server --help
```

Show version:

```bash
./build/src/merovingian-server --version
```

Use compiled secure defaults:

```bash
./build/src/merovingian-server
```

Use the checked-in Phase 1 starter config:

```bash
./build/src/merovingian-server --config config/merovingian.conf.example
```

Configuration is validated before startup continues. Parser or validation findings cause startup to fail closed.

## Configuration

See:

- `config/merovingian.conf.example`
- `docs/configuration.md`
- `docs/media-repository.md`

## Developer environment

See:

- `docs/dev-environment.md`

## Phase status

See:

- `docs/phase-1.md`

## Test standards

See:

- `docs/testing-standards.md`
- `security/coding-rules.md`

## Status

Early Phase 1 bootstrap implementation.
