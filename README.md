# Merovingian

**Latest release: v0.10.59**

**Note: Merovingian is now in beta. It is suitable for evaluation and testing, but is not yet ready for production use. Do not deploy it as a production Matrix homeserver.**

[![Build](https://github.com/OMG-Software/Merovingian/actions/workflows/ci.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/ci.yml)
[![CodeQL](https://github.com/OMG-Software/Merovingian/actions/workflows/codeql.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/codeql.yml)
[![Static analysis](https://github.com/OMG-Software/Merovingian/actions/workflows/static-analysis.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/static-analysis.yml)
[![Sanitizers](https://github.com/OMG-Software/Merovingian/actions/workflows/sanitizers.yml/badge.svg)](https://github.com/OMG-Software/Merovingian/actions/workflows/sanitizers.yml)
[![Coverage](https://codecov.io/gh/OMG-Software/Merovingian/graph/badge.svg)](https://codecov.io/gh/OMG-Software/Merovingian)
[![Code scanning](https://img.shields.io/badge/code%20scanning-CodeQL-blue)](https://github.com/OMG-Software/Merovingian/security/code-scanning)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg)](LICENSE)
[![C++26](https://img.shields.io/badge/C%2B%2B-26-blue.svg)]()
[![Meson](https://img.shields.io/badge/build-Meson-blue.svg)]()

## Table of contents

- [What is Merovingian and what makes it special?](#what-is-merovingian-and-what-makes-it-special)
- [Release Artifact Verification](#release-artifact-verification)
- [Installation and Configuration](#installation-and-configuration)
- [Starting Merovingian for the first time](#starting-merovingian-for-the-first-time)
- [Upgrading Merovingian](#upgrading-merovingian)
- [Troubleshooting](#troubleshooting)
- [Getting Started With Development](#getting-started-with-development)

## What is Merovingian and what makes it special?

Merovingian is a Matrix homeserver written in modern C++26, built around a single premise: a homeserver sits at the center of every deployment's federation identity, access tokens, and message metadata — and, for any room that isn't end-to-end encrypted, the plaintext of every conversation in it. It never holds the private keys clients use to encrypt E2EE rooms, and it never sees their plaintext — that stays client-side, by design of the Matrix protocol. But a compromised server can still forge federation traffic under its identity, mint or steal access tokens to impersonate users, read and exfiltrate every unencrypted room, and tamper with — or selectively withhold — the ciphertext of rooms it cannot read. Merovingian treats resisting that compromise as the product requirement, not a hardening pass applied after the protocol works.

### Why choose Merovingian over other homeservers

Most homeservers are large, single-process applications where security is largely input validation and TLS. Merovingian goes further and applies operating-system-level containment and fail-closed engineering at every layer, so that compromising one part of the system doesn't hand an attacker the rest of it:

- **No memory-unsafe primitives, mechanically enforced.** Raw `new`/`delete`, `malloc`/`free`, and raw pointers are banned outright — a reject-unsafe gate refuses any change that reintroduces them. Every allocation is RAII-owned, and shared ownership requires a reviewed justification comment rather than being the default.
- **Untrusted work is isolated in sandboxed worker processes, not the main server.** Image decoding for thumbnails and all federation traffic handling run in separate processes under a `seccomp-bpf` syscall allowlist, `PR_SET_NO_NEW_PRIVS`, and tight resource limits — with `pledge`/`unveil` on OpenBSD and Capsicum `cap_enter` on FreeBSD locking down filesystem and syscall access before a single byte of remote or attacker-supplied input is parsed. A worker compromise does not expose the signing key, the database, or other users' data.
- **Fail-closed by default, not fail-open.** Startup runs a hardening self-check that refuses to serve traffic unless seccomp, ASLR/PIE, RELRO, stack canaries, and capability bounding all report enabled. Federation signature verification, TLS validation, and config validation reject outright rather than silently degrading when something is missing or malformed.
- **Secrets never sit as plaintext in ordinary memory.** The server's Ed25519 signing key is encrypted at rest under a master key and only ever held in `mlock()`'d, auto-zeroising buffers; secret comparisons run in constant time so timing side-channels can't leak them.
- **Cryptography is isolated and narrow.** A small, reviewed set of modules is permitted to touch the crypto library at all; passwords and tokens use Argon2id and keyed hashing, never bare unsalted digests.
- **Media can't become a foothold.** Uploads are content-sniffed independent of what the client claims they are, quarantined by default when remote or unverified, and — because encrypted-room attachments are ciphertext-only server-side — end-to-end encrypted media is architecturally opaque to the server, not merely policy-opaque.
- **Nothing sensitive leaks into logs.** Structured logging is redaction-aware by default: tokens, session identifiers, and event content are stripped before they ever reach disk, while security-relevant actions (logins, token invalidation, federation auth decisions, media quarantines) are recorded as durable, queryable audit rows instead of ordinary debug output.
- **Hardening is continuously verified, not just documented.** Every change runs through sanitizer builds, fuzzing, static analysis, and secret scanning in CI, alongside signed, reproducible release artifacts — the properties above are gated on every merge, not aspirational.

That combination — a narrow, memory-safe-by-construction attack surface, process-level containment of untrusted input, fail-closed defaults throughout, and continuously verified hardening — is what makes Merovingian a suitable home for genuinely sensitive Matrix communications, not just a spec-conformant one. For the full detail, see [docs/threat-model.md](docs/threat-model.md), [docs/hardening.md](docs/hardening.md), [docs/crypto-boundary.md](docs/crypto-boundary.md), and [docs/security-coding-rules.md](docs/security-coding-rules.md).

Merovingian has reached **beta** (v0.10.59). Federation, persistence, packaging, and runtime security controls are implemented and covered by CI. The project is suitable for evaluation and testing; it should not be treated as production-ready until the blocking items in [docs/todos/production-milestone.md](docs/todos/production-milestone.md) are closed.

Open work items, capability gaps, and milestone blockers live in [docs/todos/](docs/todos/). See `priorities.md` for the ordered short list, `capability-gaps.md` for per-area gaps, and `beta-milestone.md` / `production-milestone.md` for milestone gates.

## Release Artifact Verification

Every release artifact (tarball, package, and `SHA256SUMS`) is signed with a detached GPG `.asc` signature by the maintainer key. The public key fingerprint is:

```text
66DFCC50187C8E46B5ED85FD92A3A264F0A7BE20
```

Verify a downloaded artifact before installing:

```sh
gpg --keyserver keys.openpgp.org --recv-keys 66DFCC50187C8E46B5ED85FD92A3A264F0A7BE20
gpg --verify merovingian-0.10.59-linux-static-x86_64.tar.gz.asc \
             merovingian-0.10.59-linux-static-x86_64.tar.gz
sha256sum -c merovingian-0.10.59-linux-static-x86_64.tar.gz.sha256
```

Releases also carry SLSA provenance attestations (`gh attestation verify`), SPDX/CycloneDX SBOMs, and a machine-readable license summary. See [docs/release-process.md](docs/release-process.md) and [docs/user-manual.md](docs/user-manual.md) for full details.

## Installation and Configuration

Merovingian can be installed from a distro package, a portable static Linux tarball, or built from source. Full install steps (including the source build) live in [docs/user-manual.md § Installation](docs/user-manual.md#installation).

```sh
# Debian/Ubuntu example
sudo dpkg -i merovingian_0.10.59_amd64.deb

# Fedora/RHEL example
sudo rpm -i merovingian-0.10.59.x86_64.rpm
```

Merovingian is designed to sit behind a reverse proxy such as nginx, Apache httpd, Caddy, Traefik, or HAProxy. The proxy should own public TLS, while Merovingian stays bound to loopback listeners behind it. Worked examples for each proxy are in [docs/user-manual.md § Reverse proxy](docs/user-manual.md#reverse-proxy).

Configuration lives in a single `merovingian.conf` file, validated at startup with fail-closed semantics — an unsafe listener bind, a missing secret file, or open registration without a token will refuse to start rather than boot insecurely. Start from the annotated example:

```sh
install -m 0644 config/merovingian.conf.example /etc/merovingian/merovingian.conf
```

The full parameter reference (server identity, CORS, TURN, listeners, database, registration, secrets, token lifetimes, encryption policy, federation policy, media, trust & safety, logging, rate limits) is documented in [docs/user-manual.md § Configuration](docs/user-manual.md#configuration). Persistence backend behavior (SQLite for evaluation, PostgreSQL for production) is covered in [docs/database-persistence.md](docs/database-persistence.md).

## Starting Merovingian for the first time

1. **Create the service user** (distro packages do this automatically):
   ```sh
   groupadd -r merovingian
   useradd -r -g merovingian -d /var/lib/merovingian -s /sbin/nologin merovingian
   ```
2. **Copy and edit the example configuration**, setting at minimum `server.name`, `server.public_baseurl`, and `server.trusted_proxies`.
3. **Generate the master key**, which encrypts the Ed25519 signing secret at rest:
   ```sh
   openssl rand -out /etc/merovingian/master-key 32
   chmod 0600 /etc/merovingian/master-key
   ```
4. **Configure the database** — SQLite for a quick evaluation, PostgreSQL for anything else.
5. **Validate the configuration**:
   ```sh
   merovingian-server --check-config /etc/merovingian/merovingian.conf
   ```
6. **Start the server**:
   ```sh
   merovingian-server --config /etc/merovingian/merovingian.conf
   ```
   or, under systemd:
   ```sh
   systemctl enable --now merovingian.service
   ```
7. **Create the first admin account**:
   ```sh
   merovingian-server --config /etc/merovingian/merovingian.conf \
     --bootstrap-admin alice \
     --bootstrap-admin-password-file /tmp/admin-pw
   ```
8. **Smoke test**:
   ```sh
   curl -s http://127.0.0.1:8008/_matrix/client/v3/version
   ```
   Expect a JSON response listing supported Matrix client-server versions.

The full walkthrough, including CLI flags and systemd hardening details, is in [docs/user-manual.md § Initial setup](docs/user-manual.md#initial-setup) and [§ Running the server](docs/user-manual.md#running-the-server). Before opening a server to real users, work through the [security checklist](docs/user-manual.md#security-checklist).

## Upgrading Merovingian

1. Review [`CHANGELOG.md`](CHANGELOG.md) for the target version.
2. Stop the server.
3. Back up the database and master key.
4. Install the new package or tarball (see [Release Artifact Verification](#release-artifact-verification)).
5. Validate the config with `--check-config`.
6. Start the server.

Schema migrations are applied automatically on startup. See [docs/user-manual.md § Upgrades](docs/user-manual.md#upgrades) for details, and [docs/user-manual.md § Maintenance](docs/user-manual.md#maintenance) for backup guidance.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `duplicate configuration key` at startup | Two active `database.backend` lines or any other duplicate key. | Remove the duplicate. |
| `Config validation failure` (exit 79) | Unsafe listener bind, missing secret file, open registration without token, etc. | Read the specific message and adjust `merovingian.conf`. |
| Client shows "Failed to connect" | Proxy emits duplicate `Access-Control-Allow-Origin` headers, or `/.well-known/matrix/client` is missing/404. | Remove proxy CORS headers; serve the well-known discovery file. |
| `429 Too Many Requests` for all clients | `server.trusted_proxies` is unset behind a reverse proxy. | Set `server.trusted_proxies` and ensure the proxy overwrites `X-Forwarded-For` with the direct peer IP. |
| `502 send_join failed: timeout` | Large room join exceeds `security.federation.join_timeout` or the proxy's request timeout. | Raise `join_timeout` and `join_race_deadline`; ensure they fit inside the proxy timeout. |
| `502 send_join failed: response_too_large` | `send_join` response exceeds `security.federation.join_response_max_size`. | Raise the value and restart both main and worker processes. |
| Federation worker does not start | `merovingian-fed-worker` binary is missing or `federation.worker.binary` points to the wrong path. | Check binary location and permissions. |
| Encrypted media downloads fail | `application/octet-stream` was removed from `security.media.allowed_mime_types`. | Restore it. |

More detail and the full security checklist are in [docs/user-manual.md § Troubleshooting](docs/user-manual.md#troubleshooting).

## Getting Started With Development

If you want to build or contribute to the project, start here:

- [docs/dev-environment.md](docs/dev-environment.md) for Linux, BSD, and WSL development setup
- [docs/testing-standards.md](docs/testing-standards.md) for the project's Given/When/Then testing rules
- [docs/security-coding-rules.md](docs/security-coding-rules.md) for implementation constraints and secure coding expectations
- [docs/release-process.md](docs/release-process.md) for build, test, and release evidence expectations

Typical local setup starts with:

```sh
sh scripts/setup-dev-env.sh   # install toolchain and configure build dir
python build.py linux          # configure, compile, and test
```

`build.py` is the unified build entry point for all platforms. It delegates to
the shell scripts in `scripts/` and handles Meson setup, compilation, and
testing in one step. See [docs/dev-environment.md](docs/dev-environment.md)
for platform-specific targets (`linux`, `bsd`, `wsl`), packaging commands
(`deb`, `rpm`, `pkg`, `static`), and advanced options like build profiles and
dry-run mode.

Sanitizer builds are supported through the unified CLI on every development
target, including WSL. For example:

```sh
python build.py linux --builddir build-asan --buildtype debug --sanitize address,undefined
python build.py wsl --builddir build-tsan --buildtype debug --sanitize thread
```
