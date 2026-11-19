# The packages set up an operator-installed LiveKit SFU under its own account

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

The built-in LiveKit token service (ADR-0828 to ADR-0833) needs a LiveKit SFU, and until now the operator had to work
out how to run one: which account, where the API secret goes, how the SFU's key file and this server's
`api_secret_file` stay the same secret, and which LiveKit settings matter to this server. How should Merovingian help an
operator run LiveKit beside it on one host, without making LiveKit part of what this project builds and ships?

## Decision Drivers

* LiveKit takes media from the internet and is code this project neither writes nor reviews. A flaw in it must not
  reach the homeserver's database, signing key, master key or secret files.
* The API secret can mint any LiveKit token. It must never appear on a command line, in output or in a log, and an
  existing secret file must never be replaced.
* The two sides read the secret in different formats: this server reads the secret alone from an owner-only file, and
  LiveKit reads a `key: secret` YAML map from a file it refuses if others can read it.
* This server creates every call's LiveKit room before issuing a token (ADR-0830), and calls LiveKit's room service
  over `http` only on loopback.

## Considered Options

* Ship the scaffolding (service unit, sample configuration, key setup helper, account) and let the operator install
  `livekit-server` from LiveKit
* Bundle a pinned `livekit-server` binary in the packages
* Build LiveKit from source as part of this project's build
* Run the SFU as the `merovingian` account
* Generate the secret in the package's post-install script
* Ship BSD rc.d scripts as well

## Decision Outcome

Chosen option: "Ship the scaffolding and let the operator install `livekit-server`":

* The `.deb` and `.rpm` packages create a `merovingian-livekit` system account.
* They install `merovingian-livekit.service` disabled, with its `ExecStart` at `/usr/local/bin/livekit-server`
  (LiveKit's own install location) and `--config /etc/merovingian/livekit.yaml`.
* They install `/usr/sbin/merovingian-livekit-setup` and `/etc/merovingian/livekit.yaml.example`.
* The release tarball also carries an OpenRC script with the same account and paths.

The operator runs the setup helper once by hand. It writes the same new 256-bit secret to two files:

* `/etc/merovingian/livekit-secret`, owner `merovingian`, `0400`;
* `/etc/merovingian/livekit-keys.yaml`, owner `merovingian-livekit`, `0400`.

The helper moves each file into place with `ln`, so neither ever replaces an existing file. It prints the settings but
never the secret, and run again it only checks that the two files agree.

The sample configuration binds LiveKit's signalling and room-service port to `127.0.0.1` and turns off
`room.auto_create`.

Rules for future changes:

* the SFU never runs as `merovingian`, and never gets a group that can read `merovingian`'s files;
* nothing in a package script generates, reads or prints the LiveKit secret;
* the unit, the OpenRC script, the sample configuration and the helper name the same account, paths and port, which
  `tests/tooling/test_livekit_companion.py` checks.

### Positive Consequences

* An operator gets a working, hardened single-host layout without this project taking on LiveKit's code, its release
  cadence or its security fixes.
* A compromised SFU can read only its own key file. It cannot read the homeserver's state.
* A token can join only a room this server created, even after LiveKit has closed an empty room.

### Negative Consequences

* The operator installs and updates `livekit-server`, and the packages trust whatever binary is at
  `/usr/local/bin/livekit-server`.
* The secret exists in two files, and changing it means removing both and running the helper again with both services
  stopped.
* BSD hosts get nothing, because LiveKit publishes no BSD builds. An operator there runs LiveKit on a Linux host and
  points `api_url` at it over `https`.

## Pros and Cons of the Options

### Bundle a pinned `livekit-server` binary

* Good, because one package installs everything.
* Bad, because this project would ship and answer for a third-party network service's binary, its licence and its
  security releases, and would have to republish whenever LiveKit fixes a flaw.

### Build LiveKit from source

* Bad, because it brings a Go toolchain and LiveKit's dependency tree into a C++ project's build, release evidence and
  SBOM, for code this project does not review.

### Run the SFU as `merovingian`

* Good, because one account and one secret file would do.
* Bad, because a flaw in the SFU would then read the database, signing key and master key: the isolation this decision
  exists for.

### Generate the secret in the post-install script

* Good, because it needs no step from the operator.
* Bad, because every install of the package, including servers that never run LiveKit, would hold a live LiveKit
  secret. A package script that writes secrets is also harder to keep from replacing or logging one on upgrade.

### Ship BSD rc.d scripts

* Bad, because there is no LiveKit binary for them to run. They can follow if LiveKit publishes BSD builds.

## Links

* Builds on [ADR-0829](0829-the-built-in-livekit-token-service-issues-tokens-only-to-users-this-server-finds-joined.md)
* Builds on [ADR-0830](0830-every-call-to-livekit-goes-to-the-configured-address-with-a-token-of-its-own.md)
* Builds on [ADR-0833](0833-the-livekit-webhook-is-served-on-the-client-listener-and-trusted-only-to-prompt-a-check.md)
