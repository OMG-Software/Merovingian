# Complement runs the shipped trixie package, in an image that drops its own privileges

* Status: accepted
* Date: 2026-10-26

## Context and Problem Statement

Complement is the external check behind the last 1.0.0 blocker ("Federation
conformance is entirely self-attested"). It starts each homeserver from a Docker
image it is given (`COMPLEMENT_BASE_IMAGE`). It sets `SERVER_NAME`, mounts a CA
at `/complement/ca`, expects plain HTTP on 8008 and TLS federation on 8448, and
waits for the container's `HEALTHCHECK`. It starts containers itself, so it
passes none of the flags this project's deployment image relies on
(`--cap-drop=ALL`, `--security-opt=no-new-privileges`). It also snapshots
containers and starts them again.

What does the image under `tests/complement/` run, and how does it meet that
contract without changing what is being tested?

## Decision Drivers

* The result is release evidence only if it tests the bytes a release ships.
* The server's startup self-check must pass as it does in production: no
  waived control unless the run says so in its evidence.
* Nothing in the image may become a way to weaken a deployment.

## Considered Options

* Install the release's Debian trixie package, checked against a SHA-256 given
  at build time. Start as root, prepare the container, and hand over to the
  server through `setpriv`.
* Build from source inside the image, as the root `Dockerfile` does.
* Base the image on the root `Dockerfile`'s image, which runs as
  `merovingian`.

## Decision Outcome

Chosen option: install the package, because it is the only option where the
binary Complement exercises is the one users install.

* **The artifact.** The image installs the Debian trixie `.deb`, built in a
  `debian:trixie` container by `packages.yml`. It uses the same pinned
  `debian:trixie-slim` digest as the shipped image. The Linux release tarball
  is built on Ubuntu and carries neither worker, so it is not used. The build
  requires `MEROVINGIAN_DEB_SHA256` and refuses a package with any other digest.
  The image does not verify the GPG signature: whoever has the maintainer key
  (the run script) verifies the signed `SHA256SUMS` and passes the digest in.
  The image checks only that it got the bytes it was told to expect.
* **Privileges.** The image has no `USER`. The entrypoint starts as root
  because only root can empty the capability bounding set. It ends with
  `exec setpriv --reuid=merovingian ... --bounding-set=-all --no-new-privs`, so
  the server is PID 1, unprivileged, with nothing to regain.
* **The client API.** A cleartext listener must stay on loopback, a server-side
  rule that is not relaxed for tests. nginx in the container puts
  `127.0.0.1:8080` on 8008. It forwards the request target unchanged and
  replaces `X-Forwarded-For`, and the server trusts only `127.0.0.1`.
* **TLS.** The federation certificate is minted from Complement's CA at every
  start (P-256, one day, SAN from `SERVER_NAME`), and the CA is added to the
  system trust store the server reads.
* **State.** The master key and SQLite database live in the container layer,
  not a volume, so Complement's snapshots carry them and the signing key that
  other servers cached survives a restart. The state records its server name.
  The entrypoint refuses to serve it under another name, or to adopt a master
  key with no recorded name. Root writes the state, the secrets and the config
  on every start, so those directories are root-owned. Only the database
  directory belongs to `merovingian`, so a compromised server cannot plant a
  link for root to follow on the next start.
* **Configuration.** `merovingian.conf.template` keeps the server's defaults
  except for what the contract forces: open registration (ADR-0232), the
  RFC 1918 networks (ADR-0231), listeners and paths. It also changes operator
  policy that the spec does not ask for, but only as far as the server allows:
  * The server refuses a config that stops encrypting new rooms by default or
    stops requiring encryption in direct messages, so Complement meets both
    as shipped. Any test they fail is a finding for the skip list's owner, not
    something the image hides.
  * The parts of the encryption policy an operator may change are off:
    unencrypted private rooms may be created and federated.
  * Every rate limit, including the built-in per-user ones, is raised out of
    reach, and the login throttle is set to its largest counts over its
    shortest window, because every Complement client arrives from one address.
  The tooling test fails if a rate limit the server applies is not raised, and
  the real server's `--check-config` must accept the rendered config.
* **Input.** `SERVER_NAME` is written into the config and the certificate, so
  it is checked against the spec's server-name grammar before anything is
  written, and refused, never cleaned.
* **Landlock.** It stays required. Only
  `MEROVINGIAN_COMPLEMENT_ALLOW_WITHOUT_LANDLOCK=true` waives it for the
  federation worker, so a run that waives it is visible in its evidence.

### Positive Consequences

* A green Complement run is evidence about the released package.
* The `complement-image` job in `packages.yml` boots the image the way
  Complement does on every branch run, without Go or Complement. It checks
  health, the `m.login.dummy` challenge, federation over TLS through the
  worker, an empty bounding set, and a signing key that survives a restart.

### Negative Consequences

* nginx runs beside the server as root (its workers as `www-data`), with the
  container's default capabilities. It is test plumbing and never part of a
  deployment.
* A failure that only the optional encryption policy or rate limits would
  cause is not measured by Complement. Those have their own unit and
  conformance tests.
* Tests that assume a new room or direct message is unencrypted may fail
  against the shipped defaults. The first full run will show how many.

## Pros and Cons of the Options

### Build from source inside the image

* Good, because a developer can run Complement on any commit without a package.
* Bad, because the binary is the image's own build, not the release's, so a
  packaging defect (a missing worker, a wrong path, a dropped flag) passes.

### Base the image on the root `Dockerfile`'s image

* Good, because it reuses the deployment image.
* Bad, because it builds from source too, and it starts as `merovingian`, which
  cannot drop the bounding set when Complement does not pass `--cap-drop=ALL`.
  The self-check would refuse to start.

## Links

* [ADR-0231](0231-federation-may-reach-operator-named-private-networks-and-nothing-else.md)
* [ADR-0232](0232-open-registration-needs-an-explicit-acknowledgement-and-still-uses-uia.md)
* [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md) — Landlock for the federation worker
* `tests/complement/AGENTS.md`
