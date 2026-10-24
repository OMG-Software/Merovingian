# SMTP goes through libcurl, with TLS required except to a loopback literal

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-24

Technical Story: email pusher delivery (0.12.44)

## Context and Problem Statement

Email pushers (ADR-0219) need an SMTP client. It sends an address this server vouches for, and
possibly SMTP AUTH credentials, to a relay the operator names. How the session is protected, where
the password lives, and which process may send are choices a later change could loosen without
noticing what they protect.

## Decision Drivers

* No new protocol parser written here if a pinned, maintained one exists.
* An address and credentials must not cross a network in cleartext.
* Secrets stay in owner-only files, held in memory only while used (as every other secret file).
* The federation worker, the process most exposed to hostile input, holds no secret it does not
  need (ADR-0062).

## Considered Options

* libcurl's SMTP support (already pinned and used for HTTP), or a hand-written SMTP client.
* For TLS: require it always; require it except to a loopback IP literal; or try STARTTLS and fall
  back to cleartext.
* For the password: inline in the config file; or in a secret file read at startup and kept; or
  read from that file for each email.

## Decision Outcome

Chosen:

* **libcurl.** `email::send_smtp_message` drives one SMTP session per email. Peer and host name
  verification are on and the TLS floor is 1.2. It uses no proxy and no connection reuse, and
  `CURLOPT_PROTOCOLS_STR` is restricted to the configured scheme. Startup refuses a configured
  relay whose scheme the linked libcurl cannot speak, so email pushers are never accepted and
  then never delivered.
* **TLS is required except to a loopback IP literal.** `smtps://` is TLS from the first byte.
  `smtp://` demands STARTTLS (`CURLUSESSL_ALL`) before any envelope is sent, and a relay that
  does not offer it gets no mail. Cleartext needs `server.email.require_tls=false`, and config
  validation allows that only for a `127.0.0.0/8` or `[::1]` literal (a local MTA) and never with
  credentials. A host name such as `localhost` does not qualify, because DNS decides where a name
  goes. The client refuses both cases again itself.
* **The password is read from `server.email.password_file` for each email.** The file must pass the
  owner-only secret-file check at startup. It is read into a `core::SecretBuffer` only for the
  send, so a rotated password takes effect without a restart. libcurl keeps its own copy for the
  life of the handle, which is destroyed when the send ends.
* **Only the main process sends.** The federation worker clears `server.email` in its own config
  copy before starting its runtime, as it clears the master-key path. The password file is also
  one of `worker_landlock_secret_paths`, so the worker refuses to start if a Landlock rule (such as
  the SQLite directory grant) would let it read the file. The email job thread runs
  only in main, starts after process hardening (ADR-0082), and never holds `runtime.mutex` across
  the SMTP session.

### Positive Consequences

* The SMTP state machine, STARTTLS and SASL are libcurl's, with no new dependency.
* An address or password never crosses a network in cleartext.

### Negative Consequences

* A relay with a private CA is not supported yet: the system trust store is used (there is no
  `server.email` CA setting).
* libcurl does not wipe its copy of the password when it frees it.

## Pros and Cons of the Options

### A hand-written SMTP client

* Good, because it has no libcurl protocol surface.
* Bad, because STARTTLS, SASL and dot-stuffing are easy to get subtly wrong. libcurl is already
  pinned and audited for this project.

### Opportunistic STARTTLS with cleartext fallback

* Good, because it works with more relays.
* Bad, because an attacker on the path can strip STARTTLS and read the envelope and credentials.

### Password inline in the config file

* Good, because it is simpler to configure.
* Bad, because config files are not held to the secret-file rules and are copied to the
  federation worker.

## Links

* Policy this transport serves: [ADR-0219](0219-email-pushers-mail-only-the-accounts-own-addresses-an-unread-count-in-a-delayed-digest.md)
* Worker secret boundary: [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
* Thread start ordering: [ADR-0082](0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)
