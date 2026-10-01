# The federation worker never signs

* Status: accepted
* Date: 2026-09-29

Technical Story: security audit 2026-09-29, finding CRY-1. Supersedes the
signing-oracle part of [ADR-0015](0015-keep-the-signing-secret-out-of-the-federation-worker.md).

## Context and Problem Statement

ADR-0015 kept the signing secret out of the federation worker by having the
worker send `sign_request` IPC frames that main answered by signing the bytes it
was given with whichever held key it named. Its consequences called this "a
compromised worker can request signatures but cannot exfiltrate the signing
key. That is the entire point of the split."

That premise was wrong in two ways. First, requesting signatures is what a
forger needs; the key never needing to leave main does not stop a compromised
worker from minting valid signatures as this server: forged PDUs "from" any local
user, forged X-Matrix requests, forged key-server responses. The worker keeps
outbound network access, so it can deliver them to any peer, and ADR-0071's
re-verification does not help because the forgeries never pass through main.
The handler had no domain tag, no allowlist of request shapes, no key pinning
and no binding to an operation main had started, and it signed under the global
`runtime.mutex`, so a frame of tens of MiB doubled as a lock-hold denial of
service. Second, the worker has no production need for a signature at all.
Every signing call site reachable in the worker either runs in main or cannot
succeed there (see the trace below).

## Decision Drivers

* The worker is the process most exposed to hostile input; it must hold no
  capability whose abuse is worse than what the worker can already do.
* A capability nothing legitimate uses is pure attack surface.
* Fail closed: an unexpected request must produce an error, never a signature.

## Considered Options

* Keep `sign_request` and harden it (typed requests, key pinning, refuse
  anything event-shaped, do the work outside `runtime.mutex`)
* Remove signing from the worker entirely and refuse any `sign_request` in main

## Decision Outcome

Chosen option: "Remove signing from the worker entirely".

* The `sign_request` frame, main's handler for it, `ipc::IpcEd25519Provider`
  and `RuntimeStartOptions::signing_override` are removed.
* The worker starts its runtime with `RuntimeStartOptions::signing_disabled`,
  which installs `crypto::RefusingEd25519Provider`: every `sign` returns an
  error with no signature bytes, and `verify` returns "not valid" (it no longer
  terminates the process). No key is loaded or minted, and the key document is
  not pre-warmed.
* Main answers a `sign_request` frame from a worker with an error frame
  (`{"type":"error","status":403,...}`) and no signature, inline on the IPC
  dispatch thread, through `homeserver::refuse_forbidden_worker_request`. That
  function takes no `HomeserverRuntime`, so a refused frame cannot take
  `runtime.mutex`, reach a crypto provider or occupy a handler-pool slot or an
  in-flight slot. The refusal is logged at error level without the
  attacker-controlled payload or key id.
* The channel is not torn down on such a frame. Every other unexpected frame
  type is already logged and dropped without a teardown, and tearing the channel
  down would only let a compromised worker churn supervisor restarts. Detection
  and response are the log line and the operator.
* Other frame types are not renumbered or changed; framing stays compatible.

If worker-originated signing is ever genuinely needed, it must be a new,
narrowly typed request: main builds the payload itself from validated fields,
pins the active key, and refuses anything shaped like an event. That is a new
decision, not a reinstatement of `sign_request`.

### Signing call sites reachable in the worker (why none is needed)

* Client-server sends, room creation, joins, leaves, invites-by-3pid and
  `compose_signed_event` (`room_service.cpp`): main only, driven by client
  requests the worker never serves.
* Outbound X-Matrix (`perform_sync_outbound_call`, the dispatch worker,
  backfill): signed in main with the raw secret held in main's runtime; the
  worker's `outbound_http_request` handler only executes an already-signed
  request. In the worker the secret is empty, so these already fail closed.
* Invites: the worker's `invite_handler` is overridden to relay `invite_ingest`
  to main, which signs; the default handler that signs
  (`sign_invite_event`) never runs in the worker.
* `GET /_matrix/key/v2/server` (`publish_server_signing_keys`): always served
  by main (`FederationProxy`), and the worker skips the start-up pre-warm.
* send_join, send_leave, send_knock, transactions and EDUs: relayed to main;
  the worker verifies nothing through the runtime provider.

### Positive Consequences

* A compromised worker has no signing capability, locally or through main. The
  signing secret and the ability to use it both stay in main.
* The lock-hold denial of service through `sign_request` is gone.
* Main's IPC surface from the worker shrinks by one frame type.

### Negative Consequences

* A future feature that needs the worker to sign has to introduce a typed,
  main-built request instead of reusing a generic signing frame.
* The refusal is an error reply, not a channel teardown, so a compromised worker
  can still send `sign_request` frames (each is cheap and answered inline); the
  per-channel frame-size cap and the other frame caps still bound them.

## Links

* Supersedes the signing-oracle part of [ADR-0015](0015-keep-the-signing-secret-out-of-the-federation-worker.md)
* Related: [ADR-0062](0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md),
  [ADR-0071](0071-main-re-verifies-pdus-relayed-by-the-federation-worker.md)
* [`docs/crypto-boundary.md`](../crypto-boundary.md), [`docs/threat-model.md`](../threat-model.md)
