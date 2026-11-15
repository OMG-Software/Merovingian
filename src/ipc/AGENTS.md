# src/ipc/ — Encrypted Worker IPC Channel

Bidirectional encrypted IPC over an `AF_UNIX` socketpair fd between `merovingian-server` (main)
and `merovingian-fed-worker`. There is no filesystem socket path: the fd is inherited through
`posix_spawn` (`IpcChannel.hpp`).

## Key files

| File | Responsibility |
|---|---|
| `IpcChannel.cpp` | `IpcChannel`: handshake, AEAD framing, reader and dispatch threads, `send_request` / `send_response` / `send_notification` |
| `FederationIpcFrames.cpp` | JSON (de)serialisation of `fed_request` / `fed_response`, `outbound_http_request` / `outbound_http_response`, `room_sync`, and `membership_template_ingest` (a worker's `make_join`, ADR-0184) frame bodies; and the worker store frames (ADR-0733): `room_list_request` / `room_list_page`, `room_snapshot_request` / `room_snapshot_page`, `server_keys_request` / `server_keys_result`, with `paginate_room_list` and `paginate_room_snapshot` |
| `RoomSnapshotAssembler.cpp` | `RoomSnapshotAssembler`: joins a room snapshot's pages on the worker, in order, one room and generation, every row of that room |

## Security model — non-negotiable

1. **The key exchange is mutually authenticated, not just confidential.** Both peers derive the
   same `crypto::IpcAuthKey` from the operator master key and MAC each other's ephemeral
   `crypto_kx` public keys before deriving session keys. A peer that cannot prove possession of
   the master key is rejected, fail-closed.
2. **No libsodium in this module.** The AEAD stream cipher is a `crypto::IpcStreamCipher`
   implemented in `src/crypto/`; `scripts/reject-unsafe.sh` rejects direct libsodium use here.
3. **The signing secret and client credentials never cross the channel, and there is no signing
   frame.** The worker never signs and never asks main to sign for it (ADR-0078, superseding the
   signing-oracle part of ADR-0015): the `sign_request` frame and its worker-side provider are gone,
   main answers a `sign_request` from a worker with an error and no signature
   (`homeserver::refuse_forbidden_worker_request`, no runtime lock), and the worker's provider is
   `crypto::RefusingEd25519Provider`. Never add a generic "sign these bytes" frame; if a worker ever
   needs a signature, add a narrowly typed request where main builds the payload itself. Callers must
   never put the Ed25519 secret key, a client access token, or a peer's inbound `Authorization` /
   `X-Matrix` header into a frame body: main verifies the inbound signature and sends the worker only
   the verified identity, and `fed_request` drops those headers (`is_credential_header_name`). The one
   exception is direction-specific: an outbound request frame (`serialize_outbound_http_request`)
   carries this server's own `Authorization: X-Matrix` signature, bound to that one request's method,
   URI, destination and body, which is not a reusable peer or client credential (`docs/hardening.md`,
   `docs/security-coding-rules.md`).
4. **Oversize frames fail the send and are logged, never silently dropped.** `max_frame_bytes`
   (`kIpcMaxFrameBytes`, 24 MiB) is derived identically on both ends from
   `security.federation.join_response_max_size` and the transport caps, by
   `homeserver::worker_ipc_frame_bytes` (use it, never a copy of the arithmetic); both processes parse the same
   `--config` rather than negotiating over IPC, so both must restart to pick up a change. A response over the
   cap is replaced by `{"ipc_error":"response_too_large"}`, which the reader turns into "no response" for the
   waiter at once (`send_request` returns `nullopt`, as for a timeout), so the requester never waits out its timeout
   (ADR-0368). `ipc_error` is a reserved frame member. The cap is on the BUILT frame (body plus the `id` / `reply_to` header), not the body: `send_response` replaces a response whose frame is over it, `send_request` returns `nullopt` before registering a pending entry, and `send_notification` returns `false` (`[[nodiscard]]`), so no send is silently lost.
5. **Response bodies are base64-encoded, not JSON-string-escaped.** Base64's 4/3 expansion is
   fixed; escaping's is payload-dependent and can push a near-cap response over the frame limit
   (ADR-0043).

6. **Every frame a process writes is valid UTF-8, and only a failed read or write ends a channel.** The reader
   parses frames with `canonicaljson::parse_json`, which refuses invalid UTF-8, so `ipc_json_str` copies
   only valid sequences and writes U+FFFD for the rest (ADR-0321). A `fed_request` field that holds bytes
   a remote server chose (`target`, header `v`, `body`) goes through `append_lossless_member`, which sends
   a value that is not UTF-8 as `<key>_b64` and `get_lossless_str` restores it; a new such field does the
   same. An authenticated frame whose payload does not parse (an integer past 2^53 - 1, bad UTF-8) is logged
   and dropped by `reader_loop`, and the waiter of a response is released through `read_frame_routing`,
   which reads `{"id":N,"reply_to":M` from the front: keep that prefix first in `build_frame`. Only
   `read_frame` failing (length, short read, AEAD authentication) marks the channel unhealthy (ADR-0322), and on the
   sending side only a `write_frame` that fails after encryption (ADR-0734): the cipher has moved on, so a frame not
   written whole breaks the stream for good. `end_after_failed_write` marks the channel unhealthy and shuts the socket
   down; a refusal before encryption (over the cap, no memory) keeps the channel. Never ignore a failed write again.
   Never put a clamp for one value in place of this; the next value has the same effect.

7. **A pending request carries main-owned identity and EDU digests, never worker JSON (FED-12, F-74, ADR-0142,
   ADR-0395).** `send_request` takes the `verified_origin` and, for a verified `/send`, the digests of the EDUs of
   the body (`WorkerPool::handle`, `verified_send_edu_digests`). `consume_pending_edu` is the only way an EDU relay is
   admitted: live parent on this channel, exact origin, and an unused equal digest, marked used under `pending_mu_`.
   The pending lock covers that scan only, never a sink or network call. This module hashes nothing: digests are
   opaque strings made by `federation::edu_relay_digest`. The same holds for the claim and key/profile query relays
   (GHSA-3p5v-vrg8-f545, ADR-0595): `send_request`'s `relay_digests` come from `federation::verified_request_relay_digests`
   for a verified request only, and `consume_pending_relay` is the only way such a relay is admitted (live verified
   parent on this channel, an unused equal permit, marked used under `pending_mu_`).

8. **The worker's store crosses the channel exactly, in pages that fit a frame, or not at all (ADR-0733).** Every
   string of a store row goes through the lossless form and every integer as decimal text, so bytes that are not UTF-8
   and integers past 2^53 arrive as stored. `paginate_room_snapshot` and `paginate_room_list` pack rows under
   `worker_store_page_budget(max_frame_bytes)`, reserving the widest page numbers; a row that does not fit a page of its
   own refuses the room (`row_over_page_budget`) and is never cut. `RoomSnapshotAssembler` refuses a page out of order,
   of another room or generation, or with a row of another room, and a snapshot whose group entries or mappings name no
   group or event of it; the worker then fails the reload and never applies part of a room. A server key row is written
   with its public columns only.

## Thread safety — the reader/dispatch split

Each `IpcChannel` runs two threads (`docs/architecture.md`, "IPC reader/dispatch split"):

- **Reader thread** only routes frames: it wakes the `send_request` waiter for a `reply_to` frame
  or queues a request frame for dispatch. It must never run handler code, or a handler blocked on
  a lock held by a thread waiting in `send_request` on the same channel wedges all routing.
- **Dispatch thread** runs the registered `RequestHandler` for queued requests one at a time, in
  arrival order. Hand expensive work to a thread pool from inside the handler.
- A handler must never call its own channel's `stop()` — it would join itself.
- The IPC dispatch queue is deliberately **unbounded** while the network connection queue is
  bounded: the producer is the local supervisor, not a remote peer, and dropping here would lose
  federation work rather than shed a retryable connection (ADR-0027).

## Testing

- `tests/unit/test_ipc_framing.cpp` — framing, request/response pairing, notifications, timeouts, pending-request admission of EDU relays (`[f74-edu-binding]`) and of claim and query relays (`[ghsa-3p5v]`)
- `tests/unit/test_ipc_stream_cipher.cpp` — handshake and AEAD framing
- `tests/unit/test_ipc_federation_frames.cpp` — federation frame (de)serialisation
- `tests/unit/test_ipc_worker_store_frames.cpp` — the worker store frames, page budget and assembler (`[worker-store-frames]`)

## Key docs

- `docs/hardening.md` — "Out-of-process federation worker IPC security"
- `docs/crypto-boundary.md` — IPC key derivation and cipher
- [ADR-0027](../../docs/adr/0027-bound-the-connection-queue-but-not-the-ipc-queue.md) ·
  [ADR-0043](../../docs/adr/0043-base64-encode-ipc-response-bodies.md) ·
  [ADR-0368](../../docs/adr/0368-an-ipc-response-that-cannot-be-sent-fails-its-requester-at-once.md) ·
  [ADR-0321](../../docs/adr/0321-every-ipc-frame-is-valid-utf-8-by-construction.md) ·
  [ADR-0322](../../docs/adr/0322-an-authenticated-frame-whose-payload-does-not-parse-fails-one-request.md) ·
  [ADR-0395](../../docs/adr/0395-bind-worker-edu-relays-to-the-edus-of-the-verified-body-by-digest.md)
