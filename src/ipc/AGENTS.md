# src/ipc/ — Encrypted Worker IPC Channel

Bidirectional encrypted IPC over an `AF_UNIX` socketpair fd between `merovingian-server` (main)
and `merovingian-fed-worker`. There is no filesystem socket path: the fd is inherited through
`posix_spawn` (`channel.hpp`).

## Key files

| File | Responsibility |
|---|---|
| `channel.cpp` | `IpcChannel`: handshake, AEAD framing, reader and dispatch threads, `send_request` / `send_response` / `send_notification` |
| `federation_ipc_frames.cpp` | JSON (de)serialisation of `fed_request` / `fed_response`, `outbound_http_request` / `outbound_http_response`, `room_sync` frame bodies |
| `ipc_ed25519_provider.cpp` | `IpcEd25519Provider`: the worker-side `Ed25519Provider` that signs by asking main over the channel |

## Security model — non-negotiable

1. **The key exchange is mutually authenticated, not just confidential.** Both peers derive the
   same `crypto::IpcAuthKey` from the operator master key and MAC each other's ephemeral
   `crypto_kx` public keys before deriving session keys. A peer that cannot prove possession of
   the master key is rejected, fail-closed.
2. **No libsodium in this module.** The AEAD stream cipher is a `crypto::IpcStreamCipher`
   implemented in `src/crypto/`; `scripts/reject-unsafe.sh` rejects direct libsodium use here.
3. **The signing secret and client credentials never cross the channel.**
   `IpcEd25519Provider::verify()` calls `std::terminate()` — verification only happens in main.
   Callers must never put an access token, `Authorization` / `X-Matrix` header, or the Ed25519
   secret key into a frame body (`docs/hardening.md`).
4. **Oversize frames fail the send and are logged, never silently dropped.** `max_frame_bytes`
   (`kIpcMaxFrameBytes`, 24 MiB) is derived identically on both ends from
   `security.federation.join_response_max_size`; both processes parse the same `--config` rather
   than negotiating over IPC, so both must restart to pick up a change.
5. **Response bodies are base64-encoded, not JSON-string-escaped.** Base64's 4/3 expansion is
   fixed; escaping's is payload-dependent and can push a near-cap response over the frame limit
   (ADR-0043).

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

- `tests/unit/test_ipc_framing.cpp` — framing, request/response pairing, notifications, timeouts
- `tests/unit/test_ipc_stream_cipher.cpp` — handshake and AEAD framing
- `tests/unit/test_ipc_federation_frames.cpp` — federation frame (de)serialisation

## Key docs

- `docs/hardening.md` — "Out_of_process federation worker IPC security"
- `docs/crypto-boundary.md` — IPC key derivation and cipher
- [ADR-0027](../../docs/adr/0027-bound-the-connection-queue-but-not-the-ipc-queue.md) ·
  [ADR-0043](../../docs/adr/0043-base64-encode-ipc-response-bodies.md)
