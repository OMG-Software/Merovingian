# src/email/ — Outbound Email

The SMTP client and the email messages this server sends. Its only user today is kind `"email"`
pushers (ADR-0219, ADR-0220): the policy (who is mailed, when, and what) is in
`push/email_digest_queue.cpp` and `homeserver/email_push.cpp`. This module only checks addresses,
parses the relay URL, builds a message, and sends it.

Spec authority: [client-server-api.md](../../docs/matrix-v1.19-spec/client-server-api.md),
`POST /_matrix/client/v3/pushers/set` (kind `"email"`, `app_id` `"m.email"`, `pushkey` the
address). The spec says nothing about transport or content; ADR-0219 and ADR-0220 do.

## Key files

| File | Responsibility |
|---|---|
| `mailbox_address.cpp` | `is_safe_mailbox_address`: whether an address may be written into an SMTP command or a header as it stands |
| `smtp_endpoint.cpp` | `parse_smtp_url`: `smtps://host[:port]` or `smtp://host[:port]`, and whether the host is a loopback IP literal |
| `notification_email.cpp` | `build_unread_notification_email`: the RFC 5322 message carrying an unread count, and nothing else |
| `smtp_client.cpp` | `send_smtp_message` (one libcurl SMTP session) and `smtp_protocol_available` |

`mailbox_address.cpp` and `smtp_endpoint.cpp` are pure and are called by `config::validate`, which
is why `email` is built before `config` in `src/meson.build`.

## Rules — non-negotiable

1. **Refuse, never repair.** An address, server name or token that fails its check means no
   message is built and nothing is sent. Never escape, strip or truncate a value to make it fit:
   a CR, LF, NUL or `>` in an address is a command or header injection, and a "cleaned" address
   may be someone else's.
2. **Every address passes `is_safe_mailbox_address` before it reaches libcurl or a header**, the
   sender included. `send_smtp_message` checks again even though config validation and
   registration already did.
3. **TLS is required unless the relay is a loopback IP literal and the operator set
   `require_tls=false`** (ADR-0220). `smtp://` uses `CURLUSESSL_ALL`, never `CURLUSESSL_TRY`;
   verification of peer and host name stays on; the floor is TLS 1.2. Credentials are never sent
   without TLS. A name such as `localhost` is not loopback here.
4. **The password is read from its secret file for each send**, into a `core::SecretBuffer`, and
   never logged, copied into a `std::string`, or put in a finding or outcome detail.
5. **No proxy, no connection reuse, no protocol other than the configured scheme**
   (`CURLOPT_PROTOCOLS_STR`). One handle per send, destroyed when the send ends.
6. **Never call `send_smtp_message` with a lock held.** It blocks for up to the configured
   timeouts. The email job calls it with `runtime.mutex` released.
7. **The message carries only what ADR-0219 allows**: the unread count and the server name. Adding
   a room name, a sender or message text is a change to ADR-0219, not to this module.
8. **Only the main process sends email.** The federation worker clears `server.email` in its
   config copy (`worker_event_loop.cpp`); do not add a send path reachable from the worker.

## Testing

- `tests/unit/test_email.cpp` — address checks, relay URL parsing, message content and refusal
  (`[email]`)
- `tests/unit/test_config_email.cpp` — `server.email.*` parsing and validation (`[config][email]`)
- `tests/integration/test_email_push_flow.cpp` — real SMTP sessions against a loopback mock relay:
  implicit TLS with AUTH, STARTTLS, a relay without STARTTLS, cleartext loopback
  (`[integration][push][email]`)
