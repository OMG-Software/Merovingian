# Every IPC frame is valid UTF-8 by construction, and request bytes cross it losslessly

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-35 and F-08

## Context and Problem Statement

The IPC reader parses every authenticated frame with `canonicaljson::parse_json`, which refuses a document that is
not valid UTF-8. `ipc_json_str` escaped the quote, the backslash and control bytes and copied every other byte,
including 0x80-0xFF, into the frame. Bytes a remote server chose reached it in two ways: the HTTP parser lets
0x80-0xFF through in a header value and in the request target, and the federation handlers percent-decode attacker
bytes (`%FF`) into the identifiers they relay from a worker to main. One signed request therefore produced a frame
its peer could not parse. The frame is not the problem: a frame this process writes should be one its peer can read,
whatever the content, and a remote server should not choose that.

Two kinds of field are involved. Most carry text this server defines (identifiers, types, JSON it has already
parsed), where a byte that is not UTF-8 is an error and can be replaced. The `fed_request` frame carries a remote
server's request, whose target, header values and body must reach the worker as sent: the worker routes on the
target, and the body is judged by the same parser that would judge it in main.

## Considered Options

* Make `ipc_json_str` replace invalid bytes with U+FFFD, and send the request fields that must be exact in a second
  form when they are not UTF-8
* Reject a request with a non-UTF-8 target, header or body in `FederationProxy::handle` with 400
* Base64-encode every request field
* Fail `ipc_json_str` (throw or return an error) on invalid UTF-8

## Decision Outcome

Chosen option: "replace in `ipc_json_str`, and send request bytes that are not UTF-8 as `<key>_b64`".

`ipc_json_str` copies only byte sequences that `canonicaljson::utf8_is_valid` accepts and writes U+FFFD for each other
byte, so no caller, present or future, can write a frame the peer's parser refuses. It uses the parser's own
definition of valid, so the two cannot disagree.

`serialize_fed_request` sends `target`, each header value (`v`) and `body` through `append_lossless_member`: a value
that is valid UTF-8 is a plain JSON string exactly as before, and one that is not is sent as `target_b64`, `v_b64` or
`body_b64` (standard base64, as ADR-0043 does for response bodies) and restored byte for byte by
`deserialize_fed_request`. Neither side needs a flag: a key is either present or its `_b64` twin is. Valid text keeps
its plain form because that is almost every request, it stays readable in a trace, and it costs no 4/3 expansion; the
frame budget (`frame_bytes_for_transport_caps`) already allows six times the request size. Header names, the method
and the verified identity are tokens and values this server wrote, so they use `ipc_json_str` and are never
`_b64`.

Rejecting in the proxy was rejected as the only measure. It would be a change in what a worker accepts (a request the
worker could answer is refused in main) for no gain, since the worker already treats non-UTF-8 input as the failure
it is, and it protects only the one direction. The identifiers that a worker relays to main are refused in the
federation handlers with 400 `M_INVALID_PARAM` where the spec's identifier grammar rejects them (F-08); that is the
grammar, not this decision. Base64 for every field would make every frame unreadable in a trace for the sake of a
case that almost never occurs. Failing `ipc_json_str` would put an error path in 40 call sites that cannot do
anything useful with it, and a caller that forgot to handle it would drop a frame silently.

### Positive Consequences

* A remote server can no longer make a frame its peer rejects. The reader's tolerance (ADR-0322) is the second
  layer, not the first.
* Request bytes reach the worker exactly, so worker behaviour on a malformed request is what it was.

### Negative Consequences

* A relayed identifier or JSON string holding invalid bytes reaches its peer with U+FFFD in place of them. For
  identifiers that is correct (they fail the grammar at the peer as well); a string that must be signed or hashed
  is never built this way, because it has already been parsed as JSON and so is valid UTF-8.
* A new `fed_request` field that carries remote bytes has to use `append_lossless_member`.

## Links

* Refines [ADR-0043](0043-base64-encode-ipc-response-bodies.md)
* Related to [ADR-0322](0322-an-authenticated-frame-whose-payload-does-not-parse-fails-one-request.md)
