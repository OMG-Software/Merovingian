# An authenticated IPC frame whose payload does not parse fails one request, not the channel

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-03

Technical Story: security audit run 2, F-09 (and F-08, F-35 as the same class)

## Context and Problem Statement

`IpcChannel::reader_loop` treated any parse failure of a frame as fatal: it set `healthy_` false and stopped
reading. A frame is parsed as a whole, application fields included, so one out-of-range integer in a response
(`make_join`'s `depth` of 2^53 for a room already at the limit), one byte that is not UTF-8, or any other value the
parser refuses ended the channel, and the worker process with it. PR #549 clamped the one `depth` that was reachable,
but the class stayed: any application value the parser refuses, in any frame, from any code path, kills a shard.

Two different failures reach the reader. A frame that fails AEAD authentication or breaks the length framing means
the stream cannot be trusted any further, and nothing after it can be read with confidence. A frame that decrypts
fine and carries a payload the JSON parser refuses was written by the peer, whole, and the only thing wrong is
the one request it belongs to.

## Considered Options

* Keep the channel on a payload parse failure, read the frame's id and reply_to from its fixed prefix, and fail
  that request
* Keep the channel and drop the frame, leaving the waiter to its timeout
* Parse the routing members first and the application members later, in a second pass
* Leave the reader as it was and clamp each value at its producer

## Decision Outcome

Chosen option: "keep the channel, read the routing prefix, fail that request". Only `read_frame` failing (length,
short read, AEAD) ends the channel.

`IpcChannel::build_frame` writes `{"id":N` and, for a response, `,"reply_to":M` first in every frame. When
`parse_json` refuses an authenticated frame, `read_frame_routing` reads those two integers from the front without
parsing the rest. A response (`reply_to`) wakes its `send_request` waiter with no response, so the caller sees
the failure at once instead of its timeout; every caller already treats `std::nullopt` as a failed request (503, a
refused relay). A request frame, or one whose id cannot be read, is dropped and logged at warning level, with the
parser's error name, the size and the ids, never the payload. Nothing is sent back for a dropped request, because
the reader thread must not block on a write (its peer's reader may be blocked the same way) and the sender's own timeout
bounds it.

Clamping each producer (F-09's suggestion) was kept as well for the depth, but rejected as the fix: it names one value
in one frame, and the next unclamped value would have the same effect. Parsing the routing members first and the rest
later was rejected as the same behaviour at twice the code. Dropping with no recovery of the id was rejected because
the waiter of a response would hang for its whole timeout (up to the remote timeout plus ten seconds), which is the
availability loss this removes.

### Positive Consequences

* One bad value fails one request. Authentication and framing failures still end the channel.
* The reader needs no knowledge of any frame type.

### Negative Consequences

* A peer that can write authenticated frames (a compromised worker) can fill the log with warnings. It could already
  send any well-formed frame at will; the dispatch queue caps still bound the memory it can pin.
* The routing prefix is a property of `build_frame`; a frame built any other way yields no ids and is only logged.

## Links

* Related to [ADR-0321](0321-every-ipc-frame-is-valid-utf-8-by-construction.md)
* Related to [ADR-0323](0323-the-supervisor-restarts-a-worker-whose-main-side-channel-failed.md)
