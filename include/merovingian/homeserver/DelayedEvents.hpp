// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/DelayedEventAction.hpp"
#include "merovingian/homeserver/DelayedEventScheduleRequest.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/StopFlag.hpp"

#include <chrono>
#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

struct ClientServerRuntime;

// Delayed events (MSC4140, ADR-0823 to ADR-0826): scheduling, managing, looking up and sending an event a user asked
// to have sent later. Every function takes `ClientServerRuntime&` because the send-time rate limit lives there. Each
// REQUIRES the caller to hold `runtime.homeserver.mutex` (a request handler does), except `send_due_delayed_events`,
// which takes it itself. None makes a network call. Nothing here logs `content_json` or a state key.

// Wall-clock milliseconds since the Unix epoch, or `test_delayed_event_clock_ms` when a test set it. Every "now" of
// the feature comes from here or from the job's `now_ms` parameter. Needs no lock.
[[nodiscard]] auto delayed_event_now_ms(HomeserverRuntime const& runtime) -> std::uint64_t;

// Calls `HomeserverRuntime::delayed_events_wake` when one is installed, so the "delayed-events" job re-reads its next
// deadline. Caller holds runtime.mutex; the hook never blocks.
auto wake_delayed_events(HomeserverRuntime& runtime) -> void;

// Schedules a delayed event, in this order: the feature must be enabled (403 M_FORBIDDEN); the shape (413 M_TOO_LARGE
// for an event type over 255 bytes, 400 M_INVALID_PARAM for a transaction ID over 255 bytes, the ordinary state path's
// answer for a state key holding NUL or over 255 bytes, 400 M_INVALID_PARAM for a NUL in the type or transaction ID or
// a zero delay, 400 M_BAD_JSON for content that is not a JSON object, 413 M_TOO_LARGE for content over 65,536 bytes);
// the delay at most `max_delayed_event_delay_ms` (400, `M_DELAY_TOO_LARGE` or `ORG.MATRIX.MSC4140_DELAY_TOO_LARGE`);
// an existing event of the same (user, device, room, type, transaction ID), which is answered `ok` with its ID and
// stores nothing; the room known and the sender joined (the answers `send_event` gives), and for a state event the
// sender's power (403, "event authorization or signing failed"); then the per-user cap (429 M_LIMIT_EXCEEDED with
// `retry_after_ms`, the time to the user's earliest due event rounded up to a whole second, at least 1000). On success
// stores the row, wakes the job, and answers `ok` with `value` the new delay ID (at most 64 bytes, URL-safe, at least
// 128 random bits). A store failure is 500.
[[nodiscard]] auto schedule_delayed_event(ClientServerRuntime& runtime, DelayedEventScheduleRequest const& request)
    -> OperationResult;

// Sends, cancels or restarts the delayed event `delay_id` of `user_id`. An ID that is unknown, another user's, empty or
// over 64 bytes is 404 M_NOT_FOUND "Delayed event not found.", identically. Outcomes (all `ok`, empty `value`, on 200):
// scheduled: restart (the timer starts again now), cancel, or send (sends now; on success the row is sent). Sent: send
// is 200, restart and cancel 409. Cancelled, or failed: cancel is 200, restart and send 409. Being sent right now: 409
// for all three. A 409 is errcode M_UNKNOWN with reason "The delayed event has already been sent." / "...already been
// cancelled." / "The delayed event is being sent.". A send that fails answers with the send's own OperationResult
// (status, errcode, reason, retry_after_ms), unchanged, and leaves the row scheduled with its timer unchanged: an
// account refusal is 401 M_USER_LOCKED, 403 M_USER_SUSPENDED or 403 M_USER_DEACTIVATED, a rate-limit denial 429
// M_LIMIT_EXCEEDED with `retry_after_ms`, and the rest are what `send_event` would answer. A store failure is 500.
[[nodiscard]] auto manage_delayed_event(ClientServerRuntime& runtime, std::string_view user_id,
                                        std::string_view delay_id, DelayedEventAction action) -> OperationResult;

// The lookup of one delayed event: the same 404 as `manage_delayed_event` for an unknown, foreign, empty or over-long
// ID; on a hit `ok` with `value` the JSON body (`delay_id`, `room_id`, `type`, `state_key` only for a state event,
// `delay_ms`, `delayed_since_ts`, `content`, and `finalised` {`finalised_ts`, `event_id` when sent, `error` when
// failed} only once finalised).
[[nodiscard]] auto delayed_event_lookup(ClientServerRuntime& runtime, std::string_view user_id,
                                        std::string_view delay_id) -> OperationResult;

// The "delayed-events" job's body (main.cpp; tests call it directly). Takes runtime.homeserver.mutex itself: sends the
// earliest scheduled event due at `now_ms` or earlier, if any, in one hold, and none once `stop` is requested, never
// before its due time; then, in another hold, deletes at most 500 finalised rows older than 7 days before `now_ms`.
// At most ONE send a run, so the runtime lock is free between sends (the mutex is not fair; ADR-0353 paces the profile
// job the same way). A failed send is recorded and never retried. Returns how long to wait before the next run, never
// 0: 5 ms (`delayed_events_pace`) when another event is already due at `now_ms`; else the time to the next deadline,
// at least 5 ms and at most 60 s; 60 s when nothing is scheduled. A caller that wants a backlog drained calls it again.
[[nodiscard]] auto send_due_delayed_events(ClientServerRuntime& runtime, std::uint64_t now_ms, StopFlag const& stop)
    -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
