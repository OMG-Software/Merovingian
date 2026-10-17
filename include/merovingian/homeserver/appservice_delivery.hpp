// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"

#include <chrono>
#include <cstdint>
#include <stop_token>
#include <string_view>

namespace merovingian::homeserver
{

// Application Service API (Matrix v1.19) outbound delivery, "Pushing events":
// "The homeserver MUST maintain a queue of transactions to send to the
// application service ... these requests can be made without blocking other
// aspects of the homeserver. Homeservers MUST NOT alter (e.g. add more) events
// they were going to send within that transaction ID on retries."
//
// The design (ADR-0163) has two halves that never meet except through the
// database:
//
//   * enqueue_appservice_delivery runs on the request thread, under
//     runtime.mutex, makes no network call, and writes one durable
//     `appservice_outbox` row per interested appservice;
//   * drain_appservice_queues runs on ONE dedicated thread and sends each
//     appservice's rows, oldest first, one event per transaction, retrying a
//     failed transaction under the same ID with exponential back-off.

// Queues the event `event_id` in `room` for every registered appservice
// interested in it (appservice::registration_interested_in_room_event,
// evaluated now, at event time), then wakes the drainer through
// runtime.appservice_delivery_wake when anything was queued.
//
// `fallback_stream_ordering` is used only when the store holds no row for the
// event. Idempotent on (appservice, stream ordering). There is deliberately no
// "already delivered" check: stream orderings are allocated before commit and
// events in different rooms commit out of order, so a lower ordering can
// arrive after a higher one was delivered. Takes runtime.mutex itself (it is
// recursive, so callers that already hold it are fine). Does nothing when no
// appservice is registered or the runtime has no outbound client.
auto enqueue_appservice_delivery(HomeserverRuntime& runtime, LocalRoom const& room, std::string_view event_id,
                                 std::uint64_t fallback_stream_ordering, std::string_view sender) -> void;

// Sends queued transactions. Call from exactly ONE thread at a time (the
// PeriodicJob in main.cpp, or a test), WITHOUT runtime.mutex held by the
// caller: it takes the mutex itself and releases it around every network call.
// That single caller is the invariant that makes "one in-flight transaction per
// appservice" true without a lock of its own; calling it concurrently would let
// two threads send the same pending transaction.
//
// Per appservice, oldest outbox row first, at most 64 transactions per call,
// stopping early when `stop` is requested (checked between transactions):
//
//   1. A transaction already pending on the cursor (sent but not acknowledged,
//      including one left by the pre-outbox design) is rebuilt from its stored
//      event and re-sent under its own ID.
//   2. Otherwise the lowest outbox row becomes the next transaction: its ID
//      and event are written to the cursor BEFORE sending, so a retry (even
//      after a restart) reuses that ID with that event and nothing else.
//   3. On success (or a url:null appservice, which needs no traffic) the cursor
//      advance and the row's deletion commit in one database transaction.
//   4. On failure the appservice backs off in memory (1 s, doubling to 5 min)
//      and the rest of its queue waits behind the failed transaction.
//
// `now` is the caller's clock (tests step it; production passes the default).
// Returns how long until the next call is worthwhile: 0 when an appservice
// still has queued work this call did not get to, otherwise the time to the
// earliest back-off deadline, otherwise 60 s.
[[nodiscard]] auto drain_appservice_queues(HomeserverRuntime& runtime, std::stop_token const& stop,
                                           std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
