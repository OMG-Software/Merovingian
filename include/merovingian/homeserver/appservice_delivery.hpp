// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stop_flag.hpp"

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

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

// Every alias this server holds for `room_id` (a room may have several; the interest test must see
// all of them, not the first). Reads the store: the caller holds runtime.mutex.
[[nodiscard]] auto appservice_room_aliases(HomeserverRuntime const& runtime, std::string_view room_id)
    -> std::vector<std::string>;

// Queues the event `event_id` in `room` for every registered appservice
// interested in it (appservice::registration_interested_in_room_event,
// evaluated now, at event time), then wakes the drainer through
// runtime.appservice_delivery_wake when anything was queued.
//
// `member_event_target` is the state_key of an `m.room.member` event (the user an invite, kick
// or ban is about) and empty for every other event: a local user in an appservice's `users`
// namespace is "the target of the event" through it even though they are not joined (R07).
//
// `fallback_stream_ordering` is used only when the store holds no row for the
// event. Idempotent on (appservice, stream ordering). There is deliberately no
// "already delivered" check: stream orderings are allocated before commit and
// events in different rooms commit out of order, so a lower ordering can
// arrive after a higher one was delivered. Takes runtime.mutex itself (it is
// recursive, so callers that already hold it are fine). Does nothing when no
// appservice is registered or the runtime has no outbound client.
//
// An appservice whose queue already holds appservice.max_queued_events rows is skipped: the
// event is not queued for it, runtime.appservice_outbox_dropped is incremented, and the first
// drop and every thousandth after it are logged at warning level and audited (ADR-0191).
auto enqueue_appservice_delivery(HomeserverRuntime& runtime, LocalRoom const& room, std::string_view event_id,
                                 std::uint64_t fallback_stream_ordering, std::string_view sender,
                                 std::string_view member_event_target = {}) -> void;

// The same, for a room this server holds no LocalRoom for, such as an invite received over
// federation for a room it has never been in: `room_members` is whatever this server knows of the
// room's joined members (empty for such an invite), so only the room ID, its aliases, the sender and
// `member_event_target` can make an appservice interested.
auto enqueue_appservice_delivery(HomeserverRuntime& runtime, std::string_view room_id,
                                 std::span<std::string const> room_members, std::string_view event_id,
                                 std::uint64_t fallback_stream_ordering, std::string_view sender,
                                 std::string_view member_event_target) -> void;

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
// Ephemeral data (appservice_ephemeral.hpp, ADR-0190) rides the same transactions. An event
// transaction carries up to max_appservice_ephemeral_per_transaction queued items in its
// `ephemeral` array, the same items again on a retry under the same ID; only a transaction built
// fresh takes queued items, so a retry whose first attempt carried none carries none. When an appservice has
// ephemeral data and no queued event, an events-free transaction carries the data alone under a
// fresh ID from the cursor's next_txn_id; it is not persisted, so a restart forgets it.
//
// `now` is the caller's clock (tests step it; production passes the default).
// Returns how long until the next call is worthwhile: 0 when an appservice
// still has queued work this call did not get to, otherwise the time to the
// earliest back-off deadline, otherwise 60 s.
[[nodiscard]] auto drain_appservice_queues(HomeserverRuntime& runtime, StopFlag const& stop,
                                           std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    -> std::chrono::milliseconds;

} // namespace merovingian::homeserver
