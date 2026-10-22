// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::homeserver
{

// Application Service API (Matrix v1.19), "Pushing ephemeral data": "If the `receive_ephemeral`
// settings is enabled in the registration file, homeservers MUST send ephemeral data that is
// relevant to the application service via the transaction API, using the `ephemeral` property
// of the request's body." Three event types exist, each with its own relevance rule:
//
//   * m.typing and m.receipt "under the same rules as regular events": the appservice has
//     registered interest in the room itself (rooms or aliases namespace), or in a user that is
//     in the room. Both carry a top-level `room_id`.
//   * Private read receipts (`m.read.private`) "MUST only be sent for users matching one of the
//     application service's namespaces"; normal and threaded read receipts are always sent.
//   * m.presence "if the data would apply contextually. For example, a presence update for a user
//     an application service shares a room with, or matching one of the application service's
//     namespaces."
//
// Design (ADR-0190): ephemeral data is held in memory per appservice, bounded, coalesced by what
// it describes, and attached to the next transaction the drainer sends (appservice_delivery.hpp).
// It is never written to the database and a restart or an overflow forgets it. The spec requires
// that relevant ephemeral data be sent, not that it survive an outage; it describes the present,
// and the present is re-announced by the next typing, receipt or presence change.

// The most items queued for one appservice. At the cap the oldest is dropped (and counted).
inline constexpr auto max_appservice_ephemeral_queue = std::size_t{512U};
// The most ephemeral items one transaction carries. A transaction is not a way to move the whole
// queue in one request body, and a retry resends exactly what the first attempt carried.
inline constexpr auto max_appservice_ephemeral_per_transaction = std::size_t{100U};
// The most member-against-namespace matches one presence update makes, across every appservice and
// every room the subject is in. A presence change by a user in many large rooms would otherwise cost
// a regex match per member of every room, under runtime.mutex, per update (compare
// ADR-0173..ADR-0176). Finding the rooms the subject is in is not charged, so rooms the subject is not
// in never use up the budget. Past the budget the remaining rooms are not examined: an appservice may
// miss that one update, which the next one corrects.
inline constexpr auto max_appservice_presence_member_checks = std::size_t{20000U};

// Pure builders of the serialized `ephemeral` events. Exposed so the shapes are unit-testable
// without a runtime. Each returns an empty string if serialization fails.
//
// m.typing: {"content":{"user_ids":[...]},"room_id":"!r","type":"m.typing"}
[[nodiscard]] auto make_typing_ephemeral_event(std::string_view room_id, std::vector<std::string> const& user_ids)
    -> std::string;
// m.receipt: {"content":{"$event":{"m.read":{"@u":{"ts":N,"thread_id":"main"}}}},"room_id":"!r","type":"m.receipt"}
[[nodiscard]] auto make_receipt_ephemeral_event(database::PersistentReceipt const& receipt) -> std::string;
// m.presence:
// {"content":{"presence":...,"last_active_ago":N,"currently_active":B,...},"sender":"@u","type":"m.presence"}
[[nodiscard]] auto make_presence_ephemeral_event(database::PersistentPresence const& presence,
                                                 std::optional<database::PersistentProfile> const& profile)
    -> std::string;

// Adds `item` to `queue`: an older item with the same key is replaced (the newer one takes the
// back of the queue), and when the queue holds `capacity` items the oldest is dropped and counted
// in `queue.dropped`. Pure, for tests and for the three queue_* functions below.
auto push_appservice_ephemeral(AppserviceEphemeralQueue& queue, AppserviceEphemeralItem item, std::size_t capacity)
    -> void;

// Queues the room's current typing list for every appservice with `receive_ephemeral` that is
// interested in the room. Called whenever the set of users typing in a room changes
// (update_room_typing_stream_id_if_changed), which covers local typing, federated typing and the
// stop-typing a message send implies. Takes runtime.mutex itself (recursive) and wakes the
// drainer when anything was queued. Makes no network call.
auto queue_appservice_typing(HomeserverRuntime& runtime, std::string_view room_id) -> void;
// As above, with the room's typing list (sorted user IDs) already in hand, so a caller that has
// grouped the typing table by room (expire_typing) does not rescan it per room.
auto queue_appservice_typing(HomeserverRuntime& runtime, std::string_view room_id,
                             std::vector<std::string> const& typing_user_ids) -> void;

// Queues one stored read receipt (local or federated) for every interested appservice with
// `receive_ephemeral`; private read receipts only for appservices whose namespaces cover the
// receipt's user. Same locking and wake behaviour as above.
auto queue_appservice_receipt(HomeserverRuntime& runtime, database::PersistentReceipt const& receipt) -> void;

// Queues one presence change for every appservice with `receive_ephemeral` whose namespaces cover
// the user, or that has a user in a room the subject is joined to. Makes at most
// max_appservice_presence_member_checks namespace matches in total.
auto queue_appservice_presence(HomeserverRuntime& runtime, database::PersistentPresence const& presence) -> void;

// Removes up to max_appservice_ephemeral_per_transaction items, oldest first, from the queue of
// `appservice_id` and returns their serialized events. Called by the drainer with runtime.mutex held.
[[nodiscard]] auto take_appservice_ephemeral(HomeserverRuntime& runtime, std::string_view appservice_id)
    -> std::vector<std::string>;

// True when something is queued for `appservice_id` (the drainer uses it to decide whether an
// events-free transaction is worth sending). Caller holds runtime.mutex.
[[nodiscard]] auto has_appservice_ephemeral(HomeserverRuntime const& runtime, std::string_view appservice_id) -> bool;

} // namespace merovingian::homeserver
