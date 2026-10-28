// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sync_filter.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Matrix v1.19 CS API "Presence" and SS API "m.presence".
//
// Local resource policy, not a Matrix protocol limit: a status message is at most this many UTF-8
// bytes, on PUT and on an inbound EDU alike.
inline constexpr auto max_presence_status_msg_bytes = std::size_t{1024U};

// The most entries of one inbound m.presence EDU's `push` list that are looked at. A federation
// transaction carries at most 100 EDUs, and an entry costs a lookup and a row write under
// runtime.mutex, so the list is cut off here rather than trusted to be short.
inline constexpr auto max_inbound_presence_entries = std::size_t{100U};

// Spec: "One of: [online, offline, unavailable]".
[[nodiscard]] auto presence_state_is_valid(std::string_view state) noexcept -> bool;

// `presence.enabled`.
[[nodiscard]] auto presence_enabled(HomeserverRuntime const& runtime) noexcept -> bool;

// Wall-clock milliseconds since the Unix epoch.
[[nodiscard]] auto presence_now_ms() -> std::int64_t;

// "The last active time must be up to date whenever the server gives a presence event to the
// client": the stored value plus the time since it was true. Never negative.
[[nodiscard]] auto presence_last_active_ago(database::PersistentPresence const& row, std::int64_t now_ms) noexcept
    -> std::int64_t;

// The `content` of an m.presence event for a client (CS API "m.presence"): `presence`,
// `status_msg` when set, `last_active_ago`, `currently_active`, and the user's `displayname` and
// `avatar_url` when this server holds a profile for them.
[[nodiscard]] auto presence_event_content(database::PersistentStore const& store,
                                          database::PersistentPresence const& row, std::int64_t now_ms)
    -> canonicaljson::Object;

// The `content` of the m.presence EDU (SS API) that reports one local user's presence:
// {"push":[{"user_id","presence","last_active_ago","currently_active","status_msg"?}]}.
// Empty when it cannot be serialized.
[[nodiscard]] auto presence_edu_content(database::PersistentPresence const& row, std::int64_t now_ms) -> std::string;

// Stores one user's presence and tells appservices. The caller holds runtime.mutex and wakes the
// sync notifier. `row.observed_at_ms` is set here.
[[nodiscard]] auto record_presence(HomeserverRuntime& runtime, database::PersistentPresence row) -> bool;

// How a GET /presence/{userId}/status is answered.
enum class PresenceReadStatus : std::uint8_t
{
    ok,
    forbidden,
    not_found,
};

struct PresenceRead final
{
    PresenceReadStatus status{PresenceReadStatus::not_found};
    // The response body when `status` is ok.
    canonicaljson::Object body{};
};

// GET /_matrix/client/v3/presence/{userId}/status for `requester`. The caller holds runtime.mutex.
//
//  * presence off: not_found ("no presence state for this user").
//  * the requester's own: always visible, `offline` for a local user who has none yet.
//  * another user: visible only when they share a joined room ("Presence information is published
//    to all users who share a room with the target user"), otherwise forbidden, for a user who
//    does not exist as for one who does, so the answer reveals nothing about who exists here.
//  * a visible local user with no presence is `offline`; a visible remote user with none is
//    not_found.
[[nodiscard]] auto read_presence(HomeserverRuntime const& runtime, std::string_view requester, std::string_view target)
    -> PresenceRead;

// What the `set_presence` parameter of /sync asks for.
enum class SyncPresenceMode : std::uint8_t
{
    online,      // omitted or "online"
    unavailable, // "unavailable": "the client is marked as being idle"
    offline,     // "offline": "not marked as being online when it uses this API"
};

// nullopt for a value outside the enumeration.
[[nodiscard]] auto parse_sync_presence_mode(std::optional<std::string_view> value) noexcept
    -> std::optional<SyncPresenceMode>;

// Applies a /sync's `set_presence` to a local user. Only a change of state is stored (and so only
// a change is sent to other users); an `online` user who syncs again just has their last-active
// time refreshed in memory. The caller holds runtime.mutex. Returns the new row when the state
// changed, so the caller can send it to other servers and wake long-polling syncs.
[[nodiscard]] auto apply_sync_presence(HomeserverRuntime& runtime, std::string_view user, SyncPresenceMode mode)
    -> std::optional<database::PersistentPresence>;

// The `presence.events` of a /sync response for `user`: other users who share a joined room,
// whose presence changed since `since_sync_stream_id` or who started sharing a room in
// (`since_ordering`, `sync_position`]. `has_since` is false for an initial sync, which names all.
// Advances `max_observed_stream_id` over the rows it sends. The caller holds runtime.mutex.
[[nodiscard]] auto build_sync_presence_events(database::PersistentStore const& store,
                                              sync::EventTypeFilter const& filter, std::string_view user,
                                              bool has_since, std::uint64_t since_sync_stream_id,
                                              std::uint64_t since_ordering, std::uint64_t sync_position,
                                              std::int64_t now_ms, std::uint64_t& max_observed_stream_id)
    -> canonicaljson::Array;

// An inbound m.presence EDU (SS API "m.presence"). Takes runtime.mutex itself. An entry is kept
// only when:
//   * `user_id` belongs to the sending origin (a server speaks only for its own users);
//   * `presence` is one of the enumeration and `status_msg`, if any, is a string within
//     max_presence_status_msg_bytes;
//   * the user is joined to a room that a user of this server is joined to ("Servers should only
//     send presence updates for users that the receiving server would be interested in"), so a
//     peer cannot make this server keep rows for users it has no use for.
// Only the first max_inbound_presence_entries entries are looked at. With presence off the EDU is
// dropped. The caller wakes the sync notifier.
[[nodiscard]] auto accept_inbound_presence(HomeserverRuntime& runtime, std::string_view origin,
                                           std::string_view content_json) -> federation::EduDispositionResult;

} // namespace merovingian::homeserver
