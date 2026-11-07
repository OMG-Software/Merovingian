// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentPresence.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/PresenceRead.hpp"
#include "merovingian/homeserver/SyncPresenceMode.hpp"
#include "merovingian/sync/EventTypeFilter.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

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

// CS API "Presence", "Idle timeout": "The server will automatically set a user's presence to `unavailable` if
// their last active time was over a threshold value (e.g. 5 minutes)." The spec names no value; this is the
// spec's example (ADR-0492).
inline constexpr auto presence_idle_timeout_ms = std::int64_t{5 * 60 * 1000};

// How long the "presence-idle" job sleeps between passes. A user is set unavailable at most this much after
// crossing the threshold (ADR-0492).
inline constexpr auto presence_idle_sweep_interval = std::chrono::seconds{30};

// The most users one pass of the idle sweep sets unavailable. Each costs a commit, an appservice queue entry and a scan
// of the rooms for the servers to tell, all under runtime.mutex, so a mass disconnect or a long downtime is taken in
// passes (ADR-0492).
inline constexpr auto presence_idle_max_per_pass = std::size_t{100U};

// How long the job sleeps after a pass that hit the bound: the lock is free in between, and the rest follow.
inline constexpr auto presence_idle_catch_up_interval = std::chrono::seconds{1};

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

// CS API "Presence", "Idle timeout" (ADR-0492): sets to `unavailable`, with `currently_active` false, every LOCAL user
// whose presence is `online` and whose last active time (`presence_last_active_ago`) at `now_ms` is over
// `presence_idle_timeout_ms`. A remote user's presence is their own server's to say, and `unavailable` and
// `offline` are not idle. Returns the rows as stored, for the caller to tell other servers about and to wake
// syncs for. At most `max_changes` rows are set; the caller sleeps `presence_idle_catch_up_interval` when it got that
// many. A row with no observation time (loaded from the database) gets one, so its clock runs from the first pass.
// The caller holds runtime.mutex. Does nothing with presence off.
[[nodiscard]] auto expire_idle_presence(HomeserverRuntime& runtime, std::int64_t now_ms,
                                        std::size_t max_changes = presence_idle_max_per_pass)
    -> std::vector<database::PersistentPresence>;

// CS API "Presence", "Last active ago": "A pro-active event may be sending a message to a room". A local user's
// message just stored makes an `online` row current: last active 0, observed now, currently active. In memory, like the
// still-online case of `apply_sync_presence`: no stream position, no EDU. Makes no row for a user who has none and does
// not change a state the user chose. The caller holds runtime.mutex.
auto note_local_message_activity(HomeserverRuntime& runtime, std::string_view user_id) -> void;

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
