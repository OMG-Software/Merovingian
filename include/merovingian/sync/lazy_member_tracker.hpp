// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/stream_token.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::sync
{

// Which membership events a `/sync` client has been sent, so that lazy-loading can leave out the ones it
// already holds. Spec (client-server-api.md, "Lazy-loading room members"): "the server MAY assume that clients
// will remember membership events they have already been sent, and choose to skip sending membership events
// for members whose membership has not changed", and "it is valid for the server to send redundant membership
// events". The tracker is therefore best effort: every case it cannot be sure of sends the member, and it
// never reports a member as held unless the client has proved it has the response that carried it.
//
// Acknowledgement, not "sent". A response can be lost on the wire, and the server cannot know. What it does
// know is the `since` token a later request presents. `next_batch` is opaque and clients echo it verbatim, so
// only an exact match proves the client received that response; "at or past" does not (a client that aborts a
// long-poll and retries the same `since` can be answered after the aborted request recorded a member, with a
// token past the aborted one's, yet it never received the member). So `record` always stores an entry
// *pending* with the event ID and the `next_batch` that carried it. `begin_request` settles a pending entry
// whose token equals the request's `since` on all three components and deletes any other pending entry; it
// also deletes a settled entry the `since` does not cover (a retry of an older token). `is_acknowledged` is true
// only for a settled entry with the same event ID whose token `since` covers (ADR-0450).
//
// Keyed by (user, device, the request's `filter` value verbatim, room), so two filter streams of one device
// and two devices of one user are tracked apart. A request with no device ID, or a filter longer than
// `Limits::max_filter_bytes` (treated as untracked rather than truncated or hashed), is untracked: the
// member functions do nothing and report nothing as acknowledged.
//
// Bounds. The filter string and the number of devices and rooms are client-controlled, so every level is
// capped and evicts its least recently used entry: keys, rooms per key, members per room, and members in
// all. An evicted member is merely sent again, which is valid, never omitted.
//
// In memory only: a restart forgets everything and every client is sent its members again (ADR-0450).
//
// Locking. The tracker owns one `std::mutex`, a strict leaf: no member function calls out while holding it,
// and nothing that holds it takes the runtime mutex (`HomeserverRuntime::mutex`) or any other lock. Callers
// may hold the runtime mutex when they call in, so the order is always runtime mutex, then tracker mutex.
class LazyMemberTracker final
{
public:
    struct Limits final
    {
        // Distinct (user, device, filter) streams. Least recently used is evicted whole.
        std::size_t max_keys{1024U};
        // Rooms remembered for one stream.
        std::size_t max_rooms_per_key{64U};
        // Members remembered for one room of one stream.
        std::size_t max_members_per_room{64U};
        // Members remembered in all; bounds memory whatever the other three allow (1024 * 64 * 64 would not).
        std::size_t max_tracked_members{131072U};
        // A longer `filter` value makes the request untracked.
        std::size_t max_filter_bytes{2048U};
    };

    // One request's identity. The views must outlive the call.
    struct StreamKey final
    {
        std::string_view user_id{};
        std::string_view device_id{};
        std::string_view filter{};
    };

    // A member event a response carried in `state`.
    struct SentMember final
    {
        std::string_view user_id{};
        std::string_view event_id{};
    };

    LazyMemberTracker();
    explicit LazyMemberTracker(Limits limits);
    ~LazyMemberTracker();
    LazyMemberTracker(LazyMemberTracker const&) = delete;
    auto operator=(LazyMemberTracker const&) -> LazyMemberTracker& = delete;
    LazyMemberTracker(LazyMemberTracker&&) = delete;
    auto operator=(LazyMemberTracker&&) -> LazyMemberTracker& = delete;

    // Called once per lazy-loading request that is about to be answered, before any
    // `is_acknowledged`. Without a `since` it deletes everything under the stream; with one it deletes the
    // entries `since` does not cover. A long-poll that waited calls it when it answers, not when it started.
    auto begin_request(StreamKey const& key, std::optional<StreamToken> since) -> void;

    // True when the stream's entry for (room, member) names `event_id` and `since` is at or past its token on
    // all three components: the client holds that very event. False for anything unknown, evicted or stale.
    [[nodiscard]] auto is_acknowledged(StreamKey const& key, std::string_view room_id, std::string_view member_user_id,
                                       std::string_view event_id, StreamToken since) -> bool;

    // Records the members one response carried for `room_id`, under that response's `next_batch`. Does nothing
    // when `next_batch` equals `since`: a client that presents the token it already holds cannot acknowledge
    // anything the response carried. Call it only for members actually sent, and only once the response body
    // is built.
    auto record(StreamKey const& key, std::string_view room_id, std::span<SentMember const> members,
                StreamToken next_batch, std::optional<StreamToken> since) -> void;

    // Introspection for tests and diagnostics.
    [[nodiscard]] auto key_count() const -> std::size_t;
    [[nodiscard]] auto member_count() const -> std::size_t;

private:
    struct State;
    mutable std::mutex mutex_{};
    std::unique_ptr<State> state_;
};

} // namespace merovingian::sync
