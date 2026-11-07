// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalRoom.hpp"

#include <atomic>
#include <cstddef>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <vector>

namespace merovingian::homeserver
{

// A cache of the position of each room ID in a `std::vector<LocalRoom>` (ADR-0496, ADR-0521). The first room holding
// an ID wins. The cache is verified, never trusted: it answers only while the row count it indexed equals
// `rooms.size()` and the room at the position carries the requested ID, otherwise `find` scans and rebuilds. A caller
// that edits the vector directly (hydration, a test) therefore loses speed, never correctness.
//
// `find` takes the index's own mutex, so concurrent lookups cannot race on the cache. The lock does not guard the
// vector: a caller must still not edit `rooms` while another thread reads it. Every production caller already holds
// `runtime.mutex`, so the lock is uncontended.
//
// Copying is deleted. Moving yields an empty index, because the cache rebuilds on demand and the positions of another
// vector mean nothing here. Both move operations are `noexcept` and take no lock: they are only valid while no other
// thread uses either object, which holds for a `LocalDatabase` that is moved while it is private to one thread. Move
// assignment never touches the cache (only `find` does, under the lock): it marks the cache stale, and the next `find`
// discards it.
class RoomPositionIndex final
{
public:
    RoomPositionIndex() noexcept = default;
    RoomPositionIndex(RoomPositionIndex const&) = delete;
    auto operator=(RoomPositionIndex const&) -> RoomPositionIndex& = delete;
    RoomPositionIndex(RoomPositionIndex&& /*other*/) noexcept
    {
    }
    // Marks this index stale and leaves `other` alone. No lock is taken (taking one can throw): the caller guarantees
    // that no other thread uses this object while it is assigned to.
    auto operator=(RoomPositionIndex&& /*other*/) noexcept -> RoomPositionIndex&
    {
        stale_.store(true);
        return *this;
    }
    ~RoomPositionIndex() = default;

    // The position in `rooms` of the first room whose ID is `room_id`.
    [[nodiscard]] auto find(std::vector<LocalRoom> const& rooms, std::string_view room_id) const
        -> std::optional<std::size_t>;

private:
    mutable std::mutex mutex_{};
    mutable std::unordered_map<std::string, std::size_t> positions_{};
    mutable std::size_t indexed_rows_{0U};
    // Set by move assignment; `find` discards the cache when it sees it.
    mutable std::atomic<bool> stale_{false};
};

static_assert(std::is_nothrow_default_constructible_v<std::unordered_map<std::string, std::size_t>>);
static_assert(std::is_nothrow_move_constructible_v<RoomPositionIndex> &&
              std::is_nothrow_move_assignable_v<RoomPositionIndex>);

} // namespace merovingian::homeserver
