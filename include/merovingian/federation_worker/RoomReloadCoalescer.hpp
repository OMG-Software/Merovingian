// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::federation_worker
{

// Merges a room's `room_sync` notifications into a bounded number of reloads (ADR-0623). One accepted PDU is one
// notification, and a reload re-reads the whole room, so a reload per notification let a remote server decide how much
// reloading a shard does.
//
// The invariant, which every change here must keep: a reload that STARTS after a notification was recorded sees the
// change that notification announces. Main commits an event before it sends the notification, and the reload's database
// read begins after `run_round` has cleared `dirty`. So:
//
//   * a notification recorded before a round clears `dirty` is covered by that round's read;
//   * a notification recorded after it may have been missed by the read, and it finds the room scheduled and sets
//     `dirty` again, so `run_round` answers true and another round follows.
//
// The last notification of a burst is therefore always followed by a round whose read began after it. A room is
// scheduled at most once at any moment, so a burst of any length arriving during one round costs one more round.
//
// Thread-safe. The mutex covers only this table: `reload` runs with it released, and the caller holds none of the
// store's locks across a round (ADR-0360).
class RoomReloadCoalescer final
{
public:
    RoomReloadCoalescer() = default;
    ~RoomReloadCoalescer() = default;

    RoomReloadCoalescer(RoomReloadCoalescer const&) = delete;
    auto operator=(RoomReloadCoalescer const&) -> RoomReloadCoalescer& = delete;
    RoomReloadCoalescer(RoomReloadCoalescer&&) = delete;
    auto operator=(RoomReloadCoalescer&&) -> RoomReloadCoalescer& = delete;

    // Records that `room_id` changed, up to main's `generation`. True when the room was not scheduled: the caller must
    // now schedule one `run_round` for it (or call `abandon`). False when a round already scheduled or running covers
    // it.
    [[nodiscard]] auto note_changed(std::string_view room_id, std::uint64_t generation) -> bool;

    // Runs one round: clears `dirty`, then calls `reload` with the newest generation recorded so far, then looks at
    // `dirty` again. True when a notification arrived during the round: the caller must schedule another round (or
    // call `abandon`). False when the room is done and no longer scheduled. An exception from `reload` ends the round
    // as a finished one and does not propagate, so a room can never be left scheduled with nothing to run it.
    [[nodiscard]] auto run_round(std::string const& room_id, std::function<void(std::uint64_t)> const& reload) -> bool;

    // Forgets a room whose round could not be scheduled because the worker is stopping.
    auto abandon(std::string_view room_id) -> void;

    // Rooms scheduled or running.
    [[nodiscard]] auto scheduled_rooms() const -> std::size_t;

private:
    struct Scheduled final
    {
        std::uint64_t newest_generation{0U};
        bool dirty{false};
    };

    struct NameHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view name) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(name);
        }
    };

    mutable std::mutex m_mutex{};
    std::unordered_map<std::string, Scheduled, NameHash, std::equal_to<>> m_rooms{};
};

} // namespace merovingian::federation_worker
