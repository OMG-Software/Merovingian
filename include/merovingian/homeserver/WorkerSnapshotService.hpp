// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/WorkerSnapshotSources.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::homeserver
{

// Main's side of the federation worker's store (C44, ADR-0733, ADR-0735). The worker opens no database: it asks main
// for the room list, each room's snapshot and a server's public keys, and this class answers. A worker may have a room
// read only under a permit main issued on that channel, and each permit is consumed once:
//
// - the room list is read once per channel, at its page 0, and each room it names may be read once (generation 0, the
//   start-up fill);
// - a room_sync main sends for (room, generation) lets the worker read that room once at a generation it was sent and
//   it has not read yet; coalesced reloads of several notifications use one read.
//
// So the reads a compromised worker can cause are bounded by what main lists and notifies, never by what it asks.
//
// Concurrency invariants (each tested deterministically, tests/unit/test_worker_snapshot_service.cpp):
// - A permit is consumed under `mu_` before any read starts, so two requests for one permit give one read.
// - No lock of this class, and never runtime.mutex, is held across a database read: `mu_` is released for the read,
//   and the class has no runtime to lock. The sources read through a store of their own.
// - The read transaction is closed before the first page is sent: `read_room` returns only after its transaction
//   ended, and `answer` returns page 0 after that; the caller sends it.
//
// Thread-safe: `answer` and `permit_reload` may be called from any thread.
class WorkerSnapshotService final
{
public:
    // The identity of a worker's channel: permits and held pages belong to one channel and die with it.
    using ChannelKey = std::shared_ptr<void const>; // SHARED_PTR: reviewed - identity of a live IPC channel.

    // A held snapshot whose next page is not asked for within this is dropped at the next request.
    static constexpr auto held_pages_lifetime = std::chrono::seconds{60};
    // At most this many key rows answer one server_keys request.
    static constexpr auto max_server_key_rows = std::size_t{256U};

    WorkerSnapshotService(WorkerSnapshotSources sources, std::size_t page_budget);

    // Records that main is about to send `channel` a room_sync for `room_id` at `generation`. Call it before the
    // notification is sent, so a worker that reloads at once finds the permit.
    auto permit_reload(ChannelKey const& channel, std::string_view room_id, std::uint64_t generation) -> void;

    // The response body to one worker request frame of `type` (room_list_request, room_snapshot_request or
    // server_keys_request). A request with no permit, out of order or malformed is answered with a refusal and causes
    // no read.
    [[nodiscard]] auto answer(ChannelKey const& channel, std::string_view type, std::string_view json) -> std::string;

    // Whether the worker on `channel` may report `room_id` as left out of its start-up fill: true only for a room in
    // the listing this channel was sent, and at most once per room, so a worker cannot make main record a room main
    // never listed to it (ADR-0756).
    [[nodiscard]] auto consume_fill_omission(ChannelKey const& channel, std::string_view room_id) -> bool;

    // Channels with state held, after dropping those whose channel is gone. For tests.
    [[nodiscard]] auto channels_tracked() -> std::size_t;

private:
    struct HeldPages final
    {
        std::string room_id{};
        std::uint64_t generation{0U};
        std::vector<std::string> pages{};
        std::size_t next_page{0U};
        std::chrono::steady_clock::time_point read_at{};
    };

    struct ReloadPermit final
    {
        std::uint64_t issued{0U};
        std::uint64_t admitted{0U};
    };

    struct ChannelState final
    {
        bool listed{false};
        std::vector<std::string> list_pages{};
        std::size_t next_list_page{0U};
        std::unordered_set<std::string> fill_permits{};
        // The listed rooms the worker has not yet reported as left out of its fill (consume_fill_omission).
        std::unordered_set<std::string> fill_omissions{};
        std::unordered_map<std::string, ReloadPermit> reload_permits{};
        std::optional<HeldPages> held{};
    };

    using ChannelMap = std::map<std::weak_ptr<void const>, ChannelState, std::owner_less<>>;

    [[nodiscard]] auto answer_room_list(ChannelKey const& channel, std::string_view json) -> std::string;
    [[nodiscard]] auto answer_room_snapshot(ChannelKey const& channel, std::string_view json) -> std::string;
    [[nodiscard]] auto answer_server_keys(std::string_view json) const -> std::string;
    // The channel's state, made on first use; drops the state of channels that are gone. Caller holds `mu_`.
    [[nodiscard]] auto state_of(ChannelKey const& channel) -> ChannelState&;

    WorkerSnapshotSources sources_;
    std::size_t page_budget_{0U};
    std::mutex mu_{};
    ChannelMap channels_{};
};

} // namespace merovingian::homeserver
