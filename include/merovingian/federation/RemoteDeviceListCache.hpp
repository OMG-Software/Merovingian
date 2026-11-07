// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/RemoteDeviceList.hpp"
#include "merovingian/federation/RemoteDeviceListOutcome.hpp"
#include "merovingian/federation/RemoteDeviceListUpdate.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// The device lists of remote users who share a joined room with a local user (G14, ADR-0560, ADR-0561).
//
// Spec (SS API, "Device Management"): a server "should populate a local cache" from a query and apply later
// `m.device_list_update` EDUs to it; one "which refers to a prev_id it does not recognise" means it "must
// resynchronise its list". A list is filled from `GET /user/devices/{userId}`, the one answer that carries the
// `stream_id` updates are matched against.
//
// A fill is two steps around a network call made with `runtime.mutex` released: `begin_resync` hands out a ticket,
// and `store_snapshot` keeps the answer only if nothing touched the user's entry in between. An update that arrives
// meanwhile voids the ticket, so a snapshot that may predate it is never kept.
//
// Bounded: at most `max_users` users, `max_devices_per_user` devices and `max_bytes_per_user` bytes per user, and
// `max_total_bytes` in all. A list over a cap is not held, and its user is asked for on every query, as before the
// cache. In memory only: a restart starts empty. Not thread-safe; the caller holds `runtime.mutex`.
class RemoteDeviceListCache final
{
public:
    static constexpr auto max_users = std::size_t{10'000U};
    static constexpr auto max_devices_per_user = std::size_t{512U};
    static constexpr auto max_bytes_per_user = std::size_t{1'048'576U};
    static constexpr auto max_total_bytes = std::size_t{67'108'864U};
    // How many applied update stream IDs are remembered, to recognise a `prev_id` naming one of them.
    static constexpr auto remembered_stream_ids = std::size_t{8U};

    // Starts a fill of the user's list: the entry is stale until `store_snapshot` with this ticket. 0 (no fill may
    // start) when the cache already holds `max_users` other users.
    [[nodiscard]] auto begin_resync(std::string_view user_id) -> std::uint64_t;

    // Keeps `list` as the user's list if `ticket` is still the entry's: no update, staleness or removal came since
    // `begin_resync`. False when it was not kept (ticket void, or a cap exceeded: the entry is then removed).
    [[nodiscard]] auto store_snapshot(std::string_view user_id, std::uint64_t ticket, RemoteDeviceList list) -> bool;

    // Applies one update in sequence order. See RemoteDeviceListOutcome.
    [[nodiscard]] auto apply_update(RemoteDeviceListUpdate const& update) -> RemoteDeviceListOutcome;

    // The user's list can no longer be trusted (an update that could not be read, a cross-signing key change): it
    // is stale until fetched again, and a fill in flight is void. Does nothing for a user not held.
    auto mark_stale(std::string_view user_id) -> void;

    // Forgets the user: they share no room with a local user any more.
    auto erase(std::string_view user_id) -> void;

    // The user's list, or nullptr when it is not held or is stale.
    [[nodiscard]] auto find_current(std::string_view user_id) const -> RemoteDeviceList const*;

    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return m_entries.size();
    }

    [[nodiscard]] auto total_bytes() const noexcept -> std::size_t
    {
        return m_total_bytes;
    }

private:
    struct Entry final
    {
        std::optional<RemoteDeviceList> list{};
        bool stale{true};
        std::uint64_t ticket{0U};
        // The stream_id of the snapshot the list was filled from: every update up to it is in the list.
        std::int64_t snapshot_stream_id{0};
        // The stream IDs of the updates applied since, newest last, at most `remembered_stream_ids`.
        std::vector<std::int64_t> applied{};
        std::size_t bytes{0U};
    };
    using Entries = std::map<std::string, Entry, std::less<>>;

    // Sets the entry's byte count and the total from its list. False (nothing changed) when the list is over a cap.
    [[nodiscard]] auto account(Entries::iterator entry) -> bool;
    auto drop(Entries::iterator entry) -> void;

    Entries m_entries{};
    std::size_t m_total_bytes{0U};
    std::uint64_t m_last_ticket{0U};
};

} // namespace merovingian::federation
