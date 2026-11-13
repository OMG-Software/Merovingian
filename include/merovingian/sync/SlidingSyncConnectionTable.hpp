// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/SlidingSyncConnectionState.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::sync
{

// The sliding sync connections of every user, with an index of them ordered by `last_used` (ADR-0663), so a request
// finds the idle ones at the front of the index instead of walking every connection of every user. Every change goes
// through `touch`, `erase` or `erase_idle`, which keep the map and the index equal; `states()` is read-only.
// Not thread-safe: the owner guards it with the runtime mutex.
class SlidingSyncConnectionTable final
{
public:
    // The state under `key`, created when absent, stamped `now` and moved to its place in the index.
    [[nodiscard]] auto touch(std::string const& key, std::chrono::steady_clock::time_point now)
        -> SlidingSyncConnectionState&;

    // Removes `key` from the map and the index; a key that is not held is ignored.
    auto erase(std::string const& key) -> void;

    // Removes every connection idle for longer than `ttl`, popping them from the front of the index and stopping at the
    // first that is not. Work is the connections removed plus one.
    auto erase_idle(std::chrono::steady_clock::time_point now, std::chrono::steady_clock::duration ttl) -> void;

    [[nodiscard]] auto contains(std::string const& key) const -> bool;
    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto empty() const noexcept -> bool;

    // The connections by key, for a walk of one device's key range. Read-only.
    [[nodiscard]] auto states() const noexcept -> std::map<std::string, SlidingSyncConnectionState> const&;

    // Index entries `erase_idle` has looked at, in total, and the index's size: a test proves cost by count.
    [[nodiscard]] auto idle_entries_visited() const noexcept -> std::uint64_t;
    [[nodiscard]] auto index_size() const noexcept -> std::size_t;

private:
    std::map<std::string, SlidingSyncConnectionState> m_states{};
    // (last_used, key) of every connection in `m_states`, oldest first.
    std::set<std::pair<std::chrono::steady_clock::time_point, std::string>> m_by_last_used{};
    std::uint64_t m_idle_entries_visited{0U};
};

} // namespace merovingian::sync
