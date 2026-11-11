// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/SendJoinPlanBase.hpp"
#include "merovingian/homeserver/SendJoinPlanStamp.hpp"

#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::homeserver
{

// A bounded, synchronised cache of the room-wide part of send_join answers (ADR-0624), keyed by room and `omit_members`
// and valid for one SendJoinPlanStamp. It also remembers, per stored join, the joiner's membership in the state before
// that join, which never changes because state groups are immutable.
//
// Every member takes the cache's own mutex (ADR-0525). `with_base` holds it across `build` and `use`, so a base can
// never be evicted while it is being read and nothing has to share ownership of one. Lock order: runtime.mutex, then
// this mutex; `build` and `use` must not take runtime.mutex themselves, and the caller already holds it.
class SendJoinPlanCache final
{
public:
    using Build = std::function<SendJoinPlanBase()>;
    using StillValid = std::function<bool(SendJoinPlanBase const&)>;
    using Use = std::function<void(SendJoinPlanBase const&)>;

    static constexpr auto default_max_entries = std::size_t{32U};
    static constexpr auto default_max_bytes = std::uint64_t{64U} * 1024U * 1024U;
    // Enough for every member of any room whose answer can fit the default 64 MiB response cap.
    static constexpr auto default_max_memberships_before = std::size_t{131072U};

    SendJoinPlanCache() = default;
    SendJoinPlanCache(std::size_t max_entries, std::uint64_t max_bytes, std::size_t max_memberships_before) noexcept;
    ~SendJoinPlanCache() = default;

    SendJoinPlanCache(SendJoinPlanCache const&) = delete;
    auto operator=(SendJoinPlanCache const&) -> SendJoinPlanCache& = delete;
    SendJoinPlanCache(SendJoinPlanCache&&) = delete;
    auto operator=(SendJoinPlanCache&&) -> SendJoinPlanCache& = delete;

    // Calls `use` with the base for (room, omit_members): the cached one when its stamp equals `stamp` and
    // `still_valid` accepts it, otherwise one from `build`, which is kept if it fits the budget.
    auto with_base(std::string_view room_id, bool omit_members, SendJoinPlanStamp const& stamp,
                   StillValid const& still_valid, Build const& build, Use const& use) -> void;

    // True when a base with this stamp is cached and is a `sizes_only` refusal.
    [[nodiscard]] auto known_not_to_fit(std::string_view room_id, bool omit_members, SendJoinPlanStamp const& stamp)
        -> bool;

    // The event ID of the joiner's membership in the state before the stored join `join_event_id` of `room_id` (empty
    // for none), if remembered.
    [[nodiscard]] auto membership_before(std::string_view room_id, std::string_view join_event_id)
        -> std::optional<std::string>;
    auto remember_membership_before(std::string_view room_id, std::string_view join_event_id,
                                    std::string_view membership_event_id) -> void;

    // How many bases have been built, entries held and their estimated bytes. For tests and metrics.
    [[nodiscard]] auto builds() const -> std::uint64_t;
    [[nodiscard]] auto entries() const -> std::size_t;
    [[nodiscard]] auto bytes() const -> std::uint64_t;

private:
    struct Entry final
    {
        std::string key{};
        SendJoinPlanStamp stamp{};
        SendJoinPlanBase base{};
        std::uint64_t bytes{0U};
    };

    struct NameHash final
    {
        using is_transparent = void;
        [[nodiscard]] auto operator()(std::string_view name) const noexcept -> std::size_t
        {
            return std::hash<std::string_view>{}(name);
        }
    };

    using EntryList = std::list<Entry>;

    auto drop_locked(EntryList::iterator position) -> void;

    std::size_t m_max_entries{default_max_entries};
    std::uint64_t m_max_bytes{default_max_bytes};
    std::size_t m_max_memberships_before{default_max_memberships_before};

    mutable std::mutex m_mutex{};
    // Most recently used first.
    EntryList m_entries{};
    std::unordered_map<std::string, EntryList::iterator, NameHash, std::equal_to<>> m_index{};
    std::uint64_t m_bytes{0U};
    std::uint64_t m_builds{0U};
    std::unordered_map<std::string, std::string, NameHash, std::equal_to<>> m_memberships_before{};
    std::deque<std::string> m_memberships_order{};
};

} // namespace merovingian::homeserver
