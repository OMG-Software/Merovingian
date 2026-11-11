// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentForwardExtremity.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// `forward_extremities`: a room's tips, found by event and counted by the server of each tip's sender without a scan
// (ADR-0602). The class owns the rows, so a writer that bypasses it does not compile and the per-server counts cannot
// drift from the tips (ADR-0325). The table has no lock: a reader needs exclusion from writers (`runtime.mutex`).
class ForwardExtremityTable final
{
public:
    using size_type = std::size_t;

    // The server part of a user ID: what follows its first colon, or empty when it has none.
    [[nodiscard]] static auto server_of_sender(std::string_view sender_user_id) noexcept -> std::string_view;

    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return size_;
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return size_ == 0U;
    }

    // Every row, room by room. A copy for tests and tools; a handler asks for one room.
    [[nodiscard]] auto rows() const -> std::vector<PersistentForwardExtremity>;
    // `room_id`'s tips, oldest first. Costs the room's own tips.
    [[nodiscard]] auto tips_of_room(std::string_view room_id) const -> std::vector<std::string>;
    [[nodiscard]] auto contains(std::string_view room_id, std::string_view event_id) const -> bool;
    [[nodiscard]] auto count_for_room(std::string_view room_id) const -> size_type;
    // How many of `room_id`'s tips were sent from the server of `sender_user_id`. A hash lookup.
    [[nodiscard]] auto count_for_sender_server(std::string_view room_id, std::string_view sender_user_id) const
        -> size_type;

    // Adds a tip sent by `sender_user_id`. False, and nothing changes, when the room already holds it.
    auto insert(PersistentForwardExtremity row, std::string_view sender_user_id) -> bool;
    // Removes a tip. False when the room does not hold it.
    auto erase(std::string_view room_id, std::string_view event_id) -> bool;
    auto erase_room(std::string_view room_id) -> void;
    // Charges every tip again to the server `sender_of` names. Hydration reads the tips before the events are indexed.
    auto recount_servers(std::function<std::string(std::string_view event_id)> const& sender_of) -> void;
    auto clear() noexcept -> void;

private:
    using CountByServer = std::unordered_map<std::string, size_type, detail::StateGroupKeyHash, std::equal_to<>>;

    struct Tip final
    {
        std::uint64_t sequence{0U};
        std::string server{};
    };

    struct RoomTips final
    {
        // Insertion order, so a room's tips keep the order they arrived in.
        std::map<std::uint64_t, std::string> in_order{};
        std::unordered_map<std::string, Tip, detail::StateGroupKeyHash, std::equal_to<>> by_event{};
        CountByServer by_server{};
    };

    static auto charge(CountByServer& counts, std::string const& server) -> void;
    static auto refund(CountByServer& counts, std::string const& server) -> void;

    std::unordered_map<std::string, RoomTips, detail::StateGroupKeyHash, std::equal_to<>> rooms_{};
    std::uint64_t next_sequence_{0U};
    size_type size_{0U};
};

} // namespace merovingian::database
