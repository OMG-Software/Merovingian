// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/ForwardExtremityTable.hpp"

#include "merovingian/database/PersistentForwardExtremity.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::database
{

auto ForwardExtremityTable::server_of_sender(std::string_view sender_user_id) noexcept -> std::string_view
{
    auto const colon = sender_user_id.find(':');
    return colon == std::string_view::npos ? std::string_view{} : sender_user_id.substr(colon + 1U);
}

auto ForwardExtremityTable::rows() const -> std::vector<PersistentForwardExtremity>
{
    auto result = std::vector<PersistentForwardExtremity>{};
    result.reserve(size_);
    for (auto const& [room_id, room] : rooms_)
    {
        for (auto const& [sequence, event_id] : room.in_order)
        {
            result.push_back({room_id, event_id});
        }
    }
    return result;
}

auto ForwardExtremityTable::tips_of_room(std::string_view room_id) const -> std::vector<std::string>
{
    auto tips = std::vector<std::string>{};
    auto const found = rooms_.find(room_id);
    if (found == rooms_.end())
    {
        return tips;
    }
    tips.reserve(found->second.in_order.size());
    for (auto const& [sequence, event_id] : found->second.in_order)
    {
        tips.push_back(event_id);
    }
    return tips;
}

auto ForwardExtremityTable::contains(std::string_view room_id, std::string_view event_id) const -> bool
{
    auto const found = rooms_.find(room_id);
    return found != rooms_.end() && found->second.by_event.contains(event_id);
}

auto ForwardExtremityTable::count_for_room(std::string_view room_id) const -> size_type
{
    auto const found = rooms_.find(room_id);
    return found == rooms_.end() ? size_type{0U} : found->second.by_event.size();
}

auto ForwardExtremityTable::count_for_sender_server(std::string_view room_id, std::string_view sender_user_id) const
    -> size_type
{
    auto const room = rooms_.find(room_id);
    if (room == rooms_.end())
    {
        return 0U;
    }
    auto const server = room->second.by_server.find(server_of_sender(sender_user_id));
    return server == room->second.by_server.end() ? size_type{0U} : server->second;
}

auto ForwardExtremityTable::charge(CountByServer& counts, std::string const& server) -> void
{
    ++counts[server];
}

auto ForwardExtremityTable::refund(CountByServer& counts, std::string const& server) -> void
{
    auto const found = counts.find(server);
    if (found == counts.end())
    {
        return;
    }
    --found->second;
    if (found->second == 0U)
    {
        counts.erase(found);
    }
}

auto ForwardExtremityTable::insert(PersistentForwardExtremity row, std::string_view sender_user_id) -> bool
{
    auto found = rooms_.find(row.room_id);
    if (found == rooms_.end())
    {
        found = rooms_.emplace(row.room_id, RoomTips{}).first;
    }
    auto& room = found->second;
    if (room.by_event.contains(row.event_id))
    {
        return false;
    }
    auto const sequence = next_sequence_++;
    auto server = std::string{server_of_sender(sender_user_id)};
    charge(room.by_server, server);
    room.by_event.emplace(row.event_id, Tip{sequence, std::move(server)});
    room.in_order.emplace(sequence, std::move(row.event_id));
    ++size_;
    return true;
}

auto ForwardExtremityTable::erase(std::string_view room_id, std::string_view event_id) -> bool
{
    auto const found = rooms_.find(room_id);
    if (found == rooms_.end())
    {
        return false;
    }
    auto& room = found->second;
    auto const tip = room.by_event.find(event_id);
    if (tip == room.by_event.end())
    {
        return false;
    }
    refund(room.by_server, tip->second.server);
    room.in_order.erase(tip->second.sequence);
    room.by_event.erase(tip);
    --size_;
    if (room.by_event.empty())
    {
        rooms_.erase(found);
    }
    return true;
}

auto ForwardExtremityTable::erase_room(std::string_view room_id) -> void
{
    auto const found = rooms_.find(room_id);
    if (found == rooms_.end())
    {
        return;
    }
    size_ -= found->second.by_event.size();
    rooms_.erase(found);
}

auto ForwardExtremityTable::recount_servers(std::function<std::string(std::string_view event_id)> const& sender_of)
    -> void
{
    for (auto& [room_id, room] : rooms_)
    {
        room.by_server.clear();
        for (auto& [event_id, tip] : room.by_event)
        {
            tip.server = std::string{server_of_sender(sender_of(event_id))};
            charge(room.by_server, tip.server);
        }
    }
}

auto ForwardExtremityTable::clear() noexcept -> void
{
    rooms_.clear();
    next_sequence_ = 0U;
    size_ = 0U;
}

} // namespace merovingian::database
