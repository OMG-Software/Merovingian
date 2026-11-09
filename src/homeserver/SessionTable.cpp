// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/SessionTable.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

auto SessionTable::reserve(std::size_t capacity) -> void
{
    sessions_.reserve(capacity);
    index_.reserve(capacity);
}

auto SessionTable::device_key(std::string_view user_id, std::string_view device_id) -> std::string
{
    auto key = std::to_string(user_id.size());
    key += ':';
    key += user_id;
    key += device_id;
    return key;
}

auto SessionTable::index_session(std::size_t position) -> void
{
    auto const& session = sessions_[position];
    index_.emplace(digest(session.access_token_hash), position);
    device_index_[device_key(session.user_id, session.device_id)].push_back(position);
}

auto SessionTable::unindex_session(std::size_t position) -> void
{
    auto const& session = sessions_[position];
    auto const [first, last] = index_.equal_range(digest(session.access_token_hash));
    for (auto entry = first; entry != last; ++entry)
    {
        if (entry->second == position)
        {
            index_.erase(entry);
            break;
        }
    }
    auto const found = device_index_.find(device_key(session.user_id, session.device_id));
    if (found != device_index_.end())
    {
        std::erase(found->second, position);
        if (found->second.empty())
        {
            device_index_.erase(found);
        }
    }
}

auto SessionTable::push_back(LocalSession session) -> void
{
    sessions_.push_back(std::move(session));
    index_session(sessions_.size() - 1U);
}

auto SessionTable::erase_device(std::string_view user_id, std::string_view device_id) -> std::size_t
{
    auto const found = device_index_.find(device_key(user_id, device_id));
    if (found == device_index_.end())
    {
        return 0U;
    }
    // Highest position first, so the session that fills a hole is never one still waiting to go.
    auto positions = found->second;
    std::ranges::sort(positions, std::greater<>{});
    for (auto const position : positions)
    {
        unindex_session(position);
        auto const last = sessions_.size() - 1U;
        if (position != last)
        {
            unindex_session(last);
            sessions_[position] = std::move(sessions_[last]);
            index_session(position);
        }
        sessions_.pop_back();
    }
    return positions.size();
}

auto SessionTable::set_access_token_hash(LocalSession& session, std::string hash) -> void
{
    auto position = std::size_t{0U};
    while (position < sessions_.size() && &sessions_[position] != &session)
    {
        ++position;
    }
    if (position == sessions_.size())
    {
        return;
    }
    auto const [first, last] = index_.equal_range(digest(session.access_token_hash));
    for (auto entry = first; entry != last; ++entry)
    {
        if (entry->second == position)
        {
            index_.erase(entry);
            break;
        }
    }
    session.access_token_hash = std::move(hash);
    index_.emplace(digest(session.access_token_hash), position);
}

auto SessionTable::rebuild_index() -> void
{
    index_.clear();
    device_index_.clear();
    index_.reserve(sessions_.size());
    for (auto position = std::size_t{0U}; position < sessions_.size(); ++position)
    {
        index_session(position);
    }
}

} // namespace merovingian::homeserver
