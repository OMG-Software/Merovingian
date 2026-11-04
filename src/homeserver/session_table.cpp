// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/session_table.hpp"

#include <chrono>
#include <cstddef>
#include <string>
#include <utility>

namespace merovingian::homeserver
{

auto SessionTable::reserve(std::size_t capacity) -> void
{
    sessions_.reserve(capacity);
    index_.reserve(capacity);
}

auto SessionTable::push_back(LocalSession session) -> void
{
    auto const key = digest(session.access_token_hash);
    sessions_.push_back(std::move(session));
    index_.emplace(key, sessions_.size() - 1U);
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
    index_.reserve(sessions_.size());
    for (auto position = std::size_t{0U}; position < sessions_.size(); ++position)
    {
        index_.emplace(digest(sessions_[position].access_token_hash), position);
    }
}

} // namespace merovingian::homeserver
