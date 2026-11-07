// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/UrlPreviewCache.hpp"

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <string>
#include <utility>

namespace merovingian::media
{

auto UrlPreviewCache::find(std::string const& url, std::uint64_t now_ms) -> std::optional<Entry>
{
    auto const found = m_index.find(url);
    if (found == m_index.end())
    {
        return std::nullopt;
    }
    if (found->second->second.expires_at_ms <= now_ms)
    {
        m_entries.erase(found->second);
        m_index.erase(found);
        return std::nullopt;
    }
    m_entries.splice(m_entries.end(), m_entries, found->second);
    return found->second->second;
}

auto UrlPreviewCache::store(std::string const& url, Entry entry, std::size_t max_entries) -> void
{
    if (max_entries == 0U)
    {
        return;
    }
    if (auto const found = m_index.find(url); found != m_index.end())
    {
        m_entries.erase(found->second);
        m_index.erase(found);
    }
    while (m_entries.size() >= max_entries)
    {
        m_index.erase(m_entries.front().first);
        m_entries.pop_front();
    }
    m_entries.emplace_back(url, std::move(entry));
    m_index.emplace(url, std::prev(m_entries.end()));
}

auto UrlPreviewCache::size() const noexcept -> std::size_t
{
    return m_entries.size();
}

} // namespace merovingian::media
