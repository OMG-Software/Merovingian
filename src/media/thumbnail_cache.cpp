// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/thumbnail_cache.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace merovingian::media
{

namespace
{

    [[nodiscard]] auto cache_key(ThumbnailCacheKey const& key) -> std::string
    {
        auto result = key.media_id;
        result += '\0';
        result += key.storage_id;
        result += '\0';
        result += std::to_string(key.width);
        result += 'x';
        result += std::to_string(key.height);
        result += key.method == ThumbnailMethod::crop ? "/crop" : "/scale";
        return result;
    }

} // namespace

auto ThumbnailCache::find(ThumbnailCacheKey const& key) -> std::optional<CachedThumbnail>
{
    auto const found = entries_.find(cache_key(key));
    if (found == entries_.end())
    {
        return std::nullopt;
    }
    found->second.last_used = ++clock_;
    return found->second.thumbnail;
}

auto ThumbnailCache::insert(ThumbnailCacheKey const& key, CachedThumbnail thumbnail, std::uint64_t max_bytes) -> void
{
    auto name = cache_key(key);
    auto const cost = static_cast<std::uint64_t>(name.size() + thumbnail.content_type.size() + thumbnail.bytes.size());
    if (max_bytes == 0U || cost > max_bytes)
    {
        return;
    }
    if (auto const existing = entries_.find(name); existing != entries_.end())
    {
        bytes_ -= existing->second.cost;
        entries_.erase(existing);
    }
    while (!entries_.empty() && bytes_ + cost > max_bytes)
    {
        auto const oldest = std::ranges::min_element(entries_, {}, [](auto const& entry) {
            return entry.second.last_used;
        });
        bytes_ -= oldest->second.cost;
        entries_.erase(oldest);
    }
    bytes_ += cost;
    entries_.emplace(std::move(name), Entry{std::move(thumbnail), cost, ++clock_});
}

auto ThumbnailCache::size_bytes() const noexcept -> std::uint64_t
{
    return bytes_;
}

auto ThumbnailCache::entry_count() const noexcept -> std::size_t
{
    return entries_.size();
}

} // namespace merovingian::media
