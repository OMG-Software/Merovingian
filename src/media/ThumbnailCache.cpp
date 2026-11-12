// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/ThumbnailCache.hpp"

#include "merovingian/media/CachedThumbnail.hpp"
#include "merovingian/media/ThumbnailCacheKey.hpp"
#include "merovingian/media/ThumbnailMethod.hpp"
#include "merovingian/media/Thumbnailer.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace merovingian::media
{

namespace
{

    // Requested axes past the worker's largest dimension are keyed as that
    // dimension: the worker clamps them, so they are the same thumbnail, and
    // keying them apart would let one client fill the cache with copies.
    [[nodiscard]] auto cache_key(ThumbnailCacheKey const& key) -> std::string
    {
        auto result = key.media_id;
        result += '\0';
        result += key.storage_id;
        result += '\0';
        result += std::to_string(std::min(key.width, max_thumbnail_dimension));
        result += 'x';
        result += std::to_string(std::min(key.height, max_thumbnail_dimension));
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
    // Recency is a second index, so the least recently used entry is the first of it (C29, ADR-0690).
    by_recency_.erase(found->second.last_used);
    found->second.last_used = ++clock_;
    by_recency_.emplace(found->second.last_used, found->first);
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
        by_recency_.erase(existing->second.last_used);
        entries_.erase(existing);
    }
    // Each eviction is the first entry of the recency index: O(log n), not a pass over every entry. The count cap
    // keeps one insert from evicting an unbounded number of tiny entries.
    while (!by_recency_.empty() && (bytes_ + cost > max_bytes || entries_.size() >= max_thumbnail_cache_entries))
    {
        auto const oldest = entries_.find(by_recency_.begin()->second);
        by_recency_.erase(by_recency_.begin());
        if (oldest == entries_.end())
        {
            continue;
        }
        bytes_ -= oldest->second.cost;
        entries_.erase(oldest);
    }
    bytes_ += cost;
    auto const last_used = ++clock_;
    by_recency_.emplace(last_used, name);
    entries_.emplace(std::move(name), Entry{std::move(thumbnail), cost, last_used});
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
