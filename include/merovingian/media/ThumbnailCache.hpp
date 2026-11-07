// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/CachedThumbnail.hpp"
#include "merovingian/media/ThumbnailCacheKey.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace merovingian::media
{

// MED-4, ADR-0152: generated thumbnails, bounded by bytes and evicted least
// recently used first. Not thread-safe: it lives in LocalMediaRepository under
// runtime.mutex. Holding an entry authorises nothing: the caller checks the
// record is still servable before serving a hit. Copyable without dangling
// state (no iterators are stored).
class ThumbnailCache final
{
public:
    // A hit becomes the most recently used entry.
    [[nodiscard]] auto find(ThumbnailCacheKey const& key) -> std::optional<CachedThumbnail>;
    // Stores `thumbnail`, evicting the least recently used entries until the
    // cache fits `max_bytes`. A thumbnail that cannot fit on its own, or a
    // budget of 0, stores nothing and evicts nothing.
    auto insert(ThumbnailCacheKey const& key, CachedThumbnail thumbnail, std::uint64_t max_bytes) -> void;
    [[nodiscard]] auto size_bytes() const noexcept -> std::uint64_t;
    [[nodiscard]] auto entry_count() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        CachedThumbnail thumbnail{};
        std::uint64_t cost{0U};
        std::uint64_t last_used{0U};
    };

    std::unordered_map<std::string, Entry> entries_{};
    std::uint64_t bytes_{0U};
    std::uint64_t clock_{0U};
};

} // namespace merovingian::media
