// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <optional>
#include <string>
#include <unordered_map>
#include <utility>

namespace merovingian::media
{

// A bounded, least-recently-used cache of preview responses keyed by the
// canonical URL, with a time to live per entry. Failures are cached too, for
// a shorter time, so a URL that cannot be previewed is not fetched again on
// every request. Not thread-safe: guarded by HomeserverRuntime::mutex.
class UrlPreviewCache final
{
public:
    // The index holds iterators into the entry list. A copy would keep the
    // source's iterators, so copies are deleted; a moved std::list keeps its
    // iterators valid, so moves are kept.
    UrlPreviewCache() = default;
    UrlPreviewCache(UrlPreviewCache const&) = delete;
    auto operator=(UrlPreviewCache const&) -> UrlPreviewCache& = delete;
    UrlPreviewCache(UrlPreviewCache&&) = default;
    auto operator=(UrlPreviewCache&&) -> UrlPreviewCache& = default;
    ~UrlPreviewCache() = default;

    struct Entry final
    {
        bool ok{false};
        std::string body{};
        std::uint64_t expires_at_ms{0U};
    };

    // The live entry for `url`, which becomes the most recently used, or
    // nullopt. An expired entry is dropped.
    [[nodiscard]] auto find(std::string const& url, std::uint64_t now_ms) -> std::optional<Entry>;
    // Stores `entry` for `url`, evicting the least recently used entries
    // beyond `max_entries`. A cap of 0 stores nothing.
    auto store(std::string const& url, Entry entry, std::size_t max_entries) -> void;
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    std::list<std::pair<std::string, Entry>> m_entries{};
    std::unordered_map<std::string, std::list<std::pair<std::string, Entry>>::iterator> m_index{};
};

} // namespace merovingian::media
