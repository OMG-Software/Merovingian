// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace merovingian::homeserver
{

// Thread-safe cache for the signed /_matrix/key/v2/server response.
// Uses its own mutex so the response can be served without holding the
// global runtime mutex — Synapse's ServerKeyFetcher times out (~20 s)
// if a concurrent make_join round-trip holds the lock for too long.
// Wrapped in unique_ptr by callers so containing structs stay moveable.
struct KeyServerCache final
{
    // Returns the cached response, or nullopt if the cache is empty or the
    // document is due for re-publication. `now_ms` is the current wall clock in
    // milliseconds. Staleness matters because the cached document carries a
    // valid_until_ts: a server that keeps serving one document forever ends up
    // advertising a window that has already elapsed, and peers then reject every
    // signature it makes. Returning nullopt sends the caller down the slow path,
    // which re-publishes and re-fills the cache.
    [[nodiscard]] auto load(std::uint64_t now_ms) const -> std::optional<std::string>
    {
        auto const lk = std::lock_guard{mutex_};
        if (value_.empty() || now_ms > refresh_after_ms_)
        {
            return std::nullopt;
        }
        return value_;
    }

    // Atomically replaces the cached response. `refresh_after_ms` is the wall
    // clock after which the document must be re-published before it is served
    // again.
    auto store(std::string value, std::uint64_t refresh_after_ms) -> void
    {
        auto const lk = std::lock_guard{mutex_};
        value_ = std::move(value);
        refresh_after_ms_ = refresh_after_ms;
    }

private:
    mutable std::mutex mutex_{};
    std::string value_{};
    std::uint64_t refresh_after_ms_{0U};
};

} // namespace merovingian::homeserver
