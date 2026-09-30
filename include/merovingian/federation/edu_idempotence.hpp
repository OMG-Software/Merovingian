// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_set>

namespace merovingian::federation
{

// Bounded, in-memory replay window for `m.direct_to_device` message IDs.
//
// Spec: SS API v1.19, "Send-to-device messaging" — `message_id` is "Unique ID
// for the message, used for idempotence. Arbitrary utf8 string, of maximum
// length 32 codepoints."
//
// An entry is keyed on (origin, message_id), so one server can neither
// suppress nor replay another server's messages. The window holds at most
// `capacity` entries; an entry older than `lifetime` is forgotten, and when the
// window is full the oldest entry is evicted first. The window is NOT
// persisted: a restart forgets it, so a replay that straddles a restart is
// delivered again. That is deliberate — persisting it would need a migration,
// and the window only exists to make a re-sent transaction idempotent.
//
// Not thread-safe; the caller holds the runtime mutex.
class EduIdempotenceWindow final
{
public:
    using Clock = std::chrono::steady_clock;

    static constexpr auto default_capacity = std::size_t{65536U};
    static constexpr auto default_lifetime = std::chrono::hours{24};

    explicit EduIdempotenceWindow(std::size_t capacity = default_capacity,
                                  Clock::duration lifetime = default_lifetime) noexcept
        : capacity_{capacity}
        , lifetime_{lifetime}
    {
    }

    // Records (origin, message_id) at `now` and returns true if it had not been
    // seen inside the window (the caller should process the EDU). Returns false
    // for a replay (the caller must drop it).
    [[nodiscard]] auto first_sighting(std::string_view origin, std::string_view message_id,
                                      Clock::time_point now) -> bool;

    [[nodiscard]] auto size() const noexcept -> std::size_t
    {
        return order_.size();
    }

private:
    struct Entry final
    {
        std::string key{};
        Clock::time_point seen_at{};
    };

    std::size_t capacity_;
    Clock::duration lifetime_;
    std::deque<Entry> order_{};
    std::unordered_set<std::string> keys_{};
};

// True if `message_id` is a usable `m.direct_to_device` message ID: non-empty
// and at most 32 UTF-8 codepoints, as the spec requires.
[[nodiscard]] auto direct_to_device_message_id_is_valid(std::string_view message_id) noexcept -> bool;

} // namespace merovingian::federation
