// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::federation
{

// Bounded, in-memory replay window for `m.direct_to_device` message IDs.
//
// Spec: SS API v1.19, "Send-to-device messaging" - `message_id` is "Unique ID
// for the message, used for idempotence. Arbitrary utf8 string, of maximum
// length 32 codepoints."
//
// An entry is keyed on (origin, sender, message_id), so one server can neither
// suppress nor replay another server's messages, and a sending server whose
// IDs are only unique per sender cannot have one user's message dropped as a
// replay of another's. The window holds at most `capacity` entries; an entry
// older than `lifetime` is forgotten, and when the window is full the oldest
// entry is evicted first. The window is NOT persisted: a restart forgets it,
// so a replay that straddles a restart is delivered again. That is deliberate -
// persisting it would need a migration, and the window only exists to make a
// re-sent transaction idempotent.
//
// Looking an ID up (`seen`) and remembering it (`record`) are separate steps so
// the caller can store the EDU's messages in between and remember the ID only
// once they are durable; an ID recorded before a failed store would make the
// origin's resend look like a replay and lose the messages.
//
// Not thread-safe; the caller holds the runtime mutex across seen -> store ->
// record.
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

    // True if (origin, sender, message_id) was recorded inside the window at
    // `now`, i.e. the EDU is a replay and must be dropped. Changes nothing.
    [[nodiscard]] auto seen(std::string_view origin, std::string_view sender, std::string_view message_id,
                            Clock::time_point now) const -> bool;

    // Remembers (origin, sender, message_id) at `now`, first forgetting expired
    // entries and, when the window is full, evicting the oldest. Recording an ID
    // that is already in the window changes nothing.
    auto record(std::string_view origin, std::string_view sender, std::string_view message_id, Clock::time_point now)
        -> void;

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
    std::unordered_map<std::string, Clock::time_point> keys_{};
};

// True if `message_id` is a usable `m.direct_to_device` message ID: non-empty
// and at most 32 UTF-8 codepoints, as the spec requires.
[[nodiscard]] auto direct_to_device_message_id_is_valid(std::string_view message_id) noexcept -> bool;

// The `message_id` a sending server puts on the `m.direct_to_device` EDU for a
// client's `PUT /sendToDevice/{eventType}/{txnId}` request.
//
// Client transaction IDs are only unique per user, and may be longer than the
// 32 codepoints the spec allows, so the raw txn id is not a usable message_id.
// The ID is instead a hash of (sender, event type, txn id): the same request
// always yields the same ID (a client retry is recognised as a replay by the
// receiver), two senders never share one, and it is always 24 characters of
// URL-safe base64. Each input is length-prefixed before hashing, so no shift of
// bytes between them can collide. Returns std::nullopt if hashing fails.
[[nodiscard]] auto derive_direct_to_device_message_id(std::string_view sender, std::string_view event_type,
                                                      std::string_view txn_id) -> std::optional<std::string>;

} // namespace merovingian::federation
