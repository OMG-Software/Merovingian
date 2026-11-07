// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/sync/UnreadEventOutcome.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::database
{
struct PersistentEvent;
} // namespace merovingian::database

namespace merovingian::sync
{

// Decides, for one user and one request, which events count towards unread notifications
// (R15, ADR-0205). count_unread_by_thread() asks it about every unread event; the homeserver's
// implementation (homeserver::PushRuleUnreadClassifier) evaluates the user's push rules. Build one
// per request and reuse it across rooms: an implementation may cache per-room facts, so its
// questions are not `const` and it is not safe to share between threads.
class UnreadEventClassifier
{
public:
    UnreadEventClassifier() = default;
    virtual ~UnreadEventClassifier() = default;
    UnreadEventClassifier(UnreadEventClassifier const&) = delete;
    UnreadEventClassifier(UnreadEventClassifier&&) = delete;
    auto operator=(UnreadEventClassifier const&) -> UnreadEventClassifier& = delete;
    auto operator=(UnreadEventClassifier&&) -> UnreadEventClassifier& = delete;

    // Only events after this stream position in `room_id` are counted; nullopt counts none.
    [[nodiscard]] virtual auto counted_after(std::string_view room_id) -> std::optional<std::uint64_t> = 0;

    // Whether the user may see `event` at all. An event the timeline withholds (history visibility,
    // a backfilled event from before the user's join) is never unread.
    [[nodiscard]] virtual auto visible(database::PersistentEvent const& event) -> bool = 0;

    // What `event` (a client-format event object of `room_id`) counts as.
    [[nodiscard]] virtual auto classify(std::string_view room_id, canonicaljson::Value const& event)
        -> UnreadEventOutcome = 0;
};

} // namespace merovingian::sync
