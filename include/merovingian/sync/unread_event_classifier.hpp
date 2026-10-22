// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <optional>
#include <string_view>

namespace merovingian::sync
{

// What one unread event counts as. Spec (client-server-api.md, "Receiving notifications"):
// "Notifications are determined by the push rules which apply to an event", and
// `highlight_count` is "The number of unread notifications for this room with the highlight flag
// set", so `highlight` implies `notify`.
struct UnreadEventOutcome final
{
    bool notify{false};
    bool highlight{false};
};

// Decides, for one user and one request, which events count towards unread notifications
// (R15, ADR-0205). count_unread_by_thread() asks it about every unread event; the homeserver's
// implementation (homeserver::PushRuleUnreadClassifier) evaluates the user's push rules. Build one
// per request and reuse it across rooms: an implementation may cache per-room facts, so it is not
// safe to share between threads.
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
    [[nodiscard]] virtual auto counted_after(std::string_view room_id) const -> std::optional<std::uint64_t> = 0;

    // Whether the user may see `event` at all. An event the timeline withholds (history visibility,
    // a backfilled event from before the user's join) is never unread.
    [[nodiscard]] virtual auto visible(database::PersistentEvent const& event) const -> bool = 0;

    // What `event` (a client-format event object of `room_id`) counts as.
    [[nodiscard]] virtual auto classify(std::string_view room_id, canonicaljson::Value const& event) const
        -> UnreadEventOutcome = 0;
};

} // namespace merovingian::sync
