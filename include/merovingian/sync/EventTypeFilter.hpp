// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// Parsed Matrix v1.19 sync filter. A filter selects which events appear in
// each portion of the /sync response. The Matrix `Filter` JSON has nested
// `room` / `presence` / `account_data` filters; we expose the subset the
// alpha homeserver applies: per-event-type allow/deny lists, per-sender
// allow/deny lists, room id allow/deny lists, and a `timeline.limit`.
struct EventTypeFilter final
{
    std::vector<std::string> types{};     // included if non-empty AND matched
    std::vector<std::string> not_types{}; // excluded
    std::vector<std::string> senders{};
    std::vector<std::string> not_senders{};
    std::size_t limit{0U}; // 0 == no cap
    // True when the filter named a `limit`. `limit: 0` then means no events, not no cap (a
    // RoomEventFilter's "maximum number of events to return"); `limit` alone cannot say which.
    bool limit_given{false};
    // RoomEventFilter, Matrix v1.19 CS API § Filtering. When lazy_load_members
    // is set the server may send only the membership events of the senders
    // appearing in the returned events, instead of the room's whole member
    // list; include_redundant_members suppresses the de-duplication the spec
    // otherwise permits across repeat calls. On GET /sync only `room.state`'s
    // flag counts (the spec supports lazy-loading there on the state filter
    // only; the same flag on `room.timeline` is parsed and ignored) and the
    // state filter's types/senders apply to the member events (ADR-0452). On
    // /messages and /context the filter's flag is read from the flat filter.
    bool lazy_load_members{false};
    bool include_redundant_members{false};
    // RoomEventFilter: "If true, enables per-thread notification counts. Only
    // applies to the /sync endpoint." Read from room.timeline.
    bool unread_thread_notifications{false};
    // RoomEventFilter `contains_url`: "If true, includes only events with a url key in
    // their content. If false, excludes those events. If omitted, url key is not considered
    // for filtering."
    std::optional<bool> contains_url{};
};

} // namespace merovingian::sync
