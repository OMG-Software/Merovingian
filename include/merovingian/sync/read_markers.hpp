// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// The thread ID of the main timeline (Client-Server API, "Threaded read receipts"): "When
// referring to the main timeline as a thread (e.g. in receipts and notifications counts) a
// special thread ID of `main` is used."
inline constexpr auto main_thread_id = std::string_view{"main"};

// Where one user has read up to in one room, from their m.read and m.read.private receipts.
//
// Spec (Client-Server API, "Marking notifications as read"): notifications up to and including
// the receipted event are read, the more recent of m.read and m.read.private counts, and "When
// handling threaded read receipts, the server is to partition the notification count to each
// thread (with the main timeline being its own thread)". An unthreaded receipt covers every
// event up to it, in a thread or not ("An unthreaded read receipt on D would mark A, B, C, and D
// as read"); a threaded one covers only its own thread's events up to it.
struct ReadMarkers final
{
    // Stream ordering of the latest event an unthreaded receipt covers; 0 when there is none.
    std::uint64_t unthreaded{0U};
    // Per thread (`main` or a thread root's event ID): stream ordering of the latest event a
    // threaded receipt covers.
    std::map<std::string, std::uint64_t, std::less<>> threads{};

    // True when the event at `stream_ordering`, in thread `thread_id`, has been read.
    [[nodiscard]] auto covers(std::uint64_t stream_ordering, std::string_view thread_id) const noexcept -> bool;
};

// The user's read markers in `room_id`, from `receipts`, with stream orderings looked up in
// `store`. A receipt naming an event `store` does not hold covers nothing. Each non-state event
// the user sent in the room also reads its own thread up to itself (spec: the read receipt is
// updated "either by using the API or by sending an event"; ADR-0170).
[[nodiscard]] auto read_markers_for(std::vector<database::PersistentReceipt> const& receipts,
                                    database::PersistentStore const& store, std::string_view room_id,
                                    std::string_view user) -> ReadMarkers;

// The thread `event` belongs to: the root's event ID, or `main`. Spec (Client-Server API,
// "Threaded read receipts"): an event is in a thread if "It has a rel_type of m.thread, or
// Following the event relationships, it has a parent event which references the thread root
// with a rel_type of m.thread"; "a maximum of 3 hops is recommended". Thread roots, and events
// related to them by other relations, are in the main timeline. Parents are looked up in
// `store`; a parent it does not hold ends the search in the main timeline.
[[nodiscard]] auto event_thread_id(database::PersistentStore const& store, canonicaljson::Object const& event)
    -> std::string;

} // namespace merovingian::sync
