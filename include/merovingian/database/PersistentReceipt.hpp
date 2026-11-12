// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::database
{

// The `thread_id` of the main timeline (Client-Server API, "Threaded read receipts"). `sync::main_thread_id` is this.
inline constexpr auto main_receipt_thread_id = std::string_view{"main"};

// The most receipt rows with a thread root's event ID as `thread_id` (neither empty nor `main`) one user holds in one
// room (ADR-0651). A threaded receipt past it replaces the user's own oldest such row.
inline constexpr std::size_t max_threaded_receipt_rows_per_user_room = 256U;

// A read receipt (Client-Server API, "Receipts"): the event `user_id` has read
// up to in `room_id`. One row per (room_id, receipt_type, user_id, thread_id):
// spec, "Each user_id, receipt_type, and categorisation (unthreaded, or
// thread_id) tuple must be associated with only a single event_id".
// `thread_id` is empty for an unthreaded receipt, `main` for the main
// timeline, or a thread root's event ID. `stream_id` is the sync stream
// position at which the receipt was last set. Persisted in `receipts`, because
// unread counts are computed from these rows and losing them on a restart
// marks every room unread again.
struct PersistentReceipt final
{
    std::string room_id{};
    std::string receipt_type{"m.read"};
    std::string user_id{};
    std::string event_id{};
    std::uint64_t ts{0U};
    std::uint64_t stream_id{0U};
    std::string thread_id{};
};

} // namespace merovingian::database
