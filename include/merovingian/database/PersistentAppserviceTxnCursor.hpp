// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// The Application Service API's (Matrix v1.19) outbound
// `PUT /_matrix/app/v1/transactions/{txnId}` delivery cursor for one
// registered appservice. One row per appservice, keyed on `appservice_id`
// (the registration file's `id`, not a secret). Delivery replays forward
// through the `events` table's `stream_ordering`, so this row -- not a
// separate durable outbox -- is the entire persisted delivery state; see
// `RoomService.cpp`'s appservice dispatch for how it is used:
//   - `next_txn_id`: the next FRESH transaction id to allocate. Monotonic,
//     never reused, so a retried transaction always carries the exact id
//     the appservice may have already partially processed.
//   - `delivered_stream_ordering`: high-water mark. Every event with
//     stream_ordering <= this value has been acknowledged (HTTP 200) by the
//     appservice.
//   - `pending_txn_id` / `pending_stream_ordering`: the currently in-flight
//     (sent, not yet acknowledged) batch, if any. `pending_txn_id == 0`
//     means no batch is in flight. A retry of that SAME batch reuses this
//     id and re-derives the identical event range
//     (delivered_stream_ordering, pending_stream_ordering] rather than
//     growing it -- the spec's "Homeservers MUST NOT alter (e.g. add more)
//     events they were going to send within that transaction ID on
//     retries."
struct PersistentAppserviceTxnCursor final
{
    std::string appservice_id{};
    std::uint64_t next_txn_id{1U};
    std::uint64_t delivered_stream_ordering{0U};
    std::uint64_t pending_txn_id{0U};
    std::uint64_t pending_stream_ordering{0U};
};

} // namespace merovingian::database
