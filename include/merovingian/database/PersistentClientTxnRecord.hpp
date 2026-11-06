// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// Idempotency record for a client-issued room send or send-to-device PUT.
// Keyed by (user_id, room_id, event_type, txn_id) (device_id is not part of the key: a retry from
// another device of the user is still the same request here); room_id is empty for
// send-to-device entries. event_id holds the stored event ID for room sends
// and is empty for send-to-device (whose response is always {}).
struct PersistentClientTxnRecord final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_type{};
    std::string txn_id{};
    std::string event_id{};
    // The device that made the request, empty for a request with none. Spec (client-server-api.md,
    // ClientEvent `unsigned.transaction_id`): the sending client is given the transaction ID, and a
    // transaction ID is scoped to a device. The idempotency key is (user_id, device_id, room_id,
    // event_type, txn_id): the same txnId from another device is another request (F-52, ADR-0380).
    std::string device_id{};
    // When the record was made, in milliseconds since the epoch; the store stamps it when it is 0.
    // Only a to-device record (room_id empty) is ever aged out (F-54, ADR-0381).
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::database
