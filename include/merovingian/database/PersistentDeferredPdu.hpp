// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// A federation PDU this server could not yet place in the room's event graph
// (a prev_event, auth_event or the state before it is unknown) and has kept,
// as received, to try again (R03, ADR-0165). `pdu_json` is the exact envelope
// ingestion would have stored, which may be the redacted form after a
// content-hash mismatch. Signatures were verified before the row was written;
// a retry re-enters ingestion after that step. `received_at_ms` is wall-clock
// milliseconds and is kept across attempts; `attempts` counts the retries that
// have not placed the PDU. Written and read by the main process only: the
// federation worker relays every PDU to main and never holds this table.
struct PersistentDeferredPdu final
{
    std::string event_id{};
    std::string room_id{};
    std::string origin{};
    std::string pdu_json{};
    std::int64_t received_at_ms{0};
    std::uint32_t attempts{0U};
};

} // namespace merovingian::database
