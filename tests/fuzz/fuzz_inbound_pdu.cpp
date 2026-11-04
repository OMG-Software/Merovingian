// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the envelope parser for a PDU received from another server. The first byte picks the
// room version the caller already resolved (the list covers the formats the parser branches on,
// plus a version it does not know); the rest is the PDU JSON. All three entry points that take
// PDU text run on it.

#include "fuzz_input.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    if (size == 0U)
    {
        return 0;
    }
    auto constexpr versions = std::array<std::string_view, 8U>{"1", "3", "6", "9", "10", "11", "12", "99"};
    auto const room_version = versions.at(data[0] % versions.size());
    auto const pdu_json = merovingian::fuzz::to_string(data + 1U, size - 1U);

    std::ignore = merovingian::federation::parse_inbound_pdu_envelope(pdu_json);
    std::ignore = merovingian::federation::parse_inbound_pdu_envelope(pdu_json, room_version);
    std::ignore = merovingian::federation::rebuild_inbound_pdu_envelope(pdu_json, room_version, "origin.example");
    return 0;
}
