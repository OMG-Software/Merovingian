// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the portable SRV-record parser against raw DNS response bytes.
// The parser is fully bounds-checked (no ns_* API); any out-of-bounds read
// or write is a bug that should be caught here.

#include "merovingian/federation/server_discovery.hpp"

#include <cstddef>
#include <cstdint>
#include <limits>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    // DNS messages are at most 65535 bytes; clamp so the int cast is safe.
    if (size > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        return 0;
    }
    std::ignore = merovingian::federation::parse_srv_records(data, static_cast<int>(size));
    return 0;
}
