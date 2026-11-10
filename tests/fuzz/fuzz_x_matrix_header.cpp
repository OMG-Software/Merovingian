// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the parser for the Authorization: X-Matrix header of an inbound federation request.
// The header is read before any signature is checked, so any server on the network can send it.

#include "fuzz_input.hpp"
#include "merovingian/federation/InboundRequest.hpp"

#include <cstddef>
#include <cstdint>
#include <tuple>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    auto const input = merovingian::fuzz::to_string(data, size);
    std::ignore = merovingian::federation::parse_x_matrix_authorization_header(input);
    return 0;
}
