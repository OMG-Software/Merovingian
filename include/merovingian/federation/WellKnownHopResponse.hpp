// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

// One request of the well-known fetch, as the transport answered it. `transport_ok` is false when no HTTP answer
// was obtained (connection, TLS, timeout, size). A 3xx answer carries its `Location` header in `location`.
struct WellKnownHopResponse final
{
    bool transport_ok{false};
    std::uint16_t status{0U};
    std::string location{};
    std::string body{};
    std::string error{};
};

} // namespace merovingian::federation
