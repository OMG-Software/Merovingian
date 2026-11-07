// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct OutboundTransactionResult final
{
    bool sent{false};
    std::uint16_t http_status{0U};
    std::string response_body{};
    std::string error{};
};

} // namespace merovingian::federation
