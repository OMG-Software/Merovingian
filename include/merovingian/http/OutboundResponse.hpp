// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundHeader.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::http
{

struct OutboundResponse final
{
    std::uint16_t status{0U};
    std::vector<OutboundHeader> headers{};
    std::string body{};
};

} // namespace merovingian::http
