// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

struct ReviewOutcome final
{
    std::uint16_t status{200U};
    std::string errcode{};
    std::string message{};
};

} // namespace merovingian::homeserver
