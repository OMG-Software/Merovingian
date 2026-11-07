// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::federation
{

struct SrvRecord final
{
    std::string target{};
    std::uint16_t port{8448U};
    std::uint16_t priority{0U};
    std::uint16_t weight{0U};
};

} // namespace merovingian::federation
