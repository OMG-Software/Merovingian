// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::tests
{

struct CapturedAppserviceRequest final
{
    std::string method{};
    std::string target{};
    std::string authorization{};
    std::string body{};
    std::uint16_t answered_status{0U};
};

} // namespace merovingian::tests
