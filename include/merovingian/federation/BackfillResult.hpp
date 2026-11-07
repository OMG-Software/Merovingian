// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct BackfillResult final
{
    bool accepted{false};
    std::uint16_t status{500U};
    std::string reason{};
    std::vector<std::string> pdus_json{};
};

} // namespace merovingian::federation
