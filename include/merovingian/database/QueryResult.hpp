// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::database
{

struct QueryResult final
{
    bool ok{false};
    std::string error{};
    std::vector<std::vector<std::string>> rows{};
};

} // namespace merovingian::database
