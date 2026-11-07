// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::http
{

struct Header final
{
    std::string name{};
    std::string value{};
};

} // namespace merovingian::http
