// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::net
{

struct TcpBindResult final
{
    bool ok{false};
    std::string error{};
};

} // namespace merovingian::net
