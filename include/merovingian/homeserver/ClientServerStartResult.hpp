// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/ClientServerRuntime.hpp"

#include <string>

namespace merovingian::homeserver
{

struct ClientServerStartResult final
{
    bool started{false};
    std::string reason{};
    ClientServerRuntime runtime{};
};

} // namespace merovingian::homeserver
