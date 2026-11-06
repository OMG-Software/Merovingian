// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"

#include <string>

namespace merovingian::homeserver
{

struct RuntimeStartResult final
{
    bool started{false};
    std::string reason{};
    HomeserverRuntime runtime{};
};

} // namespace merovingian::homeserver
