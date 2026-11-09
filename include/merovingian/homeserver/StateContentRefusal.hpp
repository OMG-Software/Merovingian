// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Why a local state event's content was refused (F-19): always a 400, with this Matrix errcode and a message.
struct StateContentRefusal final
{
    std::string_view errcode{};
    std::string message{};
};

} // namespace merovingian::homeserver
