// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::net
{

enum class ListenerRole : std::uint8_t
{
    client,
    federation,
};

} // namespace merovingian::net
