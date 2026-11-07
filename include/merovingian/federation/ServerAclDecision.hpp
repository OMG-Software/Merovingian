// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

enum class ServerAclDecision : std::uint8_t
{
    allow,
    deny,
};

} // namespace merovingian::federation
