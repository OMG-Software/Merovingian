// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::events
{

enum class MembershipState
{
    leave,
    invite,
    join,
    ban,
    knock,
    restricted,
};

} // namespace merovingian::events
