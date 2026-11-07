// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::rooms
{

enum class RedactionRules : unsigned char
{
    room_v1_v7,    // v1–v7: join_rules preserves only join_rule
    room_v8_v10,   // v8–v10: join_rules also preserves allow (restricted joins, MSC3083)
    room_v11_plus, // v11+: revised rules (aliases stripped, third_party_invite in member, etc.)
};

} // namespace merovingian::rooms
