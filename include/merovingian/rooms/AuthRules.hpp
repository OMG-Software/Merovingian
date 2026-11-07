// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::rooms
{

enum class AuthRules : unsigned char
{
    room_v1,
    room_v6_plus, // room versions 6–11
    room_v12,     // room version 12 (MSC4289/MSC4291): creator privilege + implicit create
};

} // namespace merovingian::rooms
