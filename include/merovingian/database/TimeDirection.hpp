// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// Which way nearest_by_time() looks from a timestamp (Client-Server API,
// `GET /rooms/{roomId}/timestamp_to_event`, `dir`: `f` forwards, `b` backwards).
enum class TimeDirection : unsigned char
{
    forwards,
    backwards,
};

} // namespace merovingian::database
