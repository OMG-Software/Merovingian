// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::homeserver
{

// The most event rows one evaluation of a sliding-sync long-poll walks to decide whether a room event
// concerns the caller (ADR-0609). When the walk reaches it without meeting an event in a room the caller
// has joined, the poll is treated as relevant and answered, never parked: a wake-up is not lost, and the
// answer's pos is past those events, so the next poll's walk is short.
inline constexpr std::size_t sliding_sync_relevance_scan_rows = 2048U;

} // namespace merovingian::homeserver
