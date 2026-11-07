// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

// What a clamd scan decided (ADR-0565). Only `clean` clears media; every other value keeps it quarantined.
enum class ClamdVerdict : std::uint8_t
{
    // clamd answered `stream: OK`.
    clean,
    // clamd answered `stream: <name> FOUND`.
    infected,
    // The scan did not produce a verdict: connect failure, timeout, an ERROR or malformed reply, or no scan capacity.
    failed,
    // The media is larger than `max_scan_bytes`, so it was not sent to clamd.
    oversize,
};

} // namespace merovingian::media
