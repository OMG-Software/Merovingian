// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/HomeserverRuntime.hpp"

#include <optional>
#include <string_view>

namespace merovingian::homeserver
{

// G15, ADR-0565: asks the clamd scanner whether `bytes` may be served. Returns std::nullopt when no scan applies
// (no scanner configured, or the policy for this kind of media is not `allow-after-scan`, so the verdict would be
// ignored), otherwise true only for a clean verdict; infected, failed and oversize media all answer false and the
// caller then treats the scanner as not having cleared it. `remote_fetch` picks the remote or the local upload
// policy. `actor` and `subject` label the `media.scan_infected` / `media.scan_failed` audit rows.
//
// Releases `runtime.mutex` (every recursion level) for the scan, so the caller must hold no pointer or reference
// into runtime state across the call and must re-read what it needs afterwards.
[[nodiscard]] auto clamd_media_cleared(HomeserverRuntime& runtime, bool remote_fetch, std::string_view actor,
                                       std::string_view subject, std::string_view bytes) -> std::optional<bool>;

} // namespace merovingian::homeserver
