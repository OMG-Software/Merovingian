// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::homeserver
{

// Security audit run-4 F-05 (ADR-0582). Device creation (`complete_login`, `login_local_user_by_id`) runs in
// `AuthService.cpp`, which has no `ClientApiLimits`, so the device cap is a constant here. A device-list
// announcement does work per device under `runtime.mutex`, so a user holds at most this many devices; a login
// with a device ID the user already has is always allowed.
inline constexpr std::size_t device_count_limit = 200U;

// The longest `initial_device_display_name` / `display_name` accepted, in bytes (not code points). Over it the
// request is `400 M_TOO_LARGE` and nothing is stored; the name is never truncated. `ClientApiLimits` starts from it.
inline constexpr std::size_t device_display_name_byte_limit = 256U;

} // namespace merovingian::homeserver
