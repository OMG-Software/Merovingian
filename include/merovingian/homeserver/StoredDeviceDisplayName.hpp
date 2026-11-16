// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// Module-internal (src/AGENTS.md "Where module-local helpers go"): the display name the persistent device row of
// (`user_id`, `device_id`) holds, or empty when there is no row. Shared by POST /refresh and the OAuth 2.0 refresh
// grant, which re-add a device the runtime's device list lost (after a restart) under this name, never its device ID.
// Reads one user's devices; the caller holds runtime.mutex.
[[nodiscard]] auto stored_device_display_name(HomeserverRuntime const& runtime, std::string_view user_id,
                                              std::string_view device_id) -> std::string;

} // namespace merovingian::homeserver
