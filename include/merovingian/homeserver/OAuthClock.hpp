// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// The wall-clock time the OAuth 2.0 handlers give `PendingAuthorisationStore` and `AuthorizationCodeStore`, in
// milliseconds since the epoch; zero for a clock set before it.
[[nodiscard]] auto oauth_wall_clock_ms() -> std::uint64_t;

} // namespace merovingian::homeserver
