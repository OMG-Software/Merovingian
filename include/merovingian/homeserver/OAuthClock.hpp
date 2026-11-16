// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// The wall-clock time the OAuth 2.0 handlers give `PendingAuthorisationStore` and `AuthorizationCodeStore`, in
// milliseconds since the epoch; zero for a clock set before it.
[[nodiscard]] auto oauth_wall_clock_ms() -> std::uint64_t;

// The time the device authorization grant's stores and handlers use (`DeviceAuthorisationStore`,
// `UserCodeAttemptThrottle`): `oauth_wall_clock_ms` plus `runtime.test_device_grant_clock_advance_ms`, which is 0
// outside tests (ADR-0805).
[[nodiscard]] auto oauth_device_clock_ms(HomeserverRuntime const& runtime) -> std::uint64_t;

} // namespace merovingian::homeserver
