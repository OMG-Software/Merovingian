// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// How a device came to hold a session, for remember_signed_in_device (ClientDeviceSessions.hpp).
enum class SignedInDevice : std::uint8_t
{
    // A login or an OAuth 2.0 grant: a device new to the runtime's list also records the user's own device-list
    // change, so the user's other devices and the new device's first /sync re-query the keys.
    new_session,
    // A refresh: only the runtime's device list is healed (after a restart), nothing is announced.
    refreshed_session,
};

} // namespace merovingian::homeserver
