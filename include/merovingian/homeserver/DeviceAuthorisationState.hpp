// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// Where a device authorisation stands (RFC 8628; ADR-0804). It starts pending; a user's answer on the consent page
// makes it approved or denied, once. An approved one is removed when the device redeems it; a denied one stays until
// it expires, so every poll until then hears `access_denied`.
enum class DeviceAuthorisationState : std::uint8_t
{
    pending,
    approved,
    denied,
};

} // namespace merovingian::homeserver
