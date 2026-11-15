// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::core
{

// The `SameSite` attribute of a cookie this server sets (HostCookie.hpp). `None` is not offered: a cookie of this
// server is never sent on a cross-site subrequest.
enum class CookieSameSite : std::uint8_t
{
    // Sent on a top-level navigation from another site: the pending OAuth authorisation, whose page a client opens.
    lax,
    // Never sent from another site: the account-page session.
    strict,
};

} // namespace merovingian::core
