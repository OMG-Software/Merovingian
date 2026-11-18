// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::oauth
{

// What an accepted `scope` parameter grants: full Client-Server API access for the one device it names.
struct GrantedScope final
{
    // The device ID from the single `urn:matrix:client:device:<device_id>` token.
    std::string device_id{};
    // The granted scope in canonical order, unknown tokens dropped:
    // `urn:matrix:client:api:* urn:matrix:client:device:<device_id>`.
    std::string scope{};
};

} // namespace merovingian::oauth
