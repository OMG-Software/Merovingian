// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/homeserver/PresenceReadStatus.hpp"

namespace merovingian::homeserver
{

struct PresenceRead final
{
    PresenceReadStatus status{PresenceReadStatus::not_found};
    // The response body when `status` is ok.
    canonicaljson::Object body{};
};

} // namespace merovingian::homeserver
