// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"

namespace merovingian::auth
{

// Holds the OIDC authorisation server metadata as a canonical JSON object.
// When `configured` is false the caller should return 404 M_UNRECOGNIZED;
// when true the caller should return the fields object with status 200.
struct AuthMetadata final
{
    bool configured{false};
    canonicaljson::Object fields{};
};

} // namespace merovingian::auth
