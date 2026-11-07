// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

// A single SSO identity provider advertised in the `m.login.sso` login flow
// (Matrix v1.19 CS API §"Client login via SSO", `IdP` shape). `id` and
// `name` are required by spec; `icon` (an `mxc://` URI) and `brand` are
// optional UI hints and are omitted from the advertised flow when empty.
struct SsoIdentityProvider final
{
    std::string id{};
    std::string name{};
    std::string icon{};
    std::string brand{};
};

} // namespace merovingian::config
