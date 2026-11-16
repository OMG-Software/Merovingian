// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/PagePath.hpp"

#include <string_view>

namespace merovingian::oauth
{

// The paths of the OAuth 2.0 API this server serves under its own namespace (ADR-0773). The metadata advertises
// each as `OAuthBaseUrl::url(path)`, and the dispatcher routes on the same constants, so what is advertised and what
// is served cannot drift apart. Every one is a PagePath: fixed at compile time, `/`-rooted, no query.
inline constexpr auto register_path = PagePath{"/_merovingian/oauth2/register"};
inline constexpr auto authorize_path = PagePath{"/_merovingian/oauth2/authorize"};
inline constexpr auto token_path = PagePath{"/_merovingian/oauth2/token"};
inline constexpr auto revoke_path = PagePath{"/_merovingian/oauth2/revoke"};
inline constexpr auto device_path = PagePath{"/_merovingian/oauth2/device"};
inline constexpr auto link_path = PagePath{"/_merovingian/oauth2/link"};
inline constexpr auto account_path = PagePath{"/_merovingian/account"};

// The metadata document's own paths, fixed by the spec (`GET /_matrix/client/v1/auth_metadata`) and by MSC2965 for
// the unstable form. They are routed as they stand and never joined to the base URL.
inline constexpr auto auth_metadata_path = std::string_view{"/_matrix/client/v1/auth_metadata"};
inline constexpr auto auth_metadata_unstable_path =
    std::string_view{"/_matrix/client/unstable/org.matrix.msc2965/auth_metadata"};

} // namespace merovingian::oauth
