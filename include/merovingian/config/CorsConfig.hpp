// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::config
{

struct CorsConfig final
{
    // Origins to allow. Wildcard `*` is the default and means any origin is
    // allowed to make cross-origin requests. The CORS spec forbids combining
    // `*` with `allow_credentials=true`; the config parser enforces that.
    std::vector<std::string> allowed_origins{"*"};
    // How long the preflight result may be cached, in seconds.
    std::uint32_t max_age{86400U};
    // Whether to allow browser credentials (cookies, client TLS certs).
    // Matrix clients authenticate with bearer tokens so this is false by
    // default; flip it on only when you know what you are doing.
    bool allow_credentials{false};
    // Methods advertised in the preflight `Access-Control-Allow-Methods`
    // header. Empty string falls back to the standard list.
    std::string allow_methods{"GET, POST, PUT, DELETE, OPTIONS"};
    // Headers advertised in the preflight `Access-Control-Allow-Headers`
    // header. Empty string falls back to `authorization, content-type`,
    // which is the set Matrix clients actually use.
    std::string allow_headers{"authorization, content-type"};
};

} // namespace merovingian::config
