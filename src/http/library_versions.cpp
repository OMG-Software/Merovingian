// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/library_versions.hpp"

#include "merovingian/core/library_version.hpp"

#include <curl/curl.h>

#include <string>
#include <vector>

namespace merovingian::http
{

auto library_versions() -> std::vector<core::LibraryVersion>
{
    // curl_version_info() points into libcurl's own static data.
    auto const* const info = ::curl_version_info(CURLVERSION_NOW);
    auto const* const running = info != nullptr ? info->version : nullptr;
    return {core::describe_library("libcurl", running != nullptr ? std::string{running} : std::string{},
                                   LIBCURL_VERSION, running)};
}

} // namespace merovingian::http
