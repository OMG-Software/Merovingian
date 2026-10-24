// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/library_versions.hpp"

#include "merovingian/canonicaljson/library_versions.hpp"
#include "merovingian/core/library_version.hpp"
#include "merovingian/crypto/library_versions.hpp"
#include "merovingian/database/library_versions.hpp"
#include "merovingian/http/library_versions.hpp"

#include <iterator>
#include <string_view>
#include <vector>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

namespace merovingian::homeserver
{

namespace
{

    // OpenSSL's version text starts with its own name ("OpenSSL 3.0.13 30 Jan 2024"), which the
    // log line already gives. LibreSSL's ("LibreSSL 3.8.2") keeps its name, so it reads as the
    // OpenSSL implementation it is.
    [[nodiscard]] auto without_openssl_prefix(std::string_view text) -> std::string_view
    {
        constexpr auto prefix = std::string_view{"OpenSSL "};
        return text.starts_with(prefix) ? text.substr(prefix.size()) : text;
    }

} // namespace

auto linked_library_versions() -> std::vector<core::LibraryVersion>
{
    // OpenSSL_version() returns libcrypto's own copy of the version text (LibreSSL's on OpenBSD),
    // in the same form as OPENSSL_VERSION_TEXT.
    auto const* const openssl_running = ::OpenSSL_version(OPENSSL_VERSION);
    auto libraries = std::vector<core::LibraryVersion>{
        core::describe_library("OpenSSL", without_openssl_prefix(openssl_running),
                               without_openssl_prefix(OPENSSL_VERSION_TEXT), openssl_running)};
    auto const append = [&libraries](std::vector<core::LibraryVersion> more) {
        libraries.insert(libraries.end(), std::make_move_iterator(more.begin()), std::make_move_iterator(more.end()));
    };
    append(crypto::library_versions());
    append(database::library_versions());
    append(http::library_versions());
    append(canonicaljson::library_versions());
    return libraries;
}

} // namespace merovingian::homeserver
