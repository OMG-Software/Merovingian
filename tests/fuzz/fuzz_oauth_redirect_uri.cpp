// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the strict URI reader (oauth::ParsedUri::read), the client URI rules and the redirect URI rules
// (validate_redirect_uri, match_redirect_uri). Bytes before the first NUL are the redirect URI; bytes after it are
// the client URI, which is also the one registered URI the redirect URI is matched against.

#include "fuzz_input.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientUri.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/RedirectUriRules.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <tuple>
#include <variant>

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    using merovingian::oauth::ApplicationType;

    auto const input = merovingian::fuzz::to_string(data, size);
    auto const [redirect, client] = merovingian::fuzz::split_at_nul(input);

    auto const parsed = merovingian::oauth::ParsedUri::read(redirect);
    if (auto const* uri = std::get_if<merovingian::oauth::ParsedUri>(&parsed))
    {
        std::ignore = uri->csp_source();
    }

    auto const registered = std::array{std::string{client}};
    for (auto const type : {ApplicationType::web, ApplicationType::native})
    {
        std::ignore = merovingian::oauth::match_redirect_uri(redirect, type, registered);
    }

    auto const client_uri = merovingian::oauth::ClientUri::read(client);
    if (auto const* base = std::get_if<merovingian::oauth::ClientUri>(&client_uri))
    {
        for (auto const type : {ApplicationType::web, ApplicationType::native})
        {
            std::ignore = merovingian::oauth::validate_redirect_uri(redirect, type, *base);
        }
    }
    return 0;
}
