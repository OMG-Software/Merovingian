// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Exercises the strict URI reader (oauth::ParsedUri::read), the client URI rules and the redirect URI rules
// (validate_redirect_uri, match_redirect_uri). Bytes before the first NUL are the redirect URI; bytes after it are
// the client URI, which is also the one registered URI the redirect URI is matched against.
//
// Beside stability it aborts when a property that holds for every input breaks: a CSP source holds no space, `;`, `,`
// or quote (it is joined into a policy header), a match returns the very text requested (the redirect goes there),
// and a redirect URI that validates matches itself once registered.

#include "fuzz_input.hpp"
#include "merovingian/oauth/ApplicationType.hpp"
#include "merovingian/oauth/ClientUri.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/RedirectUriRules.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace
{

// Aborts the run, which libFuzzer reports as a crash with the input that broke the property.
auto require(bool property) -> void
{
    if (!property)
    {
        std::abort();
    }
}

auto require_safe_csp_source(merovingian::oauth::ParsedUri const& uri) -> void
{
    auto const source = uri.csp_source();
    require(source.find_first_of(" ;,'\"") == std::string::npos);
}

auto require_exact_match(std::optional<merovingian::oauth::ParsedUri> const& match, std::string_view requested) -> void
{
    if (match.has_value())
    {
        require(match->text() == requested);
        require_safe_csp_source(*match);
    }
}

} // namespace

extern "C" auto LLVMFuzzerTestOneInput(std::uint8_t const* data, std::size_t size) -> int
{
    using merovingian::oauth::ApplicationType;

    auto const input = merovingian::fuzz::to_string(data, size);
    auto const [redirect, client] = merovingian::fuzz::split_at_nul(input);

    auto const parsed = merovingian::oauth::ParsedUri::read(redirect);
    if (auto const* uri = std::get_if<merovingian::oauth::ParsedUri>(&parsed))
    {
        require_safe_csp_source(*uri);
    }

    auto const registered = std::array{std::string{client}};
    for (auto const type : {ApplicationType::web, ApplicationType::native})
    {
        require_exact_match(merovingian::oauth::match_redirect_uri(redirect, type, registered), redirect);
    }

    auto const client_uri = merovingian::oauth::ClientUri::read(client);
    if (auto const* base = std::get_if<merovingian::oauth::ClientUri>(&client_uri))
    {
        for (auto const type : {ApplicationType::web, ApplicationType::native})
        {
            auto const validated = merovingian::oauth::validate_redirect_uri(redirect, type, *base);
            if (std::holds_alternative<merovingian::oauth::ParsedUri>(validated))
            {
                auto const itself = std::array{std::string{redirect}};
                auto const match = merovingian::oauth::match_redirect_uri(redirect, type, itself);
                require(match.has_value());
                require_exact_match(match, redirect);
            }
        }
    }
    return 0;
}
