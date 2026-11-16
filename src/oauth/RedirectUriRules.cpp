// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/RedirectUriRules.hpp"

#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/oauth/AsciiCase.hpp"
#include "merovingian/oauth/OAuthErrorCodes.hpp"

#include <utility>

namespace merovingian::oauth
{
namespace
{

    [[nodiscard]] auto refuse(core::ErrorCode code, char const* message) -> OAuthRefusal
    {
        return OAuthRefusal{
            std::string{error_invalid_redirect_uri},
            core::Error{code, message}
        };
    }

    [[nodiscard]] auto is_loopback_host(std::string_view host) noexcept -> bool
    {
        return host == "localhost" || host == "127.0.0.1" || host == "[::1]";
    }

    // A private-use scheme for a client whose reversed host is `reversed`: equal to it, or it and `.` and more.
    [[nodiscard]] auto is_private_use_scheme_for(std::string_view scheme, std::string_view reversed) -> bool
    {
        auto const lower = ascii_lower(scheme);
        if (lower == reversed)
        {
            return true;
        }
        return lower.size() > reversed.size() + 1U && lower.starts_with(reversed) && lower[reversed.size()] == '.';
    }

    // `requested` is `registered` with `:<port>` after the host, where `registered` is `http://<host><rest>` with no
    // port. The port has already been read as 1..65535 with no leading zero.
    [[nodiscard]] auto is_registered_loopback_with_port(ParsedUri const& requested, ParsedUri const& registered) -> bool
    {
        if (!requested.port().has_value() || requested.scheme() != "http" || requested.host() != registered.host())
        {
            return false;
        }
        auto const prefix = std::string{"http://"} + registered.host();
        auto const port_text = ":" + std::to_string(*requested.port());
        auto const& text = requested.text();
        auto const& base = registered.text();
        if (!text.starts_with(prefix) || !base.starts_with(prefix))
        {
            return false;
        }
        auto const after_host = std::string_view{text}.substr(prefix.size());
        if (!after_host.starts_with(port_text))
        {
            return false;
        }
        return after_host.substr(port_text.size()) == std::string_view{base}.substr(prefix.size());
    }

} // namespace

auto https_uri_is_on_client_host(ParsedUri const& uri, ClientUri const& client_uri) -> bool
{
    if (uri.scheme() != "https" || !uri.has_authority())
    {
        return false;
    }
    auto const host = ascii_lower(uri.host());
    auto const& base = client_uri.host_lower();
    if (host == base)
    {
        return true;
    }
    return host.size() > base.size() + 1U && host.ends_with(base) && host[host.size() - base.size() - 1U] == '.';
}

auto is_registrable_loopback_uri(ParsedUri const& uri) noexcept -> bool
{
    return uri.scheme() == "http" && uri.has_authority() && is_loopback_host(uri.host()) && !uri.port().has_value();
}

auto validate_redirect_uri(std::string_view uri, ApplicationType type, ClientUri const& client_uri)
    -> std::variant<ParsedUri, OAuthRefusal>
{
    auto parsed = ParsedUri::read(uri);
    if (auto const* error = std::get_if<core::Error>(&parsed))
    {
        return refuse(error->code(), "A redirect URI is not a valid URI.");
    }
    auto& read = std::get<ParsedUri>(parsed);

    if (https_uri_is_on_client_host(read, client_uri))
    {
        return std::move(read);
    }
    if (type == ApplicationType::web)
    {
        return refuse(core::ErrorCode::parse_failure,
                      "A web client's redirect URI must be https on the client_uri host or a subdomain of it.");
    }

    if (is_registrable_loopback_uri(read))
    {
        return std::move(read);
    }
    if (!read.has_authority() && is_private_use_scheme_for(read.scheme(), client_uri.reversed_host_lower()))
    {
        return std::move(read);
    }
    return refuse(core::ErrorCode::parse_failure,
                  "A native client's redirect URI must use the reversed client_uri host as its scheme with no "
                  "authority, be http on a loopback host with no port, or be https on the client_uri host.");
}

auto match_redirect_uri(std::string_view requested, ApplicationType type, std::span<std::string const> registered)
    -> std::optional<ParsedUri>
{
    auto parsed = ParsedUri::read(requested);
    auto* read = std::get_if<ParsedUri>(&parsed);
    if (read == nullptr)
    {
        return std::nullopt;
    }
    for (auto const& candidate : registered)
    {
        if (candidate == requested)
        {
            return std::move(*read);
        }
        if (type != ApplicationType::native)
        {
            continue;
        }
        auto registered_parsed = ParsedUri::read(candidate);
        auto const* registered_uri = std::get_if<ParsedUri>(&registered_parsed);
        if (registered_uri != nullptr && is_registrable_loopback_uri(*registered_uri) &&
            is_registered_loopback_with_port(*read, *registered_uri))
        {
            return std::move(*read);
        }
    }
    return std::nullopt;
}

} // namespace merovingian::oauth
