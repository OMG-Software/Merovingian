// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/oauth/OAuthRefusal.hpp"
#include "merovingian/oauth/ParsedUri.hpp"

#include <string>
#include <string_view>
#include <variant>

namespace merovingian::oauth
{

// A client's `client_uri`, the common base of every other address it registers (spec "Client metadata"). Exists only
// through read(), so it always satisfies these rules (ADR-0771): a ParsedUri with the scheme `https` (lower case),
// an authority without userinfo, no fragment, and a host that is a DNS name of at least two labels: not an IP literal
// (no IPv6 brackets, no all-digit last label), not `localhost` and not under `.localhost`. A port, path and query
// are allowed.
class ClientUri final
{
public:
    // `text` as a client URI, or a refusal with `invalid_client_metadata` and fixed text.
    [[nodiscard]] static auto read(std::string_view text) -> std::variant<ClientUri, OAuthRefusal>;

    // The URI as read.
    [[nodiscard]] auto uri() const noexcept -> ParsedUri const&;
    // The host in ASCII lower case, for comparison.
    [[nodiscard]] auto host_lower() const noexcept -> std::string const&;
    // The lower-case host with its labels reversed (`app.example.com` gives `com.example.app`): the base of a native
    // client's private-use scheme.
    [[nodiscard]] auto reversed_host_lower() const noexcept -> std::string const&;

private:
    explicit ClientUri(ParsedUri uri);

    ParsedUri m_uri;
    std::string m_host_lower{};
    std::string m_reversed_host_lower{};
};

} // namespace merovingian::oauth
