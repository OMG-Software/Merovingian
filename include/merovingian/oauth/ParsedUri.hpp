// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace merovingian::oauth
{

// An absolute URI read by the strict reader the OAuth 2.0 code uses for every address a client supplies
// (`client_uri`, `redirect_uris`, `policy_uri`, `tos_uri`) and for every page link (ADR-0770). It is a subset of
// RFC 3986, chosen so that what it accepts can be compared byte for byte and put into a header or a page safely:
//
//  - 1 to 2048 bytes, every byte printable ASCII (`!` to `~`): no space, control byte, NUL or non-ASCII byte;
//  - `scheme ":"`, the scheme `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`, at most 255 bytes, case kept as sent;
//  - an optional `"//" authority`. It never holds userinfo (no `@`). Its host is either a bracketed IPv6 literal
//    (hex digits, `:` and `.`) or dot-separated labels of `A-Z a-z 0-9 -`, each 1 to 63 bytes, not starting or ending
//    with `-`, 253 bytes at most, with no empty label (so no trailing dot) and no `%` escape. An optional port is 1
//    to 5 digits, no leading zero, 1 to 65535. A `//` that opens an empty host is refused;
//  - a path and an optional `?query` of RFC 3986 `pchar` (`unreserved / sub-delims / ":" / "@"` and `%XX` with two
//    hex digits), `/`, and in the query `?`;
//  - never a fragment: a `#` anywhere, a bare trailing one included, is refused; so are `\`, `"`, `<`, `>`, `^`, `` `
//  ``,
//    `{`, `|`, `}`, and `[` or `]` outside an IPv6 host.
//
// Nothing is decoded, normalised or repaired: what is read is exactly the bytes given. A value of this type exists
// only through read(), so a ParsedUri always satisfies the rules above.
class ParsedUri final
{
public:
    // The longest URI read, in bytes: browsers and RFC 7230's advice stop short of 8 KiB, and a redirect URI is a
    // query parameter of an authorisation request the browser must carry; 2048 is the common URL ceiling.
    static constexpr std::size_t max_uri_bytes = 2048U;
    // The longest scheme read: a private-use scheme is a reversed DNS name (253 bytes) and a short suffix.
    static constexpr std::size_t max_scheme_bytes = 255U;

    // `text` read by the rules above, or why not. ErrorCode::parse_failure: a rule above is broken.
    // ErrorCode::invalid_argument: a length cap is exceeded. Either message is fixed text, never input.
    [[nodiscard]] static auto read(std::string_view text) -> std::variant<ParsedUri, core::Error>;

    // The whole URI, exactly as given.
    [[nodiscard]] auto text() const noexcept -> std::string const&;
    // The scheme, case as sent.
    [[nodiscard]] auto scheme() const noexcept -> std::string const&;
    // Whether `//` and an authority follow the scheme.
    [[nodiscard]] auto has_authority() const noexcept -> bool;
    // The host as written (an IPv6 literal keeps its brackets); empty when there is no authority.
    [[nodiscard]] auto host() const noexcept -> std::string const&;
    // The port, when one is written.
    [[nodiscard]] auto port() const noexcept -> std::optional<std::uint16_t>;
    // The path, possibly empty, without the query.
    [[nodiscard]] auto path() const noexcept -> std::string const&;
    // Whether a `?` is present, and the query after it (possibly empty).
    [[nodiscard]] auto has_query() const noexcept -> bool;
    [[nodiscard]] auto query() const noexcept -> std::string const&;

    // The origin as a Content-Security-Policy source: `scheme://host` or `scheme://host:port` with an authority,
    // `scheme:` without one or with a bracketed IPv6 host, which CSP cannot name (ADR-0811). Built from the fields
    // above only, so it holds no space, `;`, `,` or quote.
    [[nodiscard]] auto csp_source() const -> std::string;

private:
    ParsedUri() = default;

    std::string m_text{};
    std::string m_scheme{};
    bool m_has_authority{false};
    std::string m_host{};
    std::optional<std::uint16_t> m_port{};
    std::string m_path{};
    bool m_has_query{false};
    std::string m_query{};
};

} // namespace merovingian::oauth
