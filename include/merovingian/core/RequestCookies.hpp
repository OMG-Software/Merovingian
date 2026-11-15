// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace merovingian::core
{

// The cookies of one `Cookie` request header (RFC 6265 section 4.2.1 `cookie-string`, read as section 5.4 says a
// user agent writes it). No percent-decoding: a value is returned exactly as sent.
//
// A browser sends this host every cookie whose domain matches it, so a sibling host under the same parent domain can
// add cookies of its own, in any shape (cookie tossing). One malformed or repeated cookie therefore does not refuse
// the header; it makes that one name unusable (ADR-0766):
//
//  - pairs are separated by `;`, each trimmed of spaces and tabs; an empty pair (`;;`, a trailing `;`) is skipped;
//  - a pair whose name is an RFC 9110 token and whose value is `*cookie-octet` (no quotes, spaces, commas, `;`,
//    backslash, controls or bytes above `~`) is well-formed; a quoted value is not, since this server never sets one;
//  - find(name) answers only when exactly one pair has that name and it is well-formed. A name sent twice, or sent
//    once malformed, answers nothing, so no second value can be smuggled past a check of the first.
//
// The whole header is refused only for what no browser sends: a control character other than a tab, more than
// max_header_bytes, or more than max_cookies pairs. Values can be session identifiers: nothing here logs, an error
// never quotes the input, and the destructor wipes every name and value.
class RequestCookies final
{
public:
    // The longest header read: the default request-head cap (`http.max_header_bytes`, 32 KiB), so a header the
    // server accepted is normally readable.
    static constexpr std::size_t max_header_bytes = 32768U;
    // The most pairs: above what browsers keep for one domain (Chromium 180, RFC 6265 section 6.1 asks for 50).
    static constexpr std::size_t max_cookies = 256U;

    // No cookies.
    RequestCookies() = default;
    ~RequestCookies() noexcept;

    RequestCookies(RequestCookies const&) = delete;
    auto operator=(RequestCookies const&) -> RequestCookies& = delete;
    RequestCookies(RequestCookies&& other) noexcept = default;
    auto operator=(RequestCookies&& other) noexcept -> RequestCookies&;

    // The cookies of a `Cookie` header value; an empty value has none. ErrorCode::parse_failure: a control character.
    // ErrorCode::invalid_argument: a cap is exceeded. The message is fixed text, never input.
    [[nodiscard]] static auto parse(std::string_view header_value) -> std::variant<RequestCookies, Error>;

    // The value of the one well-formed cookie named `name` (compared exactly, case-sensitively), or nullopt when it
    // is absent, repeated or malformed. The view lives as long as this object.
    [[nodiscard]] auto find(std::string_view name) const noexcept -> std::optional<std::string_view>;

    // How many pairs were read, the malformed ones included.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    struct Entry final
    {
        std::string name{};
        std::string value{};
        bool well_formed{false};
    };

    auto wipe() noexcept -> void;

    std::vector<Entry> m_entries{};
};

} // namespace merovingian::core
