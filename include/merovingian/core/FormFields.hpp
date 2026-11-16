// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::core
{

// The fields of an `application/x-www-form-urlencoded` request body (an OAuth 2.0 token, revocation or page form
// post), read strictly. Unlike parse_query_params, which keeps going on anything, every departure from the grammar
// refuses the whole body (ADR-0817):
//
//  - a field is `name=value`; a field with no `=`, an empty name, or an empty field (`&&`, a leading or trailing
//    `&`) is refused. A value may be empty, and may hold a literal `=` after the first;
//  - `+` is a space, `%XX` is one byte, and a `%` not followed by two hex digits is refused;
//  - a raw byte outside printable ASCII (`!` to `~`), a raw space included, is refused: a conforming encoder escapes
//    them;
//  - a decoded name or value that is not UTF-8 or holds NUL is refused;
//  - a name that appears twice (compared after decoding) is refused, so no second value can hide behind a check of
//    the first;
//  - an empty body is an empty set.
//
// Values can be passwords, codes and tokens. Nothing here logs, an error never quotes the input, and the destructor
// wipes every name and value (core::secure_zero). Copying is disabled so no unwiped copy is made by accident.
class FormFields final
{
public:
    // The largest body read, in bytes: the client-server body cap (ClientApiLimits::max_body_bytes, 64 KiB). An
    // OAuth form is a few hundred bytes.
    static constexpr std::size_t max_body_bytes = 65536U;
    // The most fields: an OAuth token request has at most eight, a page form a dozen.
    static constexpr std::size_t max_fields = 64U;
    // The longest decoded name: the longest OAuth parameter name, `code_challenge_method`, is 21.
    static constexpr std::size_t max_name_bytes = 64U;
    // The longest decoded value: a redirect URI or a refresh token is far shorter; a password longer than this is
    // refused rather than cut.
    static constexpr std::size_t max_value_bytes = 8192U;

    // An empty set.
    FormFields() = default;
    ~FormFields() noexcept;

    FormFields(FormFields const&) = delete;
    auto operator=(FormFields const&) -> FormFields& = delete;
    FormFields(FormFields&& other) noexcept = default;
    auto operator=(FormFields&& other) noexcept -> FormFields&;

    // The fields of `body`, or why not. ErrorCode::parse_failure: the body breaks the grammar above.
    // ErrorCode::invalid_argument: a cap above is exceeded. Either message is fixed text, never input.
    [[nodiscard]] static auto parse(std::string_view body) -> std::variant<FormFields, Error>;

    // The fields of a page's request query (the part after `?`, without it), read as `parse` reads a body except that
    // a bare name with no `=` and an empty field (`&&`, a leading or trailing `&`) count as not sent: RFC 6749 section
    // 3.1, "Parameters sent without a value MUST be treated as if they were omitted from the request". A bare name is
    // still decoded and checked, so a malformed escape, NUL or invalid UTF-8 in it refuses the query, and every other
    // refusal and cap of `parse` holds; a bare name repeated, or beside a sent field of that name, is not a repeat.
    // Only for the queries of the browser pages (ADR-0817): a body is read with `parse`.
    [[nodiscard]] static auto parse_query(std::string_view query) -> std::variant<FormFields, Error>;

    // The decoded value of field `name`, or nullopt when it was not sent. The view lives as long as this object.
    [[nodiscard]] auto find(std::string_view name) const noexcept -> std::optional<std::string_view>;

    [[nodiscard]] auto size() const noexcept -> std::size_t;
    [[nodiscard]] auto empty() const noexcept -> bool;

    // Every field in body order, decoded: for a caller that refuses parameters it does not know.
    [[nodiscard]] auto fields() const noexcept -> std::vector<std::pair<std::string, std::string>> const&;

private:
    // Omission: whether a bare name or an empty field is refused (`parse`) or counts as not sent (`parse_query`).
    enum class Omission : unsigned char
    {
        refused,
        not_sent,
    };

    [[nodiscard]] static auto read(std::string_view text, Omission omission) -> std::variant<FormFields, Error>;
    auto wipe() noexcept -> void;

    std::vector<std::pair<std::string, std::string>> m_fields{};
};

} // namespace merovingian::core
