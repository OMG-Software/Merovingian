// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/auth/identity.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::auth
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("identity", event, std::move(fields)));
    }

    [[nodiscard]] auto is_ascii_digit(char value) noexcept -> bool
    {
        return value >= '0' && value <= '9';
    }

    [[nodiscard]] auto is_ascii_lower(char value) noexcept -> bool
    {
        return value >= 'a' && value <= 'z';
    }

    [[nodiscard]] auto is_ascii_upper(char value) noexcept -> bool
    {
        return value >= 'A' && value <= 'Z';
    }

    [[nodiscard]] auto is_ascii_alnum(char value) noexcept -> bool
    {
        return is_ascii_lower(value) || is_ascii_upper(value) || is_ascii_digit(value);
    }

    [[nodiscard]] auto is_printable_ascii_without_space(char value) noexcept -> bool
    {
        auto const byte = static_cast<unsigned char>(value);
        return byte > 0x20U && byte < 0x7FU;
    }

    // Spec: Matrix v1.18 § Identifier Grammar — new user ID localpart character set.
    // Only lowercase ASCII, digits, and the listed punctuation are permitted for
    // new user IDs. Uppercase is NOT allowed; it was removed from the spec to
    // allow future case-folding without ambiguity.
    [[nodiscard]] auto is_new_localpart_character(char value) noexcept -> bool
    {
        return is_ascii_lower(value) || is_ascii_digit(value) || value == '.' || value == '_' ||
               value == '-' || value == '=' || value == '/' || value == '+';
    }

    // Validates a byte sequence as a federated localpart.
    //
    // Spec: Matrix v1.18 § User Identifiers (historical note)
    // URL:  https://spec.matrix.org/v1.18/appendices/#user-identifiers
    //
    // Historical deployments issued user IDs with characters outside the normative
    // set (uppercase, punctuation such as '#', Unicode). Servers SHOULD accept these
    // over federation. The only hard constraints in all eras are:
    //   - ':' is forbidden — it is the separator between localpart and server_name
    //   - NUL is forbidden — it truncates C strings and corrupts storage
    //   - Code units must form valid UTF-8 (no overlong sequences, no surrogates,
    //     no code points above U+10FFFF)
    //
    // Empty localparts are technically non-conformant but accepted for maximum
    // compatibility with unusual historical deployments.
    [[nodiscard]] auto is_valid_federated_localpart_bytes(std::string_view bytes) noexcept -> bool
    {
        auto i = std::size_t{0};
        while (i < bytes.size())
        {
            auto const byte = static_cast<unsigned char>(bytes[i]);

            // Reject NUL (corrupts C-string handling) and ':' (breaks user ID parsing).
            if (byte == 0x00U || byte == 0x3AU)
            {
                return false;
            }

            // Determine UTF-8 sequence length and extract the leading code-point bits.
            std::size_t  seq_len    = 0;
            std::uint32_t code_point = 0;

            if (byte < 0x80U) // ASCII (single byte)
            {
                seq_len    = 1;
                code_point = byte;
            }
            else if ((byte & 0xE0U) == 0xC0U) // 2-byte sequence
            {
                seq_len    = 2;
                code_point = byte & 0x1FU;
            }
            else if ((byte & 0xF0U) == 0xE0U) // 3-byte sequence
            {
                seq_len    = 3;
                code_point = byte & 0x0FU;
            }
            else if ((byte & 0xF8U) == 0xF0U) // 4-byte sequence
            {
                seq_len    = 4;
                code_point = byte & 0x07U;
            }
            else
            {
                // 0x80–0xBF (lone continuation), 0xF8–0xFF (invalid in UTF-8)
                return false;
            }

            // Validate and accumulate continuation bytes.
            for (std::size_t j = 1; j < seq_len; ++j)
            {
                if (i + j >= bytes.size())
                {
                    return false; // Truncated sequence at end of input
                }
                auto const cont = static_cast<unsigned char>(bytes[i + j]);
                if ((cont & 0xC0U) != 0x80U)
                {
                    return false; // Expected continuation byte, got something else
                }
                code_point = (code_point << 6U) | (cont & 0x3FU);
            }

            // Reject overlong encodings (e.g. 2-byte encoding of an ASCII character).
            if (seq_len == 2U && code_point < 0x80U)    { return false; }
            if (seq_len == 3U && code_point < 0x800U)   { return false; }
            if (seq_len == 4U && code_point < 0x10000U) { return false; }

            // Reject surrogate code points U+D800–U+DFFF.
            // These are permanently reserved and cannot appear in valid UTF-8.
            if (code_point >= 0xD800U && code_point <= 0xDFFFU)
            {
                return false;
            }

            // Reject code points above U+10FFFF (outside Unicode range).
            if (code_point > 0x10FFFFU)
            {
                return false;
            }

            i += seq_len;
        }
        return true;
    }

    [[nodiscard]] auto port_is_valid(std::string_view port) noexcept -> bool
    {
        if (port.empty() || port.size() > 5U || !std::ranges::all_of(port, is_ascii_digit))
        {
            return false;
        }

        auto parsed_port = std::uint32_t{0};
        for (auto const digit : port)
        {
            parsed_port = (parsed_port * 10U) + static_cast<std::uint32_t>(digit - '0');
        }

        return parsed_port <= 65535U;
    }

    [[nodiscard]] auto hostname_is_valid(std::string_view hostname) noexcept -> bool
    {
        if (hostname.empty() || hostname.front() == '.' || hostname.back() == '.')
        {
            return false;
        }

        auto label_start = std::size_t{0};
        while (label_start < hostname.size())
        {
            auto const label_end = hostname.find('.', label_start);
            auto const end = label_end == std::string_view::npos ? hostname.size() : label_end;
            auto const label = hostname.substr(label_start, end - label_start);
            if (label.empty() || label.size() > 63U || label.front() == '-' || label.back() == '-')
            {
                return false;
            }
            if (!std::ranges::all_of(label, [](char const value) {
                    return is_ascii_alnum(value) || value == '-';
                }))
            {
                return false;
            }

            if (label_end == std::string_view::npos)
            {
                break;
            }
            label_start = label_end + 1U;
        }

        return true;
    }

    [[nodiscard]] auto bracketed_ipv6_literal_is_valid(std::string_view literal) noexcept -> bool
    {
        if (literal.size() < 4U || literal.front() != '[')
        {
            return false;
        }

        auto const close = literal.find(']');
        if (close == std::string_view::npos || close == 1U)
        {
            return false;
        }

        auto const address = literal.substr(1U, close - 1U);
        auto const suffix = literal.substr(close + 1U);
        if (address.find(':') == std::string_view::npos)
        {
            return false;
        }
        if (!std::ranges::all_of(address, [](char const value) {
                return is_ascii_digit(value) || (value >= 'a' && value <= 'f') || (value >= 'A' && value <= 'F') ||
                       value == ':' || value == '.';
            }))
        {
            return false;
        }
        if (suffix.empty())
        {
            return true;
        }

        return suffix.front() == ':' && port_is_valid(suffix.substr(1U));
    }

} // namespace

auto server_name_is_valid(std::string_view server_name) noexcept -> bool
{
    if (server_name.empty() || server_name.size() > 255U)
    {
        return false;
    }

    if (server_name.front() == '[')
    {
        return bracketed_ipv6_literal_is_valid(server_name);
    }

    auto const colon = server_name.find(':');
    if (colon == std::string_view::npos)
    {
        return hostname_is_valid(server_name);
    }
    if (server_name.find(':', colon + 1U) != std::string_view::npos)
    {
        return false;
    }

    auto const hostname = server_name.substr(0U, colon);
    auto const port = server_name.substr(colon + 1U);
    return hostname_is_valid(hostname) && port_is_valid(port);
}

// Spec: Matrix v1.18 § Identifier Grammar
// URL:  https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// New localparts MUST use only: a-z, 0-9, '.', '_', '-', '=', '/', '+'.
// Uppercase is not permitted for new user IDs.
// Use this for registration and all local auth paths.
auto localpart_is_valid_new(std::string_view localpart) noexcept -> bool
{
    return !localpart.empty() && localpart.size() <= 255U &&
           std::ranges::all_of(localpart, is_new_localpart_character);
}

// Spec: Matrix v1.18 § User Identifiers (historical compatibility)
// URL:  https://spec.matrix.org/v1.18/appendices/#user-identifiers
//
// Historical user IDs may contain characters outside the normative set.
// Servers SHOULD accept them when received over federation.
// Any valid UTF-8 code point is accepted except ':' and NUL.
// Empty localparts are accepted for maximum compatibility.
auto localpart_is_valid_federated(std::string_view localpart) noexcept -> bool
{
    return is_valid_federated_localpart_bytes(localpart);
}

// Strict validator for local/registration paths.
// Uses localpart_is_valid_new(); rejects uppercase and non-normative characters.
auto user_id_is_valid(std::string_view user_id) noexcept -> bool
{
    if (user_id.size() < 4U || user_id.size() > 255U || user_id.front() != '@')
    {
        return false;
    }

    auto const separator = user_id.find(':');
    if (separator == std::string_view::npos || separator <= 1U || separator + 1U >= user_id.size())
    {
        return false;
    }

    auto const localpart = user_id.substr(1U, separator - 1U);
    auto const server_name = user_id.substr(separator + 1U);
    return localpart_is_valid_new(localpart) && server_name_is_valid(server_name);
}

// Permissive validator for inbound federation paths.
// Uses localpart_is_valid_federated(); accepts historical characters and empty localparts.
auto user_id_is_valid_federated(std::string_view user_id) noexcept -> bool
{
    if (user_id.empty() || user_id.size() > 255U || user_id.front() != '@')
    {
        return false;
    }

    auto const separator = user_id.find(':');
    // Must have a colon with at least one server-name character after it.
    // Empty localpart (separator == 1) is allowed for historical compatibility.
    if (separator == std::string_view::npos || separator + 1U >= user_id.size())
    {
        return false;
    }

    auto const localpart = user_id.substr(1U, separator - 1U);
    auto const server_name = user_id.substr(separator + 1U);
    return localpart_is_valid_federated(localpart) && server_name_is_valid(server_name);
}

auto device_id_is_valid(std::string_view device_id) noexcept -> bool
{
    return !device_id.empty() && device_id.size() <= 255U &&
           std::ranges::all_of(device_id, is_printable_ascii_without_space);
}

auto password_is_acceptable(std::string_view password) noexcept -> bool
{
    auto has_lower = false;
    auto has_upper = false;
    auto has_digit = false;
    auto has_symbol = false;

    for (auto const value : password)
    {
        auto const byte = static_cast<unsigned char>(value);
        has_lower = has_lower || is_ascii_lower(value);
        has_upper = has_upper || is_ascii_upper(value);
        has_digit = has_digit || is_ascii_digit(value);
        has_symbol = has_symbol || (byte >= 0x21U && byte <= 0x7EU && !is_ascii_alnum(value));
    }

    return password.size() >= 12U && has_lower && has_upper && has_digit && has_symbol;
}

auto login_policy(UserIdentity const& user) -> LoginPolicyDecision
{
    auto result = [&]() -> LoginPolicyDecision {
        if (!user_id_is_valid(user.user_id))
        {
            return {false, "invalid user_id"};
        }
        if (!user.password_login_enabled)
        {
            return {false, "password login disabled"};
        }
        if (user.state == AccountState::locked)
        {
            return {false, "account locked"};
        }
        if (user.state == AccountState::suspended)
        {
            return {false, "account suspended"};
        }
        return {true, {}};
    }();
    log_diagnostic(result.allowed ? "login_policy.allowed" : "login_policy.denied",
                   {
                       {"user_id", user.user_id,  false},
                       {"reason",  result.reason, false}
    });
    return result;
}

} // namespace merovingian::auth
