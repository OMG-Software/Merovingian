// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/email/mailbox_address.hpp"

#include <algorithm>
#include <string_view>

namespace merovingian::email
{

namespace
{

    [[nodiscard]] auto is_ascii_alnum(char byte) noexcept -> bool
    {
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9');
    }

    // RFC 5322 section 3.2.3 atext: ALPHA / DIGIT and these specials.
    [[nodiscard]] auto is_atext(char byte) noexcept -> bool
    {
        constexpr auto specials = std::string_view{"!#$%&'*+-/=?^_`{|}~"};
        return is_ascii_alnum(byte) || specials.find(byte) != std::string_view::npos;
    }

    // Non-empty runs of `allowed` separated by single dots, with no dot at either end.
    template <typename Predicate>
    [[nodiscard]] auto is_dot_separated(std::string_view text, Predicate allowed) noexcept -> bool
    {
        if (text.empty() || text.front() == '.' || text.back() == '.' || text.find("..") != std::string_view::npos)
        {
            return false;
        }
        return std::ranges::all_of(text, [&allowed](char byte) {
            return byte == '.' || allowed(byte);
        });
    }

    // An LDH label: letters, digits and hyphens, not starting or ending with a hyphen, at most 63.
    [[nodiscard]] auto is_ldh_label(std::string_view label) noexcept -> bool
    {
        constexpr auto max_label_bytes = std::size_t{63U};
        if (label.empty() || label.size() > max_label_bytes || label.front() == '-' || label.back() == '-')
        {
            return false;
        }
        return std::ranges::all_of(label, [](char byte) {
            return is_ascii_alnum(byte) || byte == '-';
        });
    }

    [[nodiscard]] auto is_ldh_domain(std::string_view domain) noexcept -> bool
    {
        if (!is_dot_separated(domain, [](char byte) {
                return is_ascii_alnum(byte) || byte == '-';
            }))
        {
            return false;
        }
        auto rest = domain;
        while (!rest.empty())
        {
            auto const dot = rest.find('.');
            if (!is_ldh_label(rest.substr(0U, dot)))
            {
                return false;
            }
            rest = dot == std::string_view::npos ? std::string_view{} : rest.substr(dot + 1U);
        }
        return true;
    }

} // namespace

auto is_safe_mailbox_address(std::string_view address) noexcept -> bool
{
    if (address.empty() || address.size() > max_mailbox_address_bytes)
    {
        return false;
    }
    auto const at = address.find('@');
    if (at == std::string_view::npos || address.find('@', at + 1U) != std::string_view::npos)
    {
        return false;
    }
    auto const local = address.substr(0U, at);
    auto const domain = address.substr(at + 1U);
    if (local.size() > max_mailbox_local_part_bytes || domain.size() > max_mailbox_domain_bytes)
    {
        return false;
    }
    return is_dot_separated(local, is_atext) && is_ldh_domain(domain);
}

} // namespace merovingian::email
