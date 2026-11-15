// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/HostCookie.hpp"

#include "merovingian/core/CookieOctets.hpp"
#include "merovingian/core/ErrorCode.hpp"
#include "merovingian/core/HttpToken.hpp"

namespace merovingian::core
{

namespace
{

    [[nodiscard]] auto name_is_acceptable(std::string_view name) noexcept -> bool
    {
        return name.size() > host_cookie_prefix.size() && name.starts_with(host_cookie_prefix) &&
               http_token_is_valid(name);
    }

    [[nodiscard]] auto same_site_text(CookieSameSite same_site) noexcept -> std::string_view
    {
        return same_site == CookieSameSite::strict ? std::string_view{"Strict"} : std::string_view{"Lax"};
    }

    [[nodiscard]] auto serialise(std::string_view name, std::string_view value, CookieSameSite same_site,
                                 std::uint32_t max_age_seconds) -> std::string
    {
        auto out = std::string{name};
        out.push_back('=');
        out.append(value);
        out.append("; Max-Age=");
        out.append(std::to_string(max_age_seconds));
        out.append("; Path=/; Secure; HttpOnly; SameSite=");
        out.append(same_site_text(same_site));
        return out;
    }

} // namespace

auto host_cookie(std::string_view name, std::string_view value, CookieSameSite same_site, std::uint32_t max_age_seconds)
    -> std::variant<std::string, Error>
{
    if (!name_is_acceptable(name) || value.empty() || !cookie_octets_are_valid(value) ||
        name.size() + value.size() > max_host_cookie_bytes || max_age_seconds == 0U ||
        max_age_seconds > max_host_cookie_age_seconds)
    {
        return Error{ErrorCode::invalid_argument, "cookie name, value or lifetime is not acceptable"};
    }
    return serialise(name, value, same_site, max_age_seconds);
}

auto host_cookie_deletion(std::string_view name, CookieSameSite same_site) -> std::variant<std::string, Error>
{
    if (!name_is_acceptable(name) || name.size() > max_host_cookie_bytes)
    {
        return Error{ErrorCode::invalid_argument, "cookie name is not acceptable"};
    }
    return serialise(name, {}, same_site, 0U);
}

} // namespace merovingian::core
