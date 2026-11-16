// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/oauth/PageHeaders.hpp"

#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Sha256.hpp"
#include "merovingian/oauth/AsciiCase.hpp"

#include <optional>

namespace merovingian::oauth
{
namespace
{

    // Changing a byte here changes the hash in the policy; page_headers() computes it from this text, so the two
    // cannot drift apart. No `url(`, `@import` or font: the policy allows nothing to be fetched.
    constexpr auto style_text =
        std::string_view{"body{margin:0;background:#f4f5f7;color:#1d1f23;font:16px/1.5 system-ui,sans-serif}"
                         "main{max-width:28rem;margin:3rem auto;padding:1.5rem 2rem;background:#fff;border-radius:8px;"
                         "box-shadow:0 1px 3px rgba(0,0,0,.15)}"
                         "h1{font-size:1.4rem;margin:0 0 1rem}"
                         ".notice{padding:.75rem;background:#eef4ff;border-left:4px solid #3867d6}"
                         ".error{padding:.75rem;background:#fdecec;border-left:4px solid #c0392b}"
                         "dl{margin:1rem 0}dt{font-weight:600}dd{margin:0 0 .5rem;overflow-wrap:anywhere}"
                         "label{display:block;margin-top:.75rem;font-weight:600}"
                         "input{box-sizing:border-box;width:100%;padding:.5rem;font:inherit}"
                         ".buttons{display:flex;gap:.75rem;margin-top:1.25rem}"
                         "button{flex:1;padding:.6rem;font:inherit;cursor:pointer}"
                         "a{color:#3867d6;overflow-wrap:anywhere}"};

    [[nodiscard]] auto style_source() -> std::string
    {
        auto const digest = crypto::sha256(style_text);
        if (!digest.has_value())
        {
            return "'none'";
        }
        auto const encoded = crypto::base64_original_encode(*digest);
        if (!encoded.has_value())
        {
            return "'none'";
        }
        return "'sha256-" + *encoded + "'";
    }

    // The extra form-action source for a validated redirect target, or nothing. Defence in depth beyond the caller's
    // contract: with an authority only `http` and `https` are used, and without one only a scheme holding a `.`,
    // as every private-use scheme (a reversed DNS name of two or more labels) does; so `https:` alone, `data:` or
    // `javascript:` can never be added.
    [[nodiscard]] auto redirect_source(ParsedUri const& target) -> std::optional<std::string>
    {
        auto const scheme = ascii_lower(target.scheme());
        if (target.has_authority())
        {
            if (scheme != "https" && scheme != "http")
            {
                return std::nullopt;
            }
            return target.csp_source();
        }
        if (scheme.find('.') == std::string::npos)
        {
            return std::nullopt;
        }
        return target.csp_source();
    }

    [[nodiscard]] auto headers_with(std::optional<std::string> const& extra_form_action)
        -> std::vector<std::pair<std::string, std::string>>
    {
        auto policy = std::string{"default-src 'none'; style-src "};
        policy.append(style_source());
        policy.append("; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
        if (extra_form_action.has_value())
        {
            policy.push_back(' ');
            policy.append(*extra_form_action);
        }
        return {
            {"Content-Type",            "text/html; charset=utf-8"},
            {"Content-Security-Policy", std::move(policy)         },
            {"X-Frame-Options",         "DENY"                    },
            {"Referrer-Policy",         "no-referrer"             },
            {"Cache-Control",           "no-store"                },
        };
    }

} // namespace

auto page_style() noexcept -> std::string_view
{
    return style_text;
}

auto page_headers() -> std::vector<std::pair<std::string, std::string>>
{
    return headers_with(std::nullopt);
}

auto page_headers(ParsedUri const& redirect_target) -> std::vector<std::pair<std::string, std::string>>
{
    return headers_with(redirect_source(redirect_target));
}

} // namespace merovingian::oauth
