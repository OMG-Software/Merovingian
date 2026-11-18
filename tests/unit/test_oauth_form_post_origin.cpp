// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The form-post origin rule of the OAuth 2.0 pages (ADR-0784): Origin present and equal to the base URL's origin,
// Sec-Fetch-Site, when present, same-origin; everything else refused.

#include "merovingian/oauth/FormPostOrigin.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <optional>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

using merovingian::oauth::form_post_origin;
using merovingian::oauth::form_post_origin_is_accepted;
using merovingian::oauth::OAuthBaseUrl;

[[nodiscard]] auto base(std::string_view text) -> OAuthBaseUrl
{
    auto result = OAuthBaseUrl::read(text);
    REQUIRE(std::holds_alternative<OAuthBaseUrl>(result));
    return std::get<OAuthBaseUrl>(std::move(result));
}

} // namespace

SCENARIO("A form post is accepted only from this server's own origin", "[oauth][form-origin][security]")
{
    GIVEN("a base URL on the default https port, with a path")
    {
        auto const base_url = base("https://Matrix.Example.org/prefix/");

        WHEN("its origin is computed")
        {
            THEN("it is lower-case https with no port and no path")
            {
                REQUIRE(form_post_origin(base_url) == "https://matrix.example.org");
            }
        }

        WHEN("a post names that origin, with Sec-Fetch-Site same-origin or with none")
        {
            THEN("both are accepted")
            {
                REQUIRE(form_post_origin_is_accepted(base_url, "https://matrix.example.org", "same-origin"));
                REQUIRE(form_post_origin_is_accepted(base_url, "https://matrix.example.org", std::nullopt));
            }
        }

        WHEN("a post names any other Origin, or none")
        {
            constexpr auto refused = std::array{
                std::string_view{"null"},
                std::string_view{""},
                std::string_view{"https://matrix.example.org:443"},
                std::string_view{"https://matrix.example.org/"},
                std::string_view{"https://Matrix.Example.org"},
                std::string_view{"http://matrix.example.org"},
                std::string_view{"https://evil.example.org"},
                std::string_view{"https://matrix.example.org.evil.example"},
                std::string_view{"https://matrix.example.org:8443"},
                std::string_view{" https://matrix.example.org"},
            };

            THEN("each is refused, and an absent Origin is refused")
            {
                for (auto const origin : refused)
                {
                    REQUIRE_FALSE(form_post_origin_is_accepted(base_url, origin, "same-origin"));
                }
                REQUIRE_FALSE(form_post_origin_is_accepted(base_url, std::nullopt, "same-origin"));
                REQUIRE_FALSE(form_post_origin_is_accepted(base_url, std::nullopt, std::nullopt));
            }
        }

        WHEN("the right Origin comes with a Sec-Fetch-Site other than same-origin")
        {
            constexpr auto refused =
                std::array{std::string_view{"cross-site"}, std::string_view{"same-site"}, std::string_view{"none"},
                           std::string_view{"Same-Origin"}, std::string_view{""}};

            THEN("each is refused")
            {
                for (auto const site : refused)
                {
                    REQUIRE_FALSE(form_post_origin_is_accepted(base_url, "https://matrix.example.org", site));
                }
            }
        }
    }

    GIVEN("a base URL that names a port")
    {
        auto const on_port = base("https://matrix.example.org:8448");
        auto const on_default = base("https://matrix.example.org:443");

        WHEN("their origins are compared")
        {
            THEN("another port is kept and the default port is left out, as a browser writes them")
            {
                REQUIRE(form_post_origin(on_port) == "https://matrix.example.org:8448");
                REQUIRE(form_post_origin_is_accepted(on_port, "https://matrix.example.org:8448", "same-origin"));
                REQUIRE_FALSE(form_post_origin_is_accepted(on_port, "https://matrix.example.org", "same-origin"));
                REQUIRE(form_post_origin(on_default) == "https://matrix.example.org");
                REQUIRE(form_post_origin_is_accepted(on_default, "https://matrix.example.org", "same-origin"));
                REQUIRE_FALSE(
                    form_post_origin_is_accepted(on_default, "https://matrix.example.org:443", "same-origin"));
            }
        }
    }
}
