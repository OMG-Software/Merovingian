// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// An OAuth 2.0 page response is marked in its type (LocalHttpResponse::page, ADR-0785): the client-server boundary
// adds no CORS header to it, while every other response keeps the CORS headers the spec requires.

#include "merovingian/config/CorsConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/Page.hpp"
#include "merovingian/oauth/PageHeaders.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace
{

namespace hs = merovingian::homeserver;

[[nodiscard]] auto count_header(hs::LocalHttpResponse const& response, std::string_view name) -> std::size_t
{
    auto count = std::size_t{0U};
    for (auto const& [header_name, value] : response.headers)
    {
        if (header_name == name)
        {
            ++count;
        }
    }
    return count;
}

[[nodiscard]] auto header_value(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    for (auto const& [header_name, value] : response.headers)
    {
        if (header_name == name)
        {
            return value;
        }
    }
    return {};
}

} // namespace

SCENARIO("An OAuth 2.0 page response gets no CORS header at the client-server boundary",
         "[oauth][page][page-response][security]")
{
    GIVEN("a hand-built page response, a JSON response, and a CORS policy that allows every origin")
    {
        auto page = hs::LocalHttpResponse{};
        page.status = 200U;
        page.body = merovingian::oauth::Page{merovingian::oauth::HtmlText{"Sign in"}}.render();
        page.headers = merovingian::oauth::page_headers();
        page.page = true;
        auto const page_headers_before = page.headers;
        auto const body_before = page.body;
        auto json = hs::LocalHttpResponse{};
        json.status = 200U;
        json.body = "{}";
        auto cors = merovingian::config::CorsConfig{};
        cors.allowed_origins = {"*"};
        auto request = hs::LocalHttpRequest{"GET", "/_merovingian/oauth2/authorize", {}, {}};
        request.headers.push_back({"Origin", "https://evil.example"});
        auto preflight = hs::LocalHttpRequest{"OPTIONS", "/_merovingian/oauth2/authorize", {}, {}};
        preflight.headers.push_back({"Origin", "https://evil.example"});

        WHEN("the boundary headers are applied to each, for a request and a preflight")
        {
            auto page_preflight = page;
            hs::apply_client_response_headers(request, page, cors);
            hs::apply_client_response_headers(preflight, page_preflight, cors);
            hs::apply_client_response_headers(request, json, cors);

            THEN("the page has no Access-Control or Vary header, only nosniff added, and its body unchanged")
            {
                for (auto const* response : {&page, &page_preflight})
                {
                    for (auto const& [name, value] : response->headers)
                    {
                        REQUIRE_FALSE(name.starts_with("Access-Control-"));
                        REQUIRE(name != "Vary");
                    }
                    REQUIRE(count_header(*response, "X-Content-Type-Options") == 1U);
                    REQUIRE(response->headers.size() == page_headers_before.size() + 1U);
                    REQUIRE(response->body == body_before);
                    REQUIRE(header_value(*response, "Content-Type") == "text/html; charset=utf-8");
                    REQUIRE(header_value(*response, "Referrer-Policy") == "same-origin");
                }
            }

            THEN("a response that is not a page still gets the CORS headers")
            {
                REQUIRE(header_value(json, "Access-Control-Allow-Origin") == "*");
                REQUIRE(count_header(json, "X-Content-Type-Options") == 1U);
            }
        }
    }
}
