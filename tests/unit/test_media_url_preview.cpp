// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/media/url_preview.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto property(merovingian::media::OpenGraphData const& data, std::string_view key) -> std::string
{
    auto const found = std::ranges::find_if(data.properties, [key](auto const& entry) {
        return entry.first == key;
    });
    return found == data.properties.end() ? std::string{} : found->second;
}

} // namespace

SCENARIO("OpenGraph extraction reads og meta tags and the title", "[media][url-preview][preview]")
{
    GIVEN("an HTML page with OpenGraph tags written in several styles")
    {
        auto const html = std::string{R"(<!doctype html><html><head>
<title>  Page   title  </title>
<meta property="og:title" content="Matrix Blog Post">
<META PROPERTY='og:description' CONTENT='This is a really cool &amp; useful post'>
<meta name="og:image" content="/img/logo.png" />
<meta property="og:image:width" content=48>
<meta property="og:title" content="second title is ignored">
<meta name="description" content="not OpenGraph">
</head><body></body></html>)"};

        WHEN("it is extracted")
        {
            auto const data = merovingian::media::extract_open_graph(html);

            THEN("each og property is read once, entity-decoded, and other meta tags are ignored")
            {
                REQUIRE(property(data, "og:title") == "Matrix Blog Post");
                REQUIRE(property(data, "og:description") == "This is a really cool & useful post");
                REQUIRE(property(data, "og:image") == "/img/logo.png");
                REQUIRE(property(data, "og:image:width") == "48");
                REQUIRE(data.properties.size() == 4U);
                REQUIRE(property(data, "description").empty());
            }

            THEN("the title is trimmed and its whitespace collapsed")
            {
                REQUIRE(data.title == "Page title");
            }
        }
    }
}

SCENARIO("OpenGraph extraction runs nothing and skips script, style and comments", "[media][url-preview][preview]")
{
    GIVEN("meta tags hidden inside a script, a style block and a comment")
    {
        auto const html =
            std::string{R"(<script>document.write('<meta property="og:title" content="from script">');</script>
<style>/* <meta property="og:title" content="from style"> */</style>
<!-- <meta property="og:title" content="from comment"> -->
<meta property="og:title" content="real">)"};

        WHEN("it is extracted")
        {
            auto const data = merovingian::media::extract_open_graph(html);

            THEN("only the real tag counts")
            {
                REQUIRE(property(data, "og:title") == "real");
                REQUIRE(data.properties.size() == 1U);
            }
        }
    }
}

SCENARIO("OpenGraph extraction is bounded", "[media][url-preview][preview][security]")
{
    GIVEN("a page with far more og tags and longer values than a preview keeps")
    {
        auto html = std::string{};
        for (auto index = 0; index < 500; ++index)
        {
            html += "<meta property=\"og:k" + std::to_string(index) + "\" content=\"" + std::string(5000U, 'x') + "\">";
        }

        WHEN("it is extracted")
        {
            auto const data = merovingian::media::extract_open_graph(html);

            THEN("the number of properties, each value and the total are capped")
            {
                REQUIRE(data.properties.size() <= merovingian::media::max_open_graph_properties);
                auto total = std::size_t{0U};
                for (auto const& [key, value] : data.properties)
                {
                    REQUIRE(value.size() <= merovingian::media::max_open_graph_value_bytes);
                    total += key.size() + value.size();
                }
                REQUIRE(total <= merovingian::media::max_open_graph_total_bytes);
            }
        }
    }

    GIVEN("a pathological page of unterminated tags and nested script openers")
    {
        auto html = std::string{};
        for (auto index = 0; index < 20000; ++index)
        {
            html += "<script<meta<title";
        }

        WHEN("it is extracted")
        {
            auto const started = std::chrono::steady_clock::now();
            auto const data = merovingian::media::extract_open_graph(html);
            auto const elapsed = std::chrono::steady_clock::now() - started;

            THEN("it finishes promptly with nothing extracted")
            {
                REQUIRE(data.properties.empty());
                REQUIRE(elapsed < std::chrono::seconds{2});
            }
        }
    }

    GIVEN("values with control characters and invalid UTF-8")
    {
        auto const html = std::string{"<meta property=\"og:title\" content=\"line\r\none\">"} +
                          "<meta property=\"og:description\" content=\"bad \xC3\x28 utf8\">";

        WHEN("it is extracted")
        {
            auto const data = merovingian::media::extract_open_graph(html);

            THEN("control characters become a space and invalid UTF-8 is dropped")
            {
                REQUIRE(property(data, "og:title") == "line one");
                REQUIRE(property(data, "og:description").empty());
            }
        }
    }
}

SCENARIO("Only HTML content types are parsed for previews", "[media][url-preview][preview]")
{
    GIVEN("several content types")
    {
        THEN("text/html and application/xhtml+xml, with parameters, are HTML; nothing else is")
        {
            REQUIRE(merovingian::media::content_type_is_html("text/html"));
            REQUIRE(merovingian::media::content_type_is_html("Text/HTML; charset=utf-8"));
            REQUIRE(merovingian::media::content_type_is_html("application/xhtml+xml"));
            REQUIRE_FALSE(merovingian::media::content_type_is_html("text/plain"));
            REQUIRE_FALSE(merovingian::media::content_type_is_html("image/svg+xml"));
            REQUIRE_FALSE(merovingian::media::content_type_is_html("text/htmlx"));
            REQUIRE_FALSE(merovingian::media::content_type_is_html(""));
        }
    }
}

SCENARIO("Preview redirects and image references resolve only to http(s) URLs", "[media][url-preview][preview]")
{
    GIVEN("a page URL")
    {
        auto const base = std::string{"https://example.com/blog/post?x=1"};

        THEN("absolute, scheme-relative and absolute-path references resolve; others are refused")
        {
            REQUIRE(merovingian::media::resolve_preview_reference(base, "https://cdn.example.net/a.png") ==
                    "https://cdn.example.net/a.png");
            REQUIRE(merovingian::media::resolve_preview_reference(base, "//cdn.example.net/a.png") ==
                    "https://cdn.example.net/a.png");
            REQUIRE(merovingian::media::resolve_preview_reference(base, "/img/a.png") ==
                    "https://example.com/img/a.png");
            REQUIRE(merovingian::media::resolve_preview_reference(base, "/img/a.png#frag") ==
                    "https://example.com/img/a.png");
            REQUIRE(merovingian::media::resolve_preview_reference(base, "a.png").empty());
            REQUIRE(merovingian::media::resolve_preview_reference(base, "file:///etc/passwd").empty());
            REQUIRE(merovingian::media::resolve_preview_reference(base, "gopher://example.com/").empty());
            REQUIRE(merovingian::media::resolve_preview_reference(base, "").empty());
            REQUIRE(merovingian::media::resolve_preview_reference(base, "/" + std::string(5000U, 'a')).empty());
        }
    }
}

SCENARIO("The URL preview cache is bounded and expires entries", "[media][url-preview][preview]")
{
    GIVEN("a cache holding at most two entries")
    {
        auto cache = merovingian::media::UrlPreviewCache{};
        cache.store("https://a.example/", {true, "a", 1000U}, 2U);
        cache.store("https://b.example/", {true, "b", 1000U}, 2U);

        WHEN("a third URL is stored after the first was read again")
        {
            REQUIRE(cache.find("https://a.example/", 10U).has_value());
            cache.store("https://c.example/", {false, {}, 1000U}, 2U);

            THEN("the least recently used entry is evicted")
            {
                REQUIRE(cache.size() == 2U);
                REQUIRE(cache.find("https://a.example/", 10U).has_value());
                REQUIRE_FALSE(cache.find("https://b.example/", 10U).has_value());
                REQUIRE(cache.find("https://c.example/", 10U).has_value());
            }
        }

        WHEN("an entry is read after it expires")
        {
            auto const found = cache.find("https://a.example/", 1000U);

            THEN("it is gone")
            {
                REQUIRE_FALSE(found.has_value());
                REQUIRE(cache.size() == 1U);
            }
        }

        WHEN("the cap is zero")
        {
            auto empty = merovingian::media::UrlPreviewCache{};
            empty.store("https://a.example/", {true, "a", 1000U}, 0U);

            THEN("nothing is stored")
            {
                REQUIRE(empty.size() == 0U);
            }
        }
    }
}
