// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// oauth::Page, the one renderer of the server's HTML pages, and page_headers (ADR-0815, ADR-0772).

#include "merovingian/crypto/Encoding.hpp"
#include "merovingian/crypto/Sha256.hpp"
#include "merovingian/oauth/HtmlText.hpp"
#include "merovingian/oauth/Page.hpp"
#include "merovingian/oauth/PageDetail.hpp"
#include "merovingian/oauth/PageForm.hpp"
#include "merovingian/oauth/PageHeaders.hpp"
#include "merovingian/oauth/ParsedUri.hpp"
#include "merovingian/oauth/SubmitButton.hpp"
#include "merovingian/oauth/TextInput.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::oauth::HtmlText;
using merovingian::oauth::Page;
using merovingian::oauth::PageDetail;
using merovingian::oauth::PageForm;
using merovingian::oauth::ParsedUri;
using merovingian::oauth::SubmitButton;
using merovingian::oauth::TextInput;

// Unescaped text has no way in: neither a string nor a view makes an HtmlText.
static_assert(!std::is_constructible_v<HtmlText, std::string>);
static_assert(!std::is_constructible_v<HtmlText, std::string_view>);
static_assert(!std::is_default_constructible_v<HtmlText>);

// The markup-breaking payload, escaped.
constexpr auto hostile = std::string_view{"\"><script>alert('x')</script>&amp;"};
constexpr auto hostile_escaped = std::string_view{"&quot;&gt;&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;amp;"};

[[nodiscard]] auto escaped(std::string_view text) -> HtmlText
{
    auto html = HtmlText::escape(text);
    REQUIRE(html.has_value());
    return std::move(*html);
}

[[nodiscard]] auto count(std::string_view haystack, std::string_view needle) -> std::size_t
{
    auto found = std::size_t{0U};
    for (auto at = haystack.find(needle); at != std::string_view::npos; at = haystack.find(needle, at + 1U))
    {
        ++found;
    }
    return found;
}

[[nodiscard]] auto header(std::vector<std::pair<std::string, std::string>> const& headers, std::string_view name)
    -> std::string
{
    auto const it = std::ranges::find_if(headers, [name](auto const& entry) {
        return entry.first == name;
    });
    REQUIRE(it != headers.end());
    return it->second;
}

[[nodiscard]] auto read(std::string_view text) -> ParsedUri
{
    auto parsed = ParsedUri::read(text);
    REQUIRE(std::holds_alternative<ParsedUri>(parsed));
    return std::get<ParsedUri>(std::move(parsed));
}

constexpr auto fixed_policy = std::string_view{"default-src 'none'; style-src 'sha256-"};

} // namespace

SCENARIO("HtmlText escapes the five markup characters and refuses unsafe text", "[oauth][page][security]")
{
    GIVEN("the hostile payload, and text with a NUL, invalid UTF-8, a right-to-left override and a control byte")
    {
        auto with_nul = std::string{"a"};
        with_nul.push_back('\0');

        WHEN("each is escaped")
        {
            auto const markup = HtmlText::escape(hostile);

            THEN("the payload is escaped and every unsafe text is refused, never repaired")
            {
                REQUIRE(markup.has_value());
                REQUIRE(markup->html() == hostile_escaped);
                REQUIRE_FALSE(HtmlText::escape(with_nul).has_value());
                REQUIRE_FALSE(HtmlText::escape("a\xff").has_value());
                REQUIRE_FALSE(HtmlText::escape("a\xc0\xaf").has_value());
                REQUIRE_FALSE(HtmlText::escape("pay\xe2\x80\xaelapyap").has_value());
                REQUIRE_FALSE(HtmlText::escape("a\x1b[31m").has_value());
                REQUIRE_FALSE(HtmlText::escape("").has_value());
            }
        }
    }
}

SCENARIO("HtmlText is capped at 4096 bytes before escaping", "[oauth][page][boundary]")
{
    GIVEN("texts of 4096 and 4097 bytes")
    {
        auto const at_cap = std::string(HtmlText::max_text_bytes, '<');
        auto const over_cap = at_cap + "<";

        WHEN("each is escaped")
        {
            auto const accepted = HtmlText::escape(at_cap);

            THEN("4096 bytes are escaped whole and 4097 are refused")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(accepted->html().size() == HtmlText::max_text_bytes * 4U);
                REQUIRE_FALSE(HtmlText::escape(over_cap).has_value());
            }
        }
    }
}

SCENARIO("Hostile text in every slot of a page stays text", "[oauth][page][security]")
{
    GIVEN("a page with the hostile payload as title, paragraph, notice, error, details, link label and form parts")
    {
        auto page = Page{escaped(hostile)};
        page.paragraph(escaped(hostile));
        page.notice(escaped(hostile));
        page.error(escaped(hostile));
        auto const details = std::array{
            PageDetail{escaped(hostile), escaped(hostile)},
            PageDetail{HtmlText{"Device ID"}, escaped(std::string(255U, 'D'))},
        };
        page.details(details);
        REQUIRE(page.link(escaped(hostile), "https://example.com/tos?a=1&b='2'"));

        auto form = PageForm{"/_merovingian/oauth2/authorize"};
        form.hidden("pending", escaped(hostile));
        REQUIRE(form.input(TextInput{"username", escaped(hostile), "username", false, escaped(hostile)}));
        REQUIRE(form.input(TextInput{"password", escaped(hostile), "current-password", true}));
        REQUIRE(form.button(SubmitButton{"decision", "approve", escaped(hostile)}));
        REQUIRE(page.form(form));

        WHEN("it is rendered")
        {
            auto const html = page.render();

            THEN("the payload appears only escaped, and the page has no script, handler or inline style")
            {
                REQUIRE(html.find("<script") == std::string::npos);
                REQUIRE(html.find("\"><") == std::string::npos);
                REQUIRE(html.find("javascript:") == std::string::npos);
                REQUIRE(html.find("style=") == std::string::npos);
                REQUIRE(html.find(" on") == std::string::npos);
                // Title, heading, paragraph, notice, error, detail label and value, link label, hidden value, two
                // input labels, the input value and the button label.
                REQUIRE(count(html, hostile_escaped) == 13U);
                REQUIRE(count(html, "<style>") == 1U);
                REQUIRE(html.find("href=\"https://example.com/tos?a=1&amp;b=&#39;2&#39;\"") != std::string::npos);
                REQUIRE(html.find("<form method=\"post\" action=\"/_merovingian/oauth2/authorize\">") !=
                        std::string::npos);
                REQUIRE(html.find("<dd><bdi>" + std::string(255U, 'D') + "</bdi></dd>") != std::string::npos);
            }
        }
    }
}

SCENARIO("A link is written only for an https URL the URI reader accepts", "[oauth][page][security]")
{
    GIVEN("an empty page")
    {
        auto page = Page{HtmlText{"Links"}};

        WHEN("links to other schemes and malformed URLs are added")
        {
            auto const refused = std::array<std::string_view, 9>{
                "javascript:alert(1)",    "JAVASCRIPT:alert(1)",       "data:text/html,<script>alert(1)</script>",
                "http://example.com/",    "HTTPS://example.com/",      "https:example.com",
                "https://example.com/#x", "https://user@example.com/", "//example.com/",
            };

            THEN("each is refused and nothing reaches the page")
            {
                for (auto const target : refused)
                {
                    INFO(target);
                    REQUIRE_FALSE(page.link(HtmlText{"go"}, target));
                }
                REQUIRE(page.render().find("<a ") == std::string::npos);
            }
        }
    }
}

SCENARIO("A form has at most two distinct buttons and never prefills a password", "[oauth][page]")
{
    GIVEN("a form at a fixed path")
    {
        auto form = PageForm{"/_merovingian/oauth2/authorize"};

        WHEN("buttons and inputs are added")
        {
            auto const first = form.button(SubmitButton{"decision", "approve", HtmlText{"Allow"}});
            auto const repeat = form.button(SubmitButton{"decision", "approve", HtmlText{"Allow again"}});
            auto const second = form.button(SubmitButton{"decision", "deny", HtmlText{"Deny"}});
            auto const third = form.button(SubmitButton{"other", "x", HtmlText{"Third"}});
            auto const prefilled_password =
                form.input(TextInput{"password", HtmlText{"Password"}, "current-password", true, HtmlText{"secret"}});
            auto const password = form.input(TextInput{"password", HtmlText{"Password"}, "current-password", true});

            THEN("the repeat, the third button and the prefilled password are refused")
            {
                REQUIRE(first);
                REQUIRE_FALSE(repeat);
                REQUIRE(second);
                REQUIRE_FALSE(third);
                REQUIRE_FALSE(prefilled_password);
                REQUIRE(password);
                auto const html = form.html();
                REQUIRE(count(html, "<button") == 2U);
                REQUIRE(html.find("secret") == std::string::npos);
                REQUIRE(html.find("<input type=\"password\" id=\"field-password\" name=\"password\" "
                                  "autocomplete=\"current-password\" required>") != std::string::npos);
            }
        }
        AND_WHEN("a form with no button is given to a page")
        {
            auto page = Page{HtmlText{"Empty"}};
            auto const added = page.form(form);

            THEN("the page refuses it")
            {
                REQUIRE_FALSE(added);
                REQUIRE(page.render().find("<form") == std::string::npos);
            }
        }
    }
}

SCENARIO("The page headers allow exactly the fixed style block by its hash", "[oauth][page][security]")
{
    GIVEN("the fixed style text and a rendered page")
    {
        auto const digest = merovingian::crypto::sha256(merovingian::oauth::page_style());
        REQUIRE(digest.has_value());
        auto const encoded = merovingian::crypto::base64_original_encode(*digest);
        REQUIRE(encoded.has_value());
        auto const html = Page{HtmlText{"Sign in"}}.render();

        WHEN("the headers are built")
        {
            auto const headers = merovingian::oauth::page_headers();

            THEN("the policy names the style text's SHA-256 and every fixed header is present")
            {
                REQUIRE(html.find("<style>" + std::string{merovingian::oauth::page_style()} + "</style>") !=
                        std::string::npos);
                REQUIRE(header(headers, "Content-Security-Policy") ==
                        std::string{fixed_policy} + *encoded +
                            "'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
                REQUIRE(header(headers, "Content-Type") == "text/html; charset=utf-8");
                REQUIRE(header(headers, "X-Frame-Options") == "DENY");
                // ADR-0784: same-origin, in the header and in the page's own meta element, which must agree: a
                // same-origin form post then carries a Referer naming this server, and no other origin sees one.
                REQUIRE(header(headers, "Referrer-Policy") == "same-origin");
                REQUIRE(html.find("<meta name=\"referrer\" content=\"same-origin\">") != std::string::npos);
                REQUIRE(html.find("no-referrer") == std::string::npos);
                REQUIRE(header(headers, "Cache-Control") == "no-store");
                REQUIRE(headers.size() == 5U);
            }
        }
    }
}

SCENARIO("A redirect target adds only its own origin to form-action", "[oauth][page][security]")
{
    GIVEN("redirect targets whose paths and queries try to inject directives and sources")
    {
        auto const web = read("https://app.example.com:8443/cb;script-src%20*?x=1;default-src%20*,'unsafe-inline'");
        auto const loopback = read("http://127.0.0.1:5000/cb?a=;b");
        auto const native = read("com.example.app:/cb;script-src");
        auto const ipv6_loopback = read("http://[::1]:5000/cb?a=;b");

        WHEN("headers are built for each")
        {
            auto const web_policy = header(merovingian::oauth::page_headers(web), "Content-Security-Policy");
            auto const loopback_policy = header(merovingian::oauth::page_headers(loopback), "Content-Security-Policy");
            auto const native_policy = header(merovingian::oauth::page_headers(native), "Content-Security-Policy");
            auto const ipv6_policy = header(merovingian::oauth::page_headers(ipv6_loopback), "Content-Security-Policy");

            THEN("each policy has the same five directives and ends with the target's origin or scheme")
            {
                for (auto const& policy : {web_policy, loopback_policy, native_policy, ipv6_policy})
                {
                    REQUIRE(count(policy, ";") == 4U);
                    REQUIRE(policy.find("script-src") == std::string::npos);
                    REQUIRE(policy.find("unsafe") == std::string::npos);
                }
                REQUIRE(web_policy.ends_with("; form-action 'self' https://app.example.com:8443"));
                REQUIRE(loopback_policy.ends_with("; form-action 'self' http://127.0.0.1:5000"));
                REQUIRE(native_policy.ends_with("; form-action 'self' com.example.app:"));
                // CSP has no form for an IPv6 host, so a bracketed loopback target adds its scheme (ADR-0811).
                REQUIRE(ipv6_policy.ends_with("; form-action 'self' http:"));
                REQUIRE(ipv6_policy.find('[') == std::string::npos);
            }
        }
    }
}

SCENARIO("A target that is no valid redirect adds no form-action source", "[oauth][page][security]")
{
    GIVEN("URIs a caller should never pass: a bare scheme with no dot, javascript:, data: and ftp://")
    {
        auto const targets = std::array{read("https:example.com"), read("javascript:alert(1)"),
                                        read("data:text/html,x"), read("ftp://example.com/")};

        WHEN("headers are built for each")
        {
            THEN("form-action stays 'self' alone")
            {
                for (auto const& target : targets)
                {
                    INFO(target.text());
                    REQUIRE(header(merovingian::oauth::page_headers(target), "Content-Security-Policy")
                                .ends_with("; form-action 'self'"));
                }
            }
        }
    }
}
