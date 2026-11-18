// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// The pure rules of the OAuth 2.0 token and revocation endpoints (ADR-0791): which form content types they read, and
// the access token lifetime and `expires_in` they answer with.

#include "merovingian/oauth/AccessTokenLifetime.hpp"
#include "merovingian/oauth/FormContentType.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string_view>

using merovingian::oauth::access_token_lifetime_ms;
using merovingian::oauth::api_form_content_type_is_accepted;
using merovingian::oauth::default_access_token_lifetime_ms;
using merovingian::oauth::expires_in_seconds;
using merovingian::oauth::page_form_content_type_is_accepted;

SCENARIO("A token request is a form body, with no parameter or only charset=utf-8", "[oauth][token-rules]")
{
    GIVEN("the content types a client may send")
    {
        WHEN("each is judged for a token or revocation request")
        {
            THEN("the form type alone, in any case, and with a UTF-8 charset are accepted")
            {
                CHECK(api_form_content_type_is_accepted("application/x-www-form-urlencoded"));
                CHECK(api_form_content_type_is_accepted("Application/X-WWW-Form-URLEncoded"));
                CHECK(api_form_content_type_is_accepted("application/x-www-form-urlencoded;charset=UTF-8"));
                CHECK(api_form_content_type_is_accepted("application/x-www-form-urlencoded; charset=utf-8"));
                CHECK(api_form_content_type_is_accepted("application/x-www-form-urlencoded; charset=\"UTF-8\""));
            }

            THEN("another type, another charset, another parameter or nothing at all is refused")
            {
                CHECK_FALSE(api_form_content_type_is_accepted(""));
                CHECK_FALSE(api_form_content_type_is_accepted("application/json"));
                CHECK_FALSE(api_form_content_type_is_accepted("multipart/form-data"));
                CHECK_FALSE(api_form_content_type_is_accepted("application/x-www-form-urlencoded; charset=latin1"));
                CHECK_FALSE(api_form_content_type_is_accepted("application/x-www-form-urlencoded; boundary=x"));
                CHECK_FALSE(api_form_content_type_is_accepted("application/x-www-form-urlencoded; charset=utf-8; x=y"));
                CHECK_FALSE(api_form_content_type_is_accepted("application/x-www-form-urlencodedx"));
                CHECK_FALSE(api_form_content_type_is_accepted("application/x-www-form-urlencoded;"));
            }
        }

        WHEN("each is judged for a page's form post")
        {
            THEN("only the type alone, in any case, is accepted")
            {
                CHECK(page_form_content_type_is_accepted("application/x-www-form-urlencoded"));
                CHECK(page_form_content_type_is_accepted("APPLICATION/X-WWW-FORM-URLENCODED"));
                CHECK_FALSE(page_form_content_type_is_accepted("application/x-www-form-urlencoded;charset=UTF-8"));
                CHECK_FALSE(page_form_content_type_is_accepted("application/json"));
                CHECK_FALSE(page_form_content_type_is_accepted(""));
            }
        }
    }
}

SCENARIO("An OAuth access token always expires, and expires_in is its lifetime in whole seconds",
         "[oauth][token-rules]")
{
    GIVEN("the configured access token lifetimes")
    {
        WHEN("the lifetime is configured, or configured as 0 (no expiry for a legacy token)")
        {
            auto const configured = access_token_lifetime_ms(300'000);
            auto const unlimited = access_token_lifetime_ms(0);

            THEN("a configured lifetime is used, and 0 is replaced by one hour")
            {
                CHECK(configured == 300'000);
                CHECK(unlimited == default_access_token_lifetime_ms);
                CHECK(default_access_token_lifetime_ms == 3'600'000);
            }
        }

        WHEN("expires_in is computed")
        {
            THEN("it is rounded down to whole seconds, at least 1 for a positive lifetime")
            {
                CHECK(expires_in_seconds(3'600'000) == 3600);
                CHECK(expires_in_seconds(1'999) == 1);
                CHECK(expires_in_seconds(1) == 1);
                CHECK(expires_in_seconds(0) == 0);
                CHECK(expires_in_seconds(std::int64_t{2'592'000'000}) == 2'592'000);
            }
        }
    }
}
