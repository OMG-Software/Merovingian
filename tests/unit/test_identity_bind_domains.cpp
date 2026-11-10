// SPDX-License-Identifier: GPL-3.0-or-later
//
// server.identity_server.allowed_bind_domains: the email domains this server
// will tell an identity server about. Spec: M_THREEPID_DENIED, "The server does
// not permit this third-party identifier. This may happen if the server only
// permits, for example, email addresses from a particular domain"
// (docs/matrix-v1.19-spec/client-server-api.md, Common error codes).

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/identity/IdentityServerClient.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

} // namespace

SCENARIO("Bind domain matching compares the email domain exactly and ignores letter case", "[identity][config][3pid]")
{
    GIVEN("an allow list of example.org")
    {
        auto const allowed = std::vector<std::string>{"example.org"};

        WHEN("addresses are checked")
        {
            using merovingian::identity::threepid_bind_domain_permitted;
            auto const same = threepid_bind_domain_permitted(allowed, "email", "a@example.org");
            auto const upper = threepid_bind_domain_permitted(allowed, "email", "a@EXAMPLE.ORG");
            auto const sub = threepid_bind_domain_permitted(allowed, "email", "a@evil.example.org");
            auto const suffix = threepid_bind_domain_permitted(allowed, "email", "a@notexample.org");
            auto const no_at = threepid_bind_domain_permitted(allowed, "email", "example.org");
            auto const msisdn = threepid_bind_domain_permitted(allowed, "msisdn", "447700900123");
            auto const open = threepid_bind_domain_permitted({}, "email", "a@anything.net");

            THEN("only the exact domain matches; msisdn has no domain and an empty list restricts nothing")
            {
                REQUIRE(same);
                REQUIRE(upper);
                REQUIRE_FALSE(sub);
                REQUIRE_FALSE(suffix);
                REQUIRE_FALSE(no_at);
                REQUIRE(msisdn);
                REQUIRE(open);
            }
        }
    }
}
