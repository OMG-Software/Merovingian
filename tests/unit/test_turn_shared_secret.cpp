// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// TURN shared-secret credentials (the coturn REST API, `use-auth-secret`): HMAC-SHA1, the credential format,
// the config rules and GET /voip/turnServer. A choice of this server (ADR-0480), so a unit test.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/crypto/HmacSha1.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/TurnCredentials.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto bytes_of(std::string_view text) -> std::vector<std::uint8_t>
{
    return {text.begin(), text.end()};
}

[[nodiscard]] auto hex(std::array<std::uint8_t, 20U> const& digest) -> std::string
{
    constexpr auto digits = std::string_view{"0123456789abcdef"};
    auto out = std::string{};
    for (auto const byte : digest)
    {
        out.push_back(digits[byte >> 4U]);
        out.push_back(digits[byte & 0x0FU]);
    }
    return out;
}

} // namespace

// RFC 2202 test cases 1 and 2 for HMAC-SHA1.
SCENARIO("hmac_sha1 matches the RFC 2202 vectors", "[crypto][hmac][turn]")
{
    GIVEN("the RFC 2202 key and data pairs")
    {
        WHEN("the MAC is computed")
        {
            auto const first =
                merovingian::crypto::hmac_sha1(std::vector<std::uint8_t>(20U, 0x0bU), bytes_of("Hi There"));
            auto const second =
                merovingian::crypto::hmac_sha1(bytes_of("Jefe"), bytes_of("what do ya want for nothing?"));

            THEN("it equals the published digests")
            {
                REQUIRE(first.has_value());
                REQUIRE(second.has_value());
                REQUIRE(hex(*first) == "b617318655057264e28bc0b6fb378c8ef146be00");
                REQUIRE(hex(*second) == "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
            }
        }
    }
}

// coturn REST API: username "<expiry>:<user>", password base64(HMAC-SHA1(secret, username)).
SCENARIO("make_turn_credentials follows the coturn REST API format", "[homeserver][turn]")
{
    GIVEN("a fixed secret, user, clock and lifetime")
    {
        auto const secret = bytes_of("north");

        WHEN("credentials are made at 1700000000 with a one day lifetime")
        {
            auto const credentials =
                merovingian::homeserver::make_turn_credentials(secret, "@alice:example.org", 1'700'000'000U, 86'400U);

            THEN("the username is the expiry then the user ID and the password is the base64 HMAC of it")
            {
                REQUIRE(credentials.has_value());
                REQUIRE(credentials->username == "1700086400:@alice:example.org");
                REQUIRE(credentials->password == "7kAkbzEsPm8QgksGNCt6Ul1FuvY=");
            }
        }

        WHEN("the secret is empty")
        {
            auto const credentials = merovingian::homeserver::make_turn_credentials({}, "@alice:example.org", 1U, 1U);

            THEN("no credentials are made")
            {
                REQUIRE_FALSE(credentials.has_value());
            }
        }
    }
}

SCENARIO("server.turn.shared_secret_file is parsed and validated", "[config][turn]")
{
    GIVEN("a TURN server with a shared secret file")
    {
        auto const parsed = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:turn.example.org:3478\nserver.turn.shared_secret_file=/run/secrets/turn\n");

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(parsed.config);

            THEN("the path is kept and nothing is reported")
            {
                REQUIRE(parsed.config.server().turn.shared_secret_file == "/run/secrets/turn");
                REQUIRE(findings.empty());
            }
        }
    }

    GIVEN("static credentials and a shared secret together")
    {
        auto const parsed = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:turn.example.org:3478\nserver.turn.username=u\nserver.turn.password=p\n"
            "server.turn.shared_secret_file=/run/secrets/turn\n");

        WHEN("validated")
        {
            auto const findings = merovingian::config::validate(parsed.config);

            THEN("the configuration is refused")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE(findings.front().field == "server.turn.shared_secret_file");
            }
        }
    }

    GIVEN("a shared secret with no TURN server")
    {
        auto const parsed =
            merovingian::config::parse_key_value_config("server.turn.shared_secret_file=/run/secrets/turn\n");

        WHEN("validated")
        {
            THEN("it is refused: it would advertise nothing")
            {
                REQUIRE_FALSE(merovingian::config::validate(parsed.config).empty());
            }
        }
    }

    GIVEN("two configurations that differ only in the secret file path")
    {
        auto const before = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:t\nserver.turn.shared_secret_file=/a\n");
        auto const after = merovingian::config::parse_key_value_config(
            "server.turn.server=turn:t\nserver.turn.shared_secret_file=/b\n");

        WHEN("a reload is planned")
        {
            auto const plan = merovingian::config::build_reload_plan(before.config, after.config);

            THEN("the change is named")
            {
                auto found = false;
                for (auto const& change : plan.changes())
                {
                    found = found || change.key == "server.turn.shared_secret_file";
                }
                REQUIRE(found);
            }
        }
    }
}
