// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// C17 (ADR-0685): the password reset mail for an address is throttled across sessions, so a caller who names the
// address cannot take the only send slot of each minute and leave its owner a session with no usable code. The
// address keeps one code per throttle interval that every session of it judges a typed code against, and a day's mail
// to one address is capped.
//
// Spec: Matrix Client-Server API v1.19, "POST /account/password/email/requestToken" and "POST /account/password"
// (`m.login.email.identity`). ../../docs/matrix-v1.19-spec/client-server-api.md

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentThreePidBinding.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/PasswordReset.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <string>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto address = "alice@example.net";
constexpr auto submit_path = "/_matrix/client/unstable/org.merovingian/account/password/email/submitToken";

[[nodiscard]] auto make_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// A relay nothing listens on: the code is queued for it and the send fails in the background; the tests read the code
// from the session that holds it.
auto prepare(hs::ClientServerRuntime& runtime) -> void
{
    auto& email = runtime.homeserver.config.server().email;
    email.smtp_url = "smtp://127.0.0.1:1";
    email.require_tls = false;
    email.from = "matrix@example.org";
    REQUIRE(
        hs::handle_client_server_request(runtime, {"POST",
                                                   "/_matrix/client/v3/register",
                                                   {},
                                                   merovingian::tests::registration_json("alice", "CorrectHorse7!")})
            .response.status == 200U);
    auto binding = merovingian::database::PersistentThreePidBinding{};
    binding.user_id = "@alice:example.org";
    binding.medium = "email";
    binding.address = address;
    binding.added_at_ms = 1700000000000U;
    binding.validated_at_ms = 1700000000000U;
    REQUIRE(merovingian::database::store_account_threepid(runtime.homeserver.database.persistent_store, binding));
}

[[nodiscard]] auto request_token(hs::ClientServerRuntime& runtime, std::string const& secret, int attempt)
    -> hs::DispatchResult
{
    return hs::handle_client_server_request(runtime, {"POST",
                                                      "/_matrix/client/v3/account/password/email/requestToken",
                                                      {},
                                                      R"({"client_secret":")" + secret + R"(","email":")" + address +
                                                          R"(","send_attempt":)" + std::to_string(attempt) + "}"});
}

[[nodiscard]] auto session_of(hs::ClientServerRuntime& runtime, std::string const& secret)
    -> hs::RegistrationValidationSession&
{
    auto const found = std::ranges::find_if(runtime.registration_validation_sessions, [&secret](auto const& session) {
        return session.client_secret == secret;
    });
    REQUIRE(found != runtime.registration_validation_sessions.end());
    return *found;
}

[[nodiscard]] auto submit(hs::ClientServerRuntime& runtime, std::string const& secret, std::string const& code)
    -> hs::LocalHttpResponse
{
    auto const sid = session_of(runtime, secret).sid;
    return hs::handle_client_server_request(
               runtime, {"POST",
                         submit_path,
                         {},
                         R"({"sid":")" + sid + R"(","client_secret":")" + secret + R"(","token":")" + code + R"("})"})
        .response;
}

[[nodiscard]] auto reset_password(hs::ClientServerRuntime& runtime, std::string const& secret) -> hs::LocalHttpResponse
{
    auto const sid = session_of(runtime, secret).sid;
    return hs::handle_client_server_request(
               runtime,
               {"POST",
                "/_matrix/client/v3/account/password",
                {},
                R"({"new_password":"BrandNewHorse9!","auth":{"type":"m.login.email.identity","threepid_creds":{"sid":")" +
                    sid + R"(","client_secret":")" + secret + R"("}}})"})
        .response;
}

// Moves a session's last send back past the throttle interval, as if a minute had gone by.
auto let_a_minute_pass(hs::ClientServerRuntime& runtime, std::string const& secret) -> void
{
    session_of(runtime, secret).reset_sent_at_ms -= hs::password_reset_address_interval_ms + 1000U;
}

} // namespace

SCENARIO("A session the throttle gave no code uses the code mailed to the address",
         "[password-reset][c17][integration]")
{
    GIVEN("an account with an address, a caller who named it first and its owner who asked second")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        prepare(runtime);
        REQUIRE(request_token(runtime, "attacker-secret", 1).response.status == 200U);
        REQUIRE(request_token(runtime, "owner-secret", 1).response.status == 200U);
        REQUIRE(session_of(runtime, "owner-secret").reset_token.empty());

        WHEN("the caller asks again after the interval, mailing a fresh code, and the owner types it")
        {
            let_a_minute_pass(runtime, "attacker-secret");
            REQUIRE(request_token(runtime, "attacker-secret", 2).response.status == 200U);
            auto const mailed = session_of(runtime, "attacker-secret").reset_token;
            REQUIRE_FALSE(mailed.empty());
            auto const owner_submit = submit(runtime, "owner-secret", mailed);

            THEN("the owner's session validates and resets the password, and the caller's session does not")
            {
                REQUIRE(owner_submit.status == 200U);
                REQUIRE(reset_password(runtime, "attacker-secret").status == 401U);
                REQUIRE(reset_password(runtime, "owner-secret").status == 200U);
            }
            THEN("the code is spent: no session of the address holds it any more")
            {
                REQUIRE(session_of(runtime, "attacker-secret").reset_token.empty());
            }
        }

        WHEN("the caller's own session submits a wrong code")
        {
            let_a_minute_pass(runtime, "attacker-secret");
            REQUIRE(request_token(runtime, "attacker-secret", 2).response.status == 200U);
            auto const refused = submit(runtime, "attacker-secret", "AAAAAAAA");

            THEN("it is refused and the session is not validated")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(session_of(runtime, "attacker-secret").validated_at_ms == 0U);
            }
        }
    }
}

SCENARIO("A day's reset mail to one address is capped", "[password-reset][c17][integration]")
{
    GIVEN("an account with an address that has been mailed the daily cap")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        prepare(runtime);
        for (auto attempt = 1; attempt <= static_cast<int>(hs::password_reset_address_daily_cap); ++attempt)
        {
            if (attempt > 1)
            {
                let_a_minute_pass(runtime, "caller");
            }
            REQUIRE(request_token(runtime, "caller", attempt).response.status == 200U);
            REQUIRE_FALSE(session_of(runtime, "caller").reset_token.empty());
        }
        auto const last_code = session_of(runtime, "caller").reset_token;

        WHEN("another request would mail it again")
        {
            let_a_minute_pass(runtime, "caller");
            auto const answered = request_token(runtime, "caller", 100);

            THEN("it is answered alike, nothing is mailed and the last code still validates")
            {
                REQUIRE(answered.response.status == 200U);
                REQUIRE(runtime.password_reset_mail_times.at(address).size() == hs::password_reset_address_daily_cap);
                REQUIRE(session_of(runtime, "caller").reset_token == last_code);
                REQUIRE(submit(runtime, "caller", last_code).status == 200U);
            }
        }
    }
}
