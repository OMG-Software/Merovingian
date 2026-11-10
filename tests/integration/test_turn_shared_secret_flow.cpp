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

class SecretFile final
{
public:
    explicit SecretFile(std::string_view contents)
        : m_directory{temporary_directory() / ("merovingian-turn-" + std::to_string(std::random_device{}()))}
    {
        std::filesystem::create_directories(m_directory);
        std::filesystem::permissions(m_directory, std::filesystem::perms::owner_all);
        m_path = m_directory / "turn_secret";
        auto stream = std::ofstream{m_path, std::ios::binary};
        stream << contents;
        stream.close();
        std::filesystem::permissions(m_path, std::filesystem::perms::owner_read);
    }
    ~SecretFile()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(m_directory, ignored);
    }
    SecretFile(SecretFile const&) = delete;
    auto operator=(SecretFile const&) -> SecretFile& = delete;

    [[nodiscard]] auto path() const -> std::string
    {
        return m_path.string();
    }

private:
    std::filesystem::path m_directory;
    std::filesystem::path m_path;
};

[[nodiscard]] auto secret_turn_config(std::string const& secret_path, std::uint32_t ttl) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.turn.server = "turn:turn.example.org:3478?transport=udp";
    server.turn.shared_secret_file = secret_path;
    server.turn.ttl_seconds = ttl;
    return {
        std::move(server),
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& localpart)
    -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json(localpart, "CorrectHorse7!")})
                .response.status == 200U);
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":"D1"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

} // namespace

SCENARIO("GET /voip/turnServer issues per-user time-limited credentials from a shared secret",
         "[homeserver][turn][client-server]")
{
    GIVEN("a server whose TURN shared secret is in an owner-only file")
    {
        auto const secret = SecretFile{"north\n"};
        auto started = merovingian::homeserver::start_client_server(secret_turn_config(secret.path(), 3600U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");
        auto const bob = login(runtime, "bob");

        WHEN("two users ask for credentials")
        {
            auto const now = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                    .count());
            auto const a = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", alice, {}});
            auto const b = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", bob, {}});

            THEN("each gets a username naming an expiry and themselves, a password that is the coturn HMAC of it, "
                 "and the ttl")
            {
                REQUIRE(a.response.status == 200U);
                REQUIRE(b.response.status == 200U);
                auto const body_a = parse_object(a.response.body);
                auto const body_b = parse_object(b.response.body);
                auto const* user_a = string_member(body_a, "username");
                auto const* user_b = string_member(body_b, "username");
                auto const* pass_a = string_member(body_a, "password");
                auto const* pass_b = string_member(body_b, "password");
                REQUIRE((user_a != nullptr && user_b != nullptr && pass_a != nullptr && pass_b != nullptr));
                REQUIRE(user_a->ends_with(":@alice:example.org"));
                REQUIRE(user_b->ends_with(":@bob:example.org"));
                REQUIRE(*pass_a != *pass_b);
                auto const expiry = std::stoull(*user_a);
                REQUIRE(expiry >= now + 3600U);
                REQUIRE(expiry <= now + 3600U + 5U);
                auto const expected = merovingian::homeserver::make_turn_credentials(
                    bytes_of("north"), "@alice:example.org", expiry - 3600U, 3600U);
                REQUIRE(expected.has_value());
                REQUIRE(*pass_a == expected->password);
                auto const* ttl = int_member(body_a, "ttl");
                REQUIRE(ttl != nullptr);
                REQUIRE(*ttl == 3600);
            }
        }
    }

    GIVEN("a shared secret path that does not exist")
    {
        auto started = merovingian::homeserver::start_client_server(
            secret_turn_config("/nonexistent/merovingian-turn-secret", 3600U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("credentials are requested")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", alice, {}});

            THEN("the answer is a 500 that names no secret and holds no credentials")
            {
                REQUIRE(result.response.status == 500U);
                REQUIRE(result.response.body.find("password") == std::string::npos);
            }
        }
    }
}
