// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// TURN shared-secret credentials (the coturn REST API, `use-auth-secret`): HMAC-SHA1, the credential format,
// the config rules and GET /voip/turnServer. A choice of this server (ADR-0480), so a unit test.

#include "../support/ConsoleLogCapture.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/ModuleLogLevel.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigParser.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/ReloadPlan.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/HmacSha1.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DispatchResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/TurnCredentials.hpp"
#include "merovingian/observability/LogLevel.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>
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

// The first captured line at `level` (the logger's name for it, such as "INFO"), filed under `module`, that names
// `event`; nullopt when there is none.
[[nodiscard]] auto module_line(std::string const& text, std::string_view level, std::string_view module,
                               std::string_view event) -> std::optional<std::string>
{
    auto const level_tag = "<" + std::string{level} + ">";
    auto const module_tag = "  " + std::string{module} + ":  ";
    auto const event_tag = "event=" + std::string{event};
    auto lines = std::istringstream{text};
    for (auto line = std::string{}; std::getline(lines, line);)
    {
        if (line.find(level_tag) != std::string::npos && line.find(module_tag) != std::string::npos &&
            line.find(event_tag) != std::string::npos)
        {
            return line;
        }
    }
    return std::nullopt;
}

// The value of the ` key=value` field in a diagnostic line, up to the next space; nullopt when the line has no such
// field. Matching the whole value keeps `uri_count=1` from passing for `uri_count=10`.
[[nodiscard]] auto field_value(std::string const& line, std::string_view key) -> std::optional<std::string>
{
    auto const marker = " " + std::string{key} + "=";
    auto const start = line.find(marker);
    if (start == std::string::npos)
    {
        return std::nullopt;
    }
    auto const value_start = start + marker.size();
    auto const value_end = line.find(' ', value_start);
    return line.substr(value_start, value_end == std::string::npos ? std::string::npos : value_end - value_start);
}

// Asks for TURN credentials as the user `token` belongs to, through the client-server dispatcher, and returns the
// HTTP response.
[[nodiscard]] auto turn_server(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token)
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"GET", "/_matrix/client/v3/voip/turnServer", token, {}})
        .response;
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

SCENARIO("GET /voip/turnServer lists every server.turn.uris entry in order with shared-secret credentials",
         "[homeserver][turn][turn-uris][client-server]")
{
    GIVEN("a server with two TURN URIs in server.turn.uris and a shared secret file")
    {
        auto const secret = SecretFile{"north\n"};
        auto config = secret_turn_config(secret.path(), 3600U);
        config.server().turn.server.clear();
        config.server().turn.uris = {"turn:turn.example.org:3478?transport=udp", "turns:turn.example.org:5349"};
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("a client asks for credentials")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/voip/turnServer", alice, {}});

            THEN("the credentials are per-user and uris holds both entries in the configured order")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* username = string_member(body, "username");
                REQUIRE(username != nullptr);
                REQUIRE(username->ends_with(":@alice:example.org"));
                auto const* uris = object_member_as_array(body, "uris");
                REQUIRE(uris != nullptr);
                REQUIRE(uris->size() == 2U);
                auto const* first = std::get_if<std::string>(&(*uris)[0U].storage());
                auto const* second = std::get_if<std::string>(&(*uris)[1U].storage());
                REQUIRE(first != nullptr);
                REQUIRE(second != nullptr);
                REQUIRE(*first == "turn:turn.example.org:3478?transport=udp");
                REQUIRE(*second == "turns:turn.example.org:5349");
            }
        }
    }
}

SCENARIO("The turn log files an issued credential under its own module, naming the user and never a credential",
         "[homeserver][turn][logging]")
{
    GIVEN("a server whose TURN shared secret is in an owner-only file, and alice")
    {
        auto const secret = SecretFile{"north-turn-secret\n"};
        auto started = merovingian::homeserver::start_client_server(secret_turn_config(secret.path(), 3600U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("alice is issued credentials with the client_server module silenced and the log captured")
        {
            auto const quiet_client_server =
                ModuleLogLevel{"client_server", merovingian::observability::LogLevel::critical};
            auto const capture = ConsoleLogCapture{};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("an info line under turn names the event, alice, the kind of credential, the ttl and the one URI")
            {
                REQUIRE(response.status == 200U);
                auto const line = module_line(text, "INFO", "turn", "turn.credentials_issued");
                REQUIRE(line.has_value());
                CHECK(field_value(line.value(), "user_id") == "@alice:example.org");
                CHECK(field_value(line.value(), "credential") == "shared_secret");
                CHECK(field_value(line.value(), "ttl_seconds") == "3600");
                CHECK(field_value(line.value(), "uri_count") == "1");
            }

            THEN("the log holds neither the username, the password nor the shared secret")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* username = string_member(body, "username");
                auto const* password = string_member(body, "password");
                REQUIRE((username != nullptr && password != nullptr));
                CHECK(text.find(*username) == std::string::npos);
                CHECK(text.find(*password) == std::string::npos);
                CHECK(text.find("north-turn-secret") == std::string::npos);
            }
        }

        WHEN("alice is issued credentials with the turn module set to error and the log captured")
        {
            auto const quiet_turn = ModuleLogLevel{"turn", merovingian::observability::LogLevel::error};
            auto const capture = ConsoleLogCapture{};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("the credentials are issued and the turn module's level keeps the info line out")
            {
                REQUIRE(response.status == 200U);
                CHECK(text.find("turn.credentials_issued") == std::string::npos);
            }
        }
    }

    GIVEN("a server with two server.turn.uris entries and a shared secret file, and alice")
    {
        auto const secret = SecretFile{"north-turn-secret\n"};
        auto config = secret_turn_config(secret.path(), 3600U);
        config.server().turn.server.clear();
        config.server().turn.uris = {"turn:turn.example.org:3478?transport=udp", "turns:turn.example.org:5349"};
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("alice is issued credentials with the log captured")
        {
            auto const capture = ConsoleLogCapture{};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("the info line counts the two URIs the answer lists")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* uris = object_member_as_array(body, "uris");
                REQUIRE(uris != nullptr);
                REQUIRE(uris->size() == 2U);
                auto const line = module_line(text, "INFO", "turn", "turn.credentials_issued");
                REQUIRE(line.has_value());
                CHECK(field_value(line.value(), "uri_count") == "2");
            }
        }
    }
}

SCENARIO("The turn log names an unreadable shared secret as an error under its own module",
         "[homeserver][turn][logging]")
{
    GIVEN("a shared secret path that does not exist, and alice")
    {
        auto started = merovingian::homeserver::start_client_server(
            secret_turn_config("/nonexistent/merovingian-turn-secret", 3600U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("alice asks for credentials with the client_server module silenced and the log captured")
        {
            auto const quiet_client_server =
                ModuleLogLevel{"client_server", merovingian::observability::LogLevel::critical};
            auto const capture = ConsoleLogCapture{};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("the answer is 500 and an error line under turn names the event, alice and the fixed reason")
            {
                REQUIRE(response.status == 500U);
                auto const line = module_line(text, "ERROR", "turn", "turn.credentials_unavailable");
                REQUIRE(line.has_value());
                CHECK(field_value(line.value(), "user_id") == "@alice:example.org");
                // The reason holds spaces, so it is matched whole rather than through field_value.
                CHECK(line.value().find(" reason=shared secret file unreadable or empty") != std::string::npos);
            }
        }
    }
}

SCENARIO("The turn log files configured static credentials under its own module and never the password",
         "[homeserver][turn][logging]")
{
    GIVEN("a server with a static TURN username and password, and alice")
    {
        auto config = secret_turn_config({}, 86400U);
        config.server().turn.username = "static-turn-user";
        config.server().turn.password = "static-turn-password";
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("alice is issued credentials with the log captured")
        {
            auto const capture = ConsoleLogCapture{};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("an info line under turn names the static credential, and the log holds neither part of it")
            {
                REQUIRE(response.status == 200U);
                auto const line = module_line(text, "INFO", "turn", "turn.credentials_issued");
                REQUIRE(line.has_value());
                CHECK(line.value().find("credential=static") != std::string::npos);
                CHECK(text.find("static-turn-user") == std::string::npos);
                CHECK(text.find("static-turn-password") == std::string::npos);
            }
        }
    }
}

SCENARIO("The turn log says at debug level that no TURN server is configured", "[homeserver][turn][logging]")
{
    GIVEN("a server with no TURN server configured, and alice")
    {
        auto config = secret_turn_config({}, 3600U);
        config.server().turn.server.clear();
        auto started = merovingian::homeserver::start_client_server(std::move(config));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = login(runtime, "alice");

        WHEN("alice asks for credentials with the turn module at debug and the log captured")
        {
            auto const verbose_turn = ModuleLogLevel{"turn", merovingian::observability::LogLevel::debug};
            auto const capture = ConsoleLogCapture{merovingian::observability::LogLevel::debug};
            auto const response = turn_server(runtime, alice);
            auto const text = capture.text();

            THEN("the answer is the empty object and a debug line under turn names the event and alice")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body == "{}");
                auto const line = module_line(text, "DEBUG", "turn", "turn.not_configured");
                REQUIRE(line.has_value());
                CHECK(line.value().find("@alice:example.org") != std::string::npos);
            }
        }
    }
}
