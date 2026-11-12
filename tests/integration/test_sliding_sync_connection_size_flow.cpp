// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto size_test_config() -> merovingian::config::Config
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

[[nodiscard]] auto login_token(merovingian::homeserver::ClientServerRuntime& rt) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        rt,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const body =
        std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                    R"("password":"CorrectHorse7!","device_id":"ALICE"})"};
    auto const login =
        merovingian::homeserver::handle_client_server_request(rt, {"POST", "/_matrix/client/v3/login", {}, body});
    REQUIRE(login.response.status == 200U);
    auto const key = std::string_view{R"("access_token":")"};
    auto const at = login.response.body.find(key);
    REQUIRE(at != std::string::npos);
    auto const start = at + key.size();
    return login.response.body.substr(start, login.response.body.find('"', start) - start);
}

[[nodiscard]] auto sliding_sync_status(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                                       std::string const& body) -> std::uint16_t
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/unstable/org.matrix.msc4186/sync", token, body}, /*can_wait=*/false);
    return result.response.status;
}

// A request on `conn_id` whose one list asks for a required_state type of `type_size` bytes.
[[nodiscard]] auto heavy_request(std::string_view conn_id, std::size_t type_size) -> std::string
{
    return R"({"conn_id":")" + std::string{conn_id} + R"(","lists":{"a":{"ranges":[[0,9]],"required_state":[[")" +
           std::string(type_size, 't') + R"(",""]]}}})";
}

} // namespace

SCENARIO("A sliding sync request over a size cap is refused and leaves no connection behind",
         "[homeserver][sliding-sync][retained-size][integration]")
{
    GIVEN("a user with a device")
    {
        auto started = merovingian::homeserver::start_client_server(size_test_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = login_token(rt);
        auto room_types = std::string{};
        for (auto i = std::size_t{0U}; i < 17U; ++i)
        {
            room_types += i == 0U ? R"("m.space")" : R"(,"m.space")";
        }

        WHEN("a list names 17 room_types")
        {
            auto const status = sliding_sync_status(
                rt, token,
                R"({"conn_id":"c","lists":{"a":{"ranges":[[0,9]],"filters":{"room_types":[)" + room_types + "]}}}}");

            THEN("it is 400 and no connection state was created")
            {
                REQUIRE(status == 400U);
                REQUIRE(rt.homeserver.sliding_sync_connections.empty());
            }
        }
        WHEN("the conn_id is 256 bytes long")
        {
            auto const status = sliding_sync_status(
                rt, token, R"({"conn_id":")" + std::string(256U, 'c') + R"(","lists":{"a":{"ranges":[[0,9]]}}})");

            THEN("it is 400 and no connection state was created")
            {
                REQUIRE(status == 400U);
                REQUIRE(rt.homeserver.sliding_sync_connections.empty());
            }
        }
        WHEN("a request with 16 room_types and a 255 byte conn_id is sent")
        {
            auto const status =
                sliding_sync_status(rt, token,
                                    R"({"conn_id":")" + std::string(255U, 'c') +
                                        R"(","lists":{"a":{"ranges":[[0,9]],"filters":{"room_types":[)" +
                                        room_types.substr(0, room_types.rfind(',')) + "]}}}}");

            THEN("it is served and its connection is kept")
            {
                REQUIRE(status == 200U);
                REQUIRE(rt.homeserver.sliding_sync_connections.size() == 1U);
            }
        }
    }
}

SCENARIO("One device's sliding sync connections together keep a bounded number of list bytes",
         "[homeserver][sliding-sync][retained-size][integration]")
{
    GIVEN("a device holding four connections that each keep about 60 KiB of lists")
    {
        auto started = merovingian::homeserver::start_client_server(size_test_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = login_token(rt);
        for (auto const* conn : {"c1", "c2", "c3", "c4"})
        {
            REQUIRE(sliding_sync_status(rt, token, heavy_request(conn, 60'000U)) == 200U);
        }

        WHEN("a fifth connection asks to keep another 60 KiB")
        {
            auto const status = sliding_sync_status(rt, token, heavy_request("c5", 60'000U));

            THEN("it is refused and no fifth entry exists")
            {
                REQUIRE(status == 400U);
                REQUIRE(rt.homeserver.sliding_sync_connections.size() == 4U);
            }
        }
        WHEN("a fifth connection asks for a small, ordinary list")
        {
            auto const status = sliding_sync_status(rt, token, R"({"conn_id":"c5","lists":{"a":{"ranges":[[0,9]]}}})");

            THEN("it is served")
            {
                REQUIRE(status == 200U);
                REQUIRE(rt.homeserver.sliding_sync_connections.size() == 5U);
            }
        }
        WHEN("an existing connection replaces its lists with a small one")
        {
            auto const status = sliding_sync_status(rt, token, R"({"conn_id":"c1","lists":{"a":{"ranges":[[0,9]]}}})");

            THEN("it is served, since its old lists are not counted against it")
            {
                REQUIRE(status == 200U);
                REQUIRE(rt.homeserver.sliding_sync_connections.size() == 4U);
            }
        }
    }
}
