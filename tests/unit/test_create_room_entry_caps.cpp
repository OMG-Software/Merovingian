// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>

// Audit run-2 F-02. create_room holds runtime.mutex while it composes, signs and commits one event
// per `invite` and `initial_state` entry. The spec (POST /createRoom) sets no number of entries a
// server must accept, so the count is capped before the lock-held work starts (default 100 each,
// `server.client_api.max_create_room_invites` and `max_create_room_initial_state`).

namespace
{

constexpr auto default_entry_cap = std::size_t{100U};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto json_string_after(std::string const& body, std::string const& key) -> std::string
{
    auto const needle = "\"" + key + "\":\"";
    auto const begin = body.find(needle);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + needle.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto invite_list(std::size_t count) -> std::string
{
    auto list = std::string{"["};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        list += (index == 0U ? "\"@u" : ",\"@u") + std::to_string(index) + ":example.org\"";
    }
    return list + "]";
}

[[nodiscard]] auto initial_state_list(std::size_t count) -> std::string
{
    auto list = std::string{"["};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        list += (index == 0U ? "" : ",");
        list += R"({"type":"org.example.state","state_key":")" + std::to_string(index) + R"(","content":{}})";
    }
    return list + "]";
}

[[nodiscard]] auto count_invites_in(merovingian::database::PersistentStore const& store, std::string const& room_id,
                                    std::string const& user_id) -> std::ptrdiff_t
{
    return std::ranges::count_if(store.events, [&](merovingian::database::PersistentEvent const& event) {
        return event.room_id == room_id && event.json.find("\"invite\"") != std::string::npos &&
               event.json.find("\"state_key\":\"" + user_id + "\"") != std::string::npos;
    });
}

} // namespace

SCENARIO("createRoom refuses more invite or initial_state entries than the cap, storing nothing",
         "[rooms][create-room][security]")
{
    GIVEN("a registered user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(registered.response.status == 200U);
        auto const token = json_string_after(registered.response.body, "access_token");
        auto const& store = runtime.homeserver.database.persistent_store;
        auto const rooms_before = store.rooms.size();
        auto const create = [&](std::string const& body) {
            return merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, body});
        };

        WHEN("the invite list is one past the cap")
        {
            auto const answered =
                create(R"({"preset":"private_chat","invite":)" + invite_list(default_entry_cap + 1U) + "}");

            THEN("it is refused with 400 M_TOO_LARGE and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("the initial_state list is one past the cap")
        {
            auto const answered = create(R"({"preset":"private_chat","initial_state":)" +
                                         initial_state_list(default_entry_cap + 1U) + "}");

            THEN("it is refused with 400 M_TOO_LARGE and no room is made")
            {
                REQUIRE(answered.response.status == 400U);
                REQUIRE(answered.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(store.rooms.size() == rooms_before);
            }
        }

        WHEN("both lists are under the cap")
        {
            auto const answered = create(R"({"preset":"private_chat","room_version":"11","invite":)" + invite_list(3U) +
                                         R"(,"initial_state":)" + initial_state_list(3U) + "}");

            THEN("the room is created")
            {
                REQUIRE(answered.response.status == 200U);
                REQUIRE(store.rooms.size() == rooms_before + 1U);
            }
        }

        WHEN("the invite list names one user several times")
        {
            auto const answered = create(
                R"({"preset":"private_chat","room_version":"11","invite":["@dup:example.org","@dup:example.org","@dup:example.org"]})");

            THEN("that user is invited once")
            {
                REQUIRE(answered.response.status == 200U);
                auto const room_id = json_string_after(answered.response.body, "room_id");
                REQUIRE(count_invites_in(store, room_id, "@dup:example.org") == 1);
            }
        }
    }
}
