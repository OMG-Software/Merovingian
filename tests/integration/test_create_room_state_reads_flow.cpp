// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Run-3 audit C35 (resource-exhaustion.create-room.auth-event-map-scans-every-room-state-row-per-event). Every event
// create_room composes under runtime.mutex was authorised against an auth map built by walking the current state of
// every room on the server. The state an event's composition reads must be bounded by the keys it names in its own
// room (ADR-0344), so the rows examined do not grow with other rooms' state.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/CreateRoomOptions.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RoomService.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

using namespace merovingian;

// Rows of other rooms' current state seeded before each createRoom.
constexpr auto other_room_rows = std::size_t{4000U};
constexpr auto initial_state_entries = 20;

[[nodiscard]] auto make_config() -> config::Config
{
    auto security = config::SecurityConfig{};
    security.secrets.master_key_file = tests::shared_master_key_file();
    tests::enable_token_registration(security);
    return {config::ServerConfig{},           config::ListenersConfig{}, tests::in_memory_database_config(), security,
            config::ClientRateLimitsConfig{}, config::LogModulesConfig{}};
}

// Appends `rows` member rows of rooms this test never touches again, and puts the state index back in step.
auto seed_other_room_rows(database::PersistentStore& store, std::size_t first, std::size_t rows) -> void
{
    for (auto i = first; i < first + rows; ++i)
    {
        store.state.push_back({"!other" + std::to_string(i % 8U) + ":remote.example", "m.room.member",
                               "@user" + std::to_string(i) + ":remote.example", "$other" + std::to_string(i)});
    }
    database::rebuild_state_index(store);
}

[[nodiscard]] auto room_options(std::string const& invitee) -> homeserver::CreateRoomOptions
{
    auto options = homeserver::CreateRoomOptions{};
    for (auto k = 0; k < initial_state_entries; ++k)
    {
        options.initial_state.push_back(canonicaljson::parse_lossless(R"({"type":"org.example.x","state_key":"k)" +
                                                                      std::to_string(k) + R"(","content":{}})")
                                            .value);
    }
    options.invitees.push_back(invitee);
    return options;
}

struct LoggedIn final
{
    std::string user_id{};
    std::string token{};
};

[[nodiscard]] auto register_and_login(homeserver::HomeserverRuntime& runtime, std::string const& localpart) -> LoggedIn
{
    auto const registered =
        homeserver::register_local_user(runtime, localpart, "CorrectHorse7!", tests::registration_token);
    REQUIRE(registered.ok);
    auto const login = homeserver::login_local_user(runtime, registered.value, "CorrectHorse7!", "DEV1");
    REQUIRE(login.ok);
    return {registered.value, login.value};
}

} // namespace

SCENARIO("createRoom reads the new room's state by key, never every room's state",
         "[homeserver][create_room][state-index][security]")
{
    GIVEN("a server holding other rooms' current state, and three local users")
    {
        auto started = homeserver::start_runtime(make_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto const bob = register_and_login(runtime, "bob");
        auto const carol = register_and_login(runtime, "carol");
        auto& store = runtime.database.persistent_store;
        seed_other_room_rows(store, 0U, other_room_rows);

        WHEN("alice creates a room, the other rooms' state doubles, and bob creates the same room")
        {
            auto const before_first = store.state_rows_examined.value();
            auto const first = homeserver::create_room(runtime, alice.token, room_options(carol.user_id));
            auto const first_examined = store.state_rows_examined.value() - before_first;

            seed_other_room_rows(store, other_room_rows, other_room_rows);
            auto const before_second = store.state_rows_examined.value();
            auto const second = homeserver::create_room(runtime, bob.token, room_options(carol.user_id));
            auto const second_examined = store.state_rows_examined.value() - before_second;

            THEN("each room is made with the state asked for")
            {
                REQUIRE(first.ok);
                REQUIRE(second.ok);
                for (auto const& [room_id, creator] : {
                         std::pair{first.value,  alice.user_id},
                         std::pair{second.value, bob.user_id  }
                })
                {
                    CHECK(database::find_current_state_event_id(store, room_id, "m.room.create", "").has_value());
                    CHECK(database::find_current_state_event_id(store, room_id, "m.room.member", creator).has_value());
                    CHECK(database::find_current_state_event_id(store, room_id, "m.room.member", carol.user_id)
                              .has_value());
                    for (auto k = 0; k < initial_state_entries; ++k)
                    {
                        CHECK(database::find_current_state_event_id(store, room_id, "org.example.x",
                                                                    "k" + std::to_string(k))
                                  .has_value());
                    }
                }
            }
            THEN("the rows examined do not depend on how much state other rooms hold")
            {
                CHECK(first_examined < other_room_rows);
                CHECK(second_examined == first_examined);
            }
        }
    }
}
