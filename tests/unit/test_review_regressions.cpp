// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <merovingian/config/config.hpp>
#include <merovingian/database/migration.hpp>
#include <merovingian/database/persistent_store.hpp>
#include <merovingian/database/schema.hpp>
#include <merovingian/homeserver/vertical_slice.hpp>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

} // namespace

SCENARIO("Admin health remains admin-only after router split", "[homeserver][security][review]")
{
    GIVEN("a runtime with an admin user and a regular user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const admin_user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!");
        auto const admin_login =
            merovingian::homeserver::login_local_user(runtime, admin_user.value, "CorrectHorse7!", "ADMIN1");
        auto const normal_user = merovingian::homeserver::register_local_user(runtime, "bob", "CorrectHorse8!");
        auto const normal_login =
            merovingian::homeserver::login_local_user(runtime, normal_user.value, "CorrectHorse8!", "USER1");
        REQUIRE(admin_login.ok);
        REQUIRE(normal_login.ok);

        WHEN("both users request admin health")
        {
            auto const admin_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", admin_login.value, {}});
            auto const normal_response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", normal_login.value, {}});

            THEN("only the admin session can read operational health")
            {
                REQUIRE(admin_response.status == 200U);
                REQUIRE(normal_response.status == 401U);
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_admin_user(runtime, normal_login.value).has_value());
            }
        }
    }
}

SCENARIO("Migration planning rejects unsupported future versions without iterating", "[database][migration][review]")
{
    GIVEN("a far future schema version")
    {
        auto const future_version = merovingian::database::current_schema_version() + 1000000U;

        WHEN("a migration plan is requested")
        {
            auto const plan = merovingian::database::migration_plan_between(future_version, 0U);
            auto const validation = merovingian::database::migration_plan_is_valid(plan);

            THEN("the unsupported range is represented as an invalid bounded plan")
            {
                REQUIRE(plan.current_version == future_version);
                REQUIRE(plan.target_version == 0U);
                REQUIRE(plan.steps.empty());
                REQUIRE_FALSE(validation.valid);
                REQUIRE(validation.reason == "migration plan has no steps");
            }
        }
    }
}

SCENARIO("Migration application reapplies upgrade statements after downgrade", "[database][migration][review]")
{
    GIVEN("a schema upgraded, downgraded, and then upgraded again")
    {
        auto const upgraded =
            merovingian::database::apply_migration_plan({}, merovingian::database::migration_plan_between(0U, 1U));
        REQUIRE(upgraded.ok);
        auto const downgraded = merovingian::database::apply_migration_plan(
            upgraded.state, merovingian::database::migration_plan_between(1U, 0U));
        REQUIRE(downgraded.ok);

        WHEN("the schema is upgraded again")
        {
            auto const reapplied = merovingian::database::apply_migration_plan(
                downgraded.state, merovingian::database::migration_plan_between(0U, 1U));

            THEN("tables are recreated even though migration history still contains the old upgrade record")
            {
                REQUIRE(reapplied.ok);
                REQUIRE(reapplied.state.version == 1U);
                REQUIRE(reapplied.state.tables.size() == merovingian::database::initial_schema_tables().size());
            }
        }
    }
}

SCENARIO("Persistent store records insert statements only for accepted user and device rows",
         "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("duplicate users and devices are stored")
        {
            auto const first_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const duplicate_user = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:2", false, false, false});
            auto const first_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const duplicate_device =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Duplicate laptop"});

            THEN("rejected duplicates do not leave replay statements behind")
            {
                REQUIRE(first_user);
                REQUIRE_FALSE(duplicate_user);
                REQUIRE(first_device);
                REQUIRE_FALSE(duplicate_device);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "insert_user");
                REQUIRE(store.prepared_statements[1].name == "insert_device");
            }
        }
    }
}

SCENARIO("Persistent store rejects duplicate token hashes before recording inserts", "[database][persistence][review]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("the same token hash is stored twice")
        {
            auto const first = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});
            auto const duplicate = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:abc", false});

            THEN("only one token row and statement are recorded")
            {
                REQUIRE(first);
                REQUIRE_FALSE(duplicate);
                REQUIRE(store.access_tokens.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 1U);
                REQUIRE(store.prepared_statements.front().name == "insert_access_token");
            }
        }
    }
}

SCENARIO("Persistent store matches state event JSON with whitespace and upserts current state",
         "[database][persistence][review]")
{
    GIVEN("state events with equivalent formatted JSON")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        auto const first_event =
            merovingian::database::store_event(store, {"$event1:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        auto const second_event =
            merovingian::database::store_event(store, {"$event2:example.org", "!room:example.org", "@alice:example.org",
                                                       R"({ "type" : "m.room.topic" , "state_key" : "" })"});
        REQUIRE(first_event);
        REQUIRE(second_event);

        WHEN("the same current-state key is stored twice")
        {
            auto const first_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event1:example.org"});
            auto const second_state = merovingian::database::store_state(
                store, {"!room:example.org", "m.room.topic", "", "$event2:example.org"});

            THEN("formatted JSON is accepted and the current-state row is replaced")
            {
                REQUIRE(first_state);
                REQUIRE(second_state);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.state.front().event_id == "$event2:example.org");
                REQUIRE(store.prepared_statements.back().name == "upsert_state");
            }
        }
    }
}

SCENARIO("Persisted local event ids are unique across rooms", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with two rooms")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!");
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const first_room = merovingian::homeserver::create_room(runtime, login.value);
        auto const second_room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(first_room.ok);
        REQUIRE(second_room.ok);

        WHEN("one event is sent to each room")
        {
            auto const first_event =
                merovingian::homeserver::send_event(runtime, login.value, first_room.value, "event-one");
            auto const second_event =
                merovingian::homeserver::send_event(runtime, login.value, second_room.value, "event-two");

            THEN("event ids do not collide in persistent storage")
            {
                REQUIRE(first_event.ok);
                REQUIRE(second_event.ok);
                REQUIRE(first_event.value != second_event.value);
                REQUIRE(runtime.database.persistent_store.events.size() == 2U);
                REQUIRE(runtime.database.persistent_store.events[0].event_id !=
                        runtime.database.persistent_store.events[1].event_id);
            }
        }
    }
}

SCENARIO("Sending a state event mirrors current state", "[homeserver][rooms][review]")
{
    GIVEN("a logged-in local user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!");
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        auto const room = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room.ok);

        WHEN("a room state event is sent")
        {
            auto const event = merovingian::homeserver::send_event(runtime, login.value, room.value,
                                                                   R"({ "type" : "m.room.topic" , "state_key" : "" })");

            THEN("the event is persisted and materialized as current state")
            {
                REQUIRE(event.ok);
                REQUIRE(runtime.database.persistent_store.events.size() == 1U);
                REQUIRE(runtime.database.persistent_store.state.size() == 1U);
                REQUIRE(runtime.database.persistent_store.state.front().event_type == "m.room.topic");
                REQUIRE(runtime.database.persistent_store.state.front().state_key.empty());
                REQUIRE(runtime.database.persistent_store.state.front().event_id == event.value);
            }
        }
    }
}
