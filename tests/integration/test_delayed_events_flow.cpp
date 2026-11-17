// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Delayed events (MSC4140, ADR-0823 to ADR-0826) below the routes: the service functions that schedule, manage and look
// up a delayed event, the job body that sends it, and what they leave in `/sync`. A real runtime and a real store
// (in memory, or a SQLite file for the restart scenarios). No scenario sleeps, starts the job's thread or depends on
// how long anything took: time is `HomeserverRuntime::test_delayed_event_clock_ms` and the job's `now_ms` parameter.
// The feature is not in the Matrix v1.19 specification, so there is no conformance scenario.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/DelayedEventStatus.hpp"
#include "merovingian/database/DelayedEventTable.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DeactivationAudit.hpp"
#include "merovingian/homeserver/DelayedEventAction.hpp"
#include "merovingian/homeserver/DelayedEventScheduleRequest.hpp"
#include "merovingian/homeserver/DelayedEvents.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/OperationResult.hpp"
#include "merovingian/homeserver/RuntimeMutex.hpp"
#include "merovingian/homeserver/StopFlag.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

namespace hs = merovingian::homeserver;
namespace cj = merovingian::canonicaljson;
namespace db = merovingian::database;
using namespace merovingian::tests;

constexpr auto t0 = std::uint64_t{1'700'000'000'000U};
constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

[[nodiscard]] auto base_config(merovingian::config::DatabaseConfig database,
                               merovingian::config::ClientRateLimitsConfig limits = {}) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        std::move(database),
        std::move(security),
        std::move(limits),
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto memory_config(merovingian::config::ClientRateLimitsConfig limits = {}) -> merovingian::config::Config
{
    return base_config(in_memory_database_config(), std::move(limits));
}

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    return base_config(std::move(database));
}

[[nodiscard]] auto request(hs::ClientServerRuntime& runtime, std::string method, std::string target,
                           std::string const& token = {}, std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

// Registers `name` and signs it in on device `device`; the access token.
[[nodiscard]] auto sign_in(hs::ClientServerRuntime& runtime, std::string const& name, std::string const& device)
    -> std::string
{
    REQUIRE(request(runtime, "POST", "/_matrix/client/v3/register", {}, registration_json(name, password)).status ==
            200U);
    auto const login =
        request(runtime, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                    R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + device + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    REQUIRE(string_member(body, "access_token") != nullptr);
    return *string_member(body, "access_token");
}

// A running homeserver with alice and bob in one public room. Alice created it.
class Fixture final
{
public:
    explicit Fixture(merovingian::config::Config const& config)
        : m_started{hs::start_client_server(config)}
    {
        REQUIRE(m_started.started);
        alice_token = sign_in(runtime(), "alice", "D1");
        bob_token = sign_in(runtime(), "bob", "D2");
        auto const created =
            request(runtime(), "POST", "/_matrix/client/v3/createRoom", alice_token, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        room_id = *string_member(parse_object(created.body), "room_id");
        REQUIRE(request(runtime(), "POST", "/_matrix/client/v3/join/" + room_id, bob_token, "{}").status == 200U);
        runtime().homeserver.test_delayed_event_clock_ms = t0;
        runtime().homeserver.test_frozen_event_clock_ms = static_cast<std::int64_t>(t0);
    }

    [[nodiscard]] auto runtime() noexcept -> hs::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto table() noexcept -> db::DelayedEventTable&
    {
        return m_started.runtime.homeserver.database.persistent_store.delayed_events;
    }

    [[nodiscard]] auto event_count() noexcept -> std::size_t
    {
        return m_started.runtime.homeserver.database.persistent_store.events.size();
    }

    std::string alice_token{};
    std::string bob_token{};
    std::string room_id{};

private:
    hs::ClientServerStartResult m_started;
};

[[nodiscard]] auto message_request(Fixture const& fixture, std::string_view user = alice, std::string txn = "txn-1",
                                   std::uint64_t delay_ms = 60'000U) -> hs::DelayedEventScheduleRequest
{
    auto made = hs::DelayedEventScheduleRequest{};
    made.user_id = std::string{user};
    made.device_id = "D1";
    made.room_id = fixture.room_id;
    made.event_type = "m.test.delayed";
    made.content_json = R"({"body":"later"})";
    made.txn_id = std::move(txn);
    made.delay_ms = delay_ms;
    return made;
}

[[nodiscard]] auto state_request(Fixture const& fixture, std::string_view user = alice,
                                 std::uint64_t delay_ms = 60'000U) -> hs::DelayedEventScheduleRequest
{
    auto made = message_request(fixture, user, {}, delay_ms);
    made.event_type = "m.test.state";
    made.state_key = std::string{};
    made.content_json = R"({"v":1})";
    return made;
}

// Every service function below needs the runtime lock; a request handler holds it, so a test takes it here.
[[nodiscard]] auto schedule(Fixture& fixture, hs::DelayedEventScheduleRequest const& made) -> hs::OperationResult
{
    auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
    return hs::schedule_delayed_event(fixture.runtime(), made);
}

[[nodiscard]] auto manage(Fixture& fixture, std::string_view user, std::string_view delay_id,
                          hs::DelayedEventAction action) -> hs::OperationResult
{
    auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
    return hs::manage_delayed_event(fixture.runtime(), user, delay_id, action);
}

[[nodiscard]] auto lookup(Fixture& fixture, std::string_view user, std::string_view delay_id) -> hs::OperationResult
{
    auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
    return hs::delayed_event_lookup(fixture.runtime(), user, delay_id);
}

[[nodiscard]] auto run_job(Fixture& fixture, std::uint64_t now_ms, hs::StopFlag const& stop = {})
    -> std::chrono::milliseconds
{
    return hs::send_due_delayed_events(fixture.runtime(), now_ms, stop);
}

// Runs the job until no scheduled event is due at `now_ms` (the job sends at most one a run), and returns how many runs
// it took. A bound stops a job that makes no progress.
auto drain_job(Fixture& fixture, std::uint64_t now_ms) -> std::size_t
{
    auto runs = std::size_t{0U};
    for (; runs < 1'000U; ++runs)
    {
        auto const* next = fixture.table().earliest_due();
        if (next == nullptr || db::delayed_event_due_ms(*next) > now_ms)
        {
            break;
        }
        std::ignore = run_job(fixture, now_ms);
    }
    return runs;
}

[[nodiscard]] auto scheduled_id(Fixture& fixture, hs::DelayedEventScheduleRequest const& made) -> std::string
{
    auto const result = schedule(fixture, made);
    REQUIRE(result.ok);
    REQUIRE_FALSE(result.value.empty());
    return result.value;
}

[[nodiscard]] auto status_of(Fixture& fixture, std::string_view user, std::string_view delay_id)
    -> db::DelayedEventStatus
{
    auto const* row = fixture.table().find_owned(user, delay_id);
    REQUIRE(row != nullptr);
    return row->status;
}

// The delayed event as `GET` shows it, parsed.
[[nodiscard]] auto looked_up(Fixture& fixture, std::string_view user, std::string_view delay_id) -> cj::Object
{
    auto const result = lookup(fixture, user, delay_id);
    REQUIRE(result.ok);
    return parse_object(result.value);
}

struct Synced final
{
    std::string next_batch{};
    std::optional<cj::Object> event{};
};

// One `/sync` for `token`; `event` is the first timeline event of `type` in `fixture`'s room.
[[nodiscard]] auto sync_for(Fixture& fixture, std::string const& token, std::string const& since, std::string_view type)
    -> Synced
{
    auto const response = request(
        fixture.runtime(), "GET",
        since.empty() ? std::string{"/_matrix/client/v3/sync"} : "/_matrix/client/v3/sync?since=" + since, token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto synced = Synced{};
    synced.next_batch = *string_member(body, "next_batch");
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* joined = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = joined == nullptr ? nullptr : object_member_as_object(*joined, fixture.room_id);
    auto const* timeline = room == nullptr ? nullptr : object_member_as_object(*room, "timeline");
    auto const* events = timeline == nullptr ? nullptr : object_member_as_array(*timeline, "events");
    if (events == nullptr)
    {
        return synced;
    }
    for (auto const& entry : *events)
    {
        auto const* object = std::get_if<cj::Object>(&entry.storage());
        if (object != nullptr && string_member(*object, "type") != nullptr && *string_member(*object, "type") == type)
        {
            synced.event = *object;
            return synced;
        }
    }
    return synced;
}

// Sets `user`'s power in the room to `level` (alice sends the new power levels).
auto set_power(Fixture& fixture, std::string_view user, std::int64_t level) -> void
{
    auto const current =
        request(fixture.runtime(), "GET", "/_matrix/client/v3/rooms/" + fixture.room_id + "/state/m.room.power_levels",
                fixture.alice_token);
    REQUIRE(current.status == 200U);
    auto const levels = parse_object(current.body);
    auto changed = cj::Object{};
    auto users = cj::Object{};
    for (auto const& member : levels)
    {
        if (member.key != "users")
        {
            changed.push_back(member);
            continue;
        }
        if (auto const* held = std::get_if<cj::Object>(&member.value->storage()); held != nullptr)
        {
            for (auto const& entry : *held)
            {
                if (entry.key != user)
                {
                    users.push_back(entry);
                }
            }
        }
    }
    users.push_back(cj::make_member(std::string{user}, cj::Value{level}));
    changed.push_back(cj::make_member("users", cj::Value{std::move(users)}));
    auto const body = cj::serialize_canonical(cj::Value{std::move(changed)}).output;
    REQUIRE(request(fixture.runtime(), "PUT",
                    "/_matrix/client/v3/rooms/" + fixture.room_id + "/state/m.room.power_levels", fixture.alice_token,
                    body)
                .status == 200U);
}

[[nodiscard]] auto nul_text(std::string_view before, std::string_view after) -> std::string
{
    return std::string{before} + std::string(1U, '\0') + std::string{after};
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return temporary_directory() / ("merovingian-delayed-events-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("A scheduled delayed event gets an opaque ID and shows every field on lookup",
         "[homeserver][delayed-events][schedule][lookup]")
{
    GIVEN("alice in a room with bob")
    {
        auto fixture = Fixture{memory_config()};

        WHEN("alice schedules a message event and a state event")
        {
            auto const message_id = scheduled_id(fixture, message_request(fixture));
            auto const state_id = scheduled_id(fixture, state_request(fixture));

            THEN("each ID is short, URL-safe and unguessable, and the lookup shows the stored fields")
            {
                CHECK(message_id != state_id);
                CHECK(message_id.size() >= 22U);
                CHECK(message_id.size() <= 64U);
                CHECK(message_id.find_first_not_of(
                          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") == std::string::npos);

                auto const message = looked_up(fixture, alice, message_id);
                CHECK(*string_member(message, "delay_id") == message_id);
                CHECK(*string_member(message, "room_id") == fixture.room_id);
                CHECK(*string_member(message, "type") == "m.test.delayed");
                CHECK(string_member(message, "state_key") == nullptr);
                CHECK(*int_member(message, "delay_ms") == 60'000);
                CHECK(*int_member(message, "delayed_since_ts") == static_cast<std::int64_t>(t0));
                CHECK(*string_member(*object_member_as_object(message, "content"), "body") == "later");
                CHECK(object_member_as_object(message, "finalised") == nullptr);

                auto const state = looked_up(fixture, alice, state_id);
                REQUIRE(string_member(state, "state_key") != nullptr);
                CHECK(string_member(state, "state_key")->empty());
                CHECK(*string_member(state, "type") == "m.test.state");
            }
        }
    }
}

SCENARIO("Another user's delay ID and an unknown one are the same answer for lookup and every action",
         "[homeserver][delayed-events][manage][lookup][privacy]")
{
    GIVEN("alice's delayed event and bob asking about it")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture));

        WHEN("bob looks it up and acts on it, and asks about IDs that do not exist")
        {
            auto const unknown = std::string{"no-such-delay-id"};
            auto const too_long = std::string(65U, 'x');

            THEN("every answer is the one 404 M_NOT_FOUND, byte for byte")
            {
                auto const reference = lookup(fixture, bob, unknown);
                CHECK_FALSE(reference.ok);
                CHECK(reference.status == 404U);
                CHECK(reference.errcode == "M_NOT_FOUND");
                CHECK(reference.reason == "Delayed event not found.");
                auto const same = [&](hs::OperationResult const& other) {
                    return !other.ok && other.status == reference.status && other.errcode == reference.errcode &&
                           other.reason == reference.reason && other.value == reference.value &&
                           other.retry_after_ms == reference.retry_after_ms;
                };
                CHECK(same(lookup(fixture, bob, id)));
                CHECK(same(lookup(fixture, bob, {})));
                CHECK(same(lookup(fixture, bob, too_long)));
                for (auto const action :
                     {hs::DelayedEventAction::send, hs::DelayedEventAction::cancel, hs::DelayedEventAction::restart})
                {
                    CHECK(same(manage(fixture, bob, id, action)));
                    CHECK(same(manage(fixture, bob, unknown, action)));
                    CHECK(same(manage(fixture, bob, {}, action)));
                    CHECK(same(manage(fixture, bob, too_long, action)));
                }
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("A delayed event is never sent early, and is then sent once with its delay ID shown only to its sender",
         "[homeserver][delayed-events][job][sync]")
{
    GIVEN("a message event due 60 s after it was scheduled and both users synced")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture));
        auto const alice_since = sync_for(fixture, fixture.alice_token, {}, "m.test.delayed").next_batch;
        auto const bob_since = sync_for(fixture, fixture.bob_token, {}, "m.test.delayed").next_batch;
        auto const before = fixture.event_count();
        auto const due = t0 + 60'000U;

        WHEN("the job runs one millisecond before the due time")
        {
            auto const wait = run_job(fixture, due - 1U);

            THEN("nothing is sent and the job asks to run again after the 5 ms pace (the 1 ms left is raised to it)")
            {
                CHECK(fixture.event_count() == before);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK(wait == std::chrono::milliseconds{5});
            }
        }

        WHEN("the job runs at the due time, then again")
        {
            auto const first_wait = run_job(fixture, due);
            auto const second_wait = run_job(fixture, due + 5U);

            THEN("exactly one event is sent, and the room's members receive it")
            {
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK(first_wait == std::chrono::milliseconds{60'000});
                CHECK(second_wait == std::chrono::milliseconds{60'000});

                auto const finalised = *object_member_as_object(looked_up(fixture, alice, id), "finalised");
                auto const event_id = *string_member(finalised, "event_id");
                CHECK(*int_member(finalised, "finalised_ts") == static_cast<std::int64_t>(due));

                auto const for_alice = sync_for(fixture, fixture.alice_token, alice_since, "m.test.delayed");
                REQUIRE(for_alice.event.has_value());
                CHECK(*string_member(*for_alice.event, "event_id") == event_id);
                CHECK(*string_member(*for_alice.event, "sender") == alice);
                auto const* alice_unsigned = object_member_as_object(*for_alice.event, "unsigned");
                REQUIRE(alice_unsigned != nullptr);
                REQUIRE(string_member(*alice_unsigned, "delay_id") != nullptr);
                CHECK(*string_member(*alice_unsigned, "delay_id") == id);
                REQUIRE(string_member(*alice_unsigned, "org.matrix.msc4140.delay_id") != nullptr);
                CHECK(*string_member(*alice_unsigned, "org.matrix.msc4140.delay_id") == id);
                CHECK(string_member(*alice_unsigned, "transaction_id") == nullptr);

                auto const for_bob = sync_for(fixture, fixture.bob_token, bob_since, "m.test.delayed");
                REQUIRE(for_bob.event.has_value());
                CHECK(*string_member(*for_bob.event, "event_id") == event_id);
                auto const* bob_unsigned = object_member_as_object(*for_bob.event, "unsigned");
                CHECK((bob_unsigned == nullptr || string_member(*bob_unsigned, "delay_id") == nullptr));
                CHECK((bob_unsigned == nullptr ||
                       string_member(*bob_unsigned, "org.matrix.msc4140.delay_id") == nullptr));
                CHECK((bob_unsigned == nullptr || string_member(*bob_unsigned, "transaction_id") == nullptr));
            }
        }
    }
}

SCENARIO("A delayed state event is sent as a state event and stamped with the time it is sent",
         "[homeserver][delayed-events][job][timestamp]")
{
    GIVEN("a state event scheduled at t0 and an event clock that has since moved on")
    {
        auto fixture = Fixture{memory_config()};
        auto const state_id = scheduled_id(fixture, state_request(fixture, alice, 30'000U));
        auto const since = sync_for(fixture, fixture.bob_token, {}, "m.test.state").next_batch;
        auto const sent_at = t0 + 123'456U;
        fixture.runtime().homeserver.test_frozen_event_clock_ms = static_cast<std::int64_t>(sent_at);

        WHEN("the job runs after the due time")
        {
            drain_job(fixture, t0 + 30'000U);

            THEN("the event is a state event whose origin_server_ts is the send time, not the schedule time")
            {
                auto const seen = sync_for(fixture, fixture.bob_token, since, "m.test.state");
                REQUIRE(seen.event.has_value());
                REQUIRE(string_member(*seen.event, "state_key") != nullptr);
                CHECK(string_member(*seen.event, "state_key")->empty());
                CHECK(*int_member(*seen.event, "origin_server_ts") == static_cast<std::int64_t>(sent_at));
                CHECK(status_of(fixture, alice, state_id) == db::DelayedEventStatus::sent);
            }
        }
    }
}

SCENARIO("Restarting a delayed event moves its deadline, and every cell of the outcome table is answered",
         "[homeserver][delayed-events][manage]")
{
    GIVEN("a scheduled message event")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture));
        auto const before = fixture.event_count();

        WHEN("it is restarted 20 s later")
        {
            fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 20'000U;
            auto const restarted = manage(fixture, alice, id, hs::DelayedEventAction::restart);

            THEN("the old due time sends nothing and the new one sends")
            {
                CHECK(restarted.ok);
                CHECK(restarted.value.empty());
                CHECK(*int_member(looked_up(fixture, alice, id), "delayed_since_ts") ==
                      static_cast<std::int64_t>(t0 + 20'000U));
                drain_job(fixture, t0 + 60'000U);
                CHECK(fixture.event_count() == before);
                drain_job(fixture, t0 + 80'000U - 1U);
                CHECK(fixture.event_count() == before);
                drain_job(fixture, t0 + 80'000U);
                CHECK(fixture.event_count() == before + 1U);
            }
        }

        WHEN("it is cancelled")
        {
            auto const cancelled = manage(fixture, alice, id, hs::DelayedEventAction::cancel);

            THEN("it is finalised as cancelled with neither an event nor an error, and is never sent")
            {
                CHECK(cancelled.ok);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::cancelled);
                auto const finalised = *object_member_as_object(looked_up(fixture, alice, id), "finalised");
                CHECK(string_member(finalised, "event_id") == nullptr);
                CHECK(object_member_as_object(finalised, "error") == nullptr);
                drain_job(fixture, t0 + 10'000'000U);
                CHECK(fixture.event_count() == before);
            }
        }
    }

    GIVEN("one delayed event in each state of its life")
    {
        auto fixture = Fixture{memory_config()};
        auto const scheduled = scheduled_id(fixture, message_request(fixture, alice, "a", 10'000U));
        auto const sent = scheduled_id(fixture, message_request(fixture, alice, "b", 1'000U));
        auto const cancelled = scheduled_id(fixture, message_request(fixture, alice, "c"));
        auto const failed = scheduled_id(fixture, message_request(fixture, bob, "d", 2'000U));
        auto const being_sent = scheduled_id(fixture, message_request(fixture, alice, "e"));
        REQUIRE(manage(fixture, alice, cancelled, hs::DelayedEventAction::cancel).ok);
        REQUIRE(request(fixture.runtime(), "POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/leave",
                        fixture.bob_token, "{}")
                    .status == 200U);
        // `sent` is due first (1 s), then `failed` (bob has left, 2 s); `scheduled` (10 s) is not yet due.
        drain_job(fixture, t0 + 5'000U);
        REQUIRE(status_of(fixture, alice, sent) == db::DelayedEventStatus::sent);
        REQUIRE(status_of(fixture, bob, failed) == db::DelayedEventStatus::failed);
        REQUIRE(fixture.table().mark_being_sent(being_sent));

        using Action = hs::DelayedEventAction;
        struct Expected final
        {
            std::string_view name;
            std::string const* id;
            std::string_view user;
            Action action;
            bool ok;
            std::uint16_t status;
            std::string_view reason;
        };
        auto const sent_reason = std::string_view{"The delayed event has already been sent."};
        auto const cancelled_reason = std::string_view{"The delayed event has already been cancelled."};
        auto const being_reason = std::string_view{"The delayed event is being sent."};

        THEN("the outcome table of the design holds cell by cell")
        {
            auto const cells = std::vector<Expected>{
                {"sent restart",       &sent,       alice, Action::restart, false, 409U, sent_reason     },
                {"sent cancel",        &sent,       alice, Action::cancel,  false, 409U, sent_reason     },
                {"sent send",          &sent,       alice, Action::send,    true,  200U, {}              },
                {"cancelled restart",  &cancelled,  alice, Action::restart, false, 409U, cancelled_reason},
                {"cancelled cancel",   &cancelled,  alice, Action::cancel,  true,  200U, {}              },
                {"cancelled send",     &cancelled,  alice, Action::send,    false, 409U, cancelled_reason},
                {"failed restart",     &failed,     bob,   Action::restart, false, 409U, cancelled_reason},
                {"failed cancel",      &failed,     bob,   Action::cancel,  true,  200U, {}              },
                {"failed send",        &failed,     bob,   Action::send,    false, 409U, cancelled_reason},
                {"being sent restart", &being_sent, alice, Action::restart, false, 409U, being_reason    },
                {"being sent cancel",  &being_sent, alice, Action::cancel,  false, 409U, being_reason    },
                {"being sent send",    &being_sent, alice, Action::send,    false, 409U, being_reason    },
            };
            for (auto const& cell : cells)
            {
                INFO(cell.name);
                auto const result = manage(fixture, cell.user, *cell.id, cell.action);
                CHECK(result.ok == cell.ok);
                CHECK(result.status == cell.status);
                if (!cell.ok)
                {
                    CHECK(result.errcode == "M_UNKNOWN");
                    CHECK(result.reason == cell.reason);
                }
            }
            CHECK(status_of(fixture, alice, scheduled) == db::DelayedEventStatus::scheduled);
            CHECK(status_of(fixture, alice, being_sent) == db::DelayedEventStatus::scheduled);
        }
    }
}

SCENARIO("The send action sends now, and a refused send leaves the event scheduled with its timer unchanged",
         "[homeserver][delayed-events][manage][send]")
{
    GIVEN("a scheduled message event")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture));
        auto const since = sync_for(fixture, fixture.bob_token, {}, "m.test.delayed").next_batch;

        WHEN("it is sent long before its time")
        {
            auto const result = manage(fixture, alice, id, hs::DelayedEventAction::send);

            THEN("the event reaches the room and the row is sent")
            {
                CHECK(result.ok);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK(sync_for(fixture, fixture.bob_token, since, "m.test.delayed").event.has_value());
            }
        }

        WHEN("the sender has left the room and then asks to send")
        {
            REQUIRE(request(fixture.runtime(), "POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/leave",
                            fixture.alice_token, "{}")
                        .status == 200U);
            auto const before = fixture.event_count();
            auto const result = manage(fixture, alice, id, hs::DelayedEventAction::send);

            THEN("the answer is the send's own, the row is still scheduled and its timer is unchanged")
            {
                CHECK_FALSE(result.ok);
                CHECK(result.status == 403U);
                CHECK(result.reason == "not joined");
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK_FALSE(fixture.table().is_being_sent(id));
                CHECK(fixture.table().find(id)->delayed_since_ms == t0);
                CHECK(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("A delayed event is authorised when it is sent, not when it was scheduled",
         "[homeserver][delayed-events][job][authorisation]")
{
    GIVEN("bob holds the power to send a state event and schedules one and a message")
    {
        auto fixture = Fixture{memory_config()};
        set_power(fixture, bob, 50);
        auto const state_id = scheduled_id(fixture, state_request(fixture, bob, 10'000U));
        auto const message_id = scheduled_id(fixture, message_request(fixture, bob, "m", 10'000U));

        WHEN("his power is lowered and the due time passes")
        {
            set_power(fixture, bob, 0);
            auto const before = fixture.event_count();
            drain_job(fixture, t0 + 10'000U);

            THEN("the state event is not sent and fails with the room's refusal, and is not tried again")
            {
                CHECK(status_of(fixture, bob, state_id) == db::DelayedEventStatus::failed);
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, bob, state_id), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == "M_FORBIDDEN");
                CHECK(string_member(error, "error") != nullptr);
                // The message needs no power, so exactly it was sent.
                CHECK(status_of(fixture, bob, message_id) == db::DelayedEventStatus::sent);
                CHECK(fixture.event_count() == before + 1U);
                drain_job(fixture, t0 + 20'000U);
                CHECK(fixture.event_count() == before + 1U);
            }
        }
    }

    GIVEN("bob schedules a message and then leaves the room")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, bob, "m", 10'000U));
        REQUIRE(request(fixture.runtime(), "POST", "/_matrix/client/v3/rooms/" + fixture.room_id + "/leave",
                        fixture.bob_token, "{}")
                    .status == 200U);
        auto const before = fixture.event_count();

        WHEN("the due time passes and the job runs twice")
        {
            drain_job(fixture, t0 + 10'000U);
            auto const after_first = fixture.event_count();
            drain_job(fixture, t0 + 20'000U);

            THEN("nothing is sent, the row is failed with the error in the lookup, and no second attempt is made")
            {
                CHECK(after_first == before);
                CHECK(fixture.event_count() == before);
                CHECK(status_of(fixture, bob, id) == db::DelayedEventStatus::failed);
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, bob, id), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == "M_FORBIDDEN");
                CHECK(*string_member(error, "error") == "not joined");
            }
        }
    }
}

SCENARIO("A suspended, locked or deactivated sender sends nothing when the event falls due",
         "[homeserver][delayed-events][job][account]")
{
    GIVEN("bob's delayed event and an account in one of the three states")
    {
        auto const mode = GENERATE(0, 1, 2);
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, bob, "m", 10'000U));
        auto& homeserver = fixture.runtime().homeserver;
        REQUIRE(hs::bootstrap_admin_user(homeserver, "admin", password).ok);
        auto expected_errcode = std::string{};
        auto expected_status = std::uint16_t{0U};
        if (mode == 0)
        {
            REQUIRE(hs::set_local_user_moderation(homeserver, "@admin:example.org", bob, true, false,
                                                  "account.suspended", "suspended")
                        .ok);
            expected_errcode = "M_USER_SUSPENDED";
            expected_status = 403U;
        }
        else if (mode == 1)
        {
            REQUIRE(hs::set_local_user_moderation(homeserver, "@admin:example.org", bob, false, true, "account.locked",
                                                  "locked")
                        .ok);
            expected_errcode = "M_USER_LOCKED";
            expected_status = 401U;
        }
        else
        {
            for (auto& user : homeserver.database.users)
            {
                if (user.user_id == bob)
                {
                    user.deactivated = true;
                }
            }
            expected_errcode = "M_USER_DEACTIVATED";
            expected_status = 403U;
        }
        auto const before = fixture.event_count();

        WHEN("the due time passes")
        {
            drain_job(fixture, t0 + 10'000U);

            THEN("the event is failed with the account's errcode and nothing is sent")
            {
                CHECK(fixture.event_count() == before);
                CHECK(status_of(fixture, bob, id) == db::DelayedEventStatus::failed);
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, bob, id), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == expected_errcode);
            }
        }

        WHEN("bob asks for the event to be sent now")
        {
            auto const result = manage(fixture, bob, id, hs::DelayedEventAction::send);

            THEN("the answer is the account refusal and the row stays scheduled")
            {
                CHECK_FALSE(result.ok);
                CHECK(result.status == expected_status);
                CHECK(result.errcode == expected_errcode);
                CHECK(status_of(fixture, bob, id) == db::DelayedEventStatus::scheduled);
                CHECK_FALSE(fixture.table().is_being_sent(id));
            }
        }
    }
}

SCENARIO("The send-time rate limit fails a due event when the user's per-user policy for the route is spent",
         "[homeserver][delayed-events][job][rate-limit]")
{
    GIVEN("a per-user policy of one send a minute for the send route, and two due events")
    {
        // The rate-limit engine reads the steady clock itself (`ClientServerClock`, no test seam), so this relies on
        // the two sends completing within the policy's 60-second window.
        auto limits = merovingian::config::ClientRateLimitsConfig{};
        limits.per_user["/_matrix/client/v3/rooms/{roomId}/send/"] = merovingian::http::RateLimitPolicy{1U, 60U};
        auto fixture = Fixture{memory_config(std::move(limits))};
        auto const first = scheduled_id(fixture, message_request(fixture, alice, "a", 1'000U));
        auto const second = scheduled_id(fixture, message_request(fixture, alice, "b", 2'000U));

        WHEN("the job runs when both are due")
        {
            drain_job(fixture, t0 + 5'000U);

            THEN("the first is sent and the second fails with M_LIMIT_EXCEEDED")
            {
                CHECK(status_of(fixture, alice, first) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, second) == db::DelayedEventStatus::failed);
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, alice, second), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == "M_LIMIT_EXCEEDED");
            }
        }
    }

    GIVEN("no per-user policy and the same two due events")
    {
        auto fixture = Fixture{memory_config()};
        auto const first = scheduled_id(fixture, message_request(fixture, alice, "a", 1'000U));
        auto const second = scheduled_id(fixture, message_request(fixture, alice, "b", 2'000U));

        WHEN("the job runs when both are due")
        {
            drain_job(fixture, t0 + 5'000U);

            THEN("both are sent")
            {
                CHECK(status_of(fixture, alice, first) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, second) == db::DelayedEventStatus::sent);
            }
        }
    }
}

SCENARIO("A user holds at most the configured number of scheduled events, and is told when to retry",
         "[homeserver][delayed-events][schedule][cap]")
{
    GIVEN("a cap of two and two events scheduled 500 ms apart")
    {
        auto fixture = Fixture{memory_config()};
        fixture.runtime().limits.max_scheduled_delayed_events_per_user = 2U;
        std::ignore = scheduled_id(fixture, message_request(fixture, alice, "a", 60'000U));
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 500U;
        std::ignore = scheduled_id(fixture, message_request(fixture, alice, "b", 30'000U));
        // The earliest due time is t0 + 30'500; at t0 + 1'200 that is 29'300 ms away.
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 1'200U;

        WHEN("alice asks for a third, and bob for his first")
        {
            auto const refused = schedule(fixture, message_request(fixture, alice, "c"));
            auto const other = schedule(fixture, message_request(fixture, bob, "x"));

            THEN("alice gets 429 with the wait rounded up to a whole second, and bob is unaffected")
            {
                CHECK_FALSE(refused.ok);
                CHECK(refused.status == 429U);
                CHECK(refused.errcode == "M_LIMIT_EXCEEDED");
                CHECK(refused.reason == "The maximum number of delayed events has been reached.");
                CHECK(refused.retry_after_ms == 30'000U);
                CHECK(fixture.table().scheduled_count(alice) == 2U);
                CHECK(other.ok);
            }
        }

        WHEN("one of alice's events is cancelled")
        {
            auto const held = fixture.table().earliest_due_ms_of_user(alice);
            REQUIRE(held.has_value());
            auto const cancelled =
                manage(fixture, alice, fixture.table().earliest_due()->delay_id, hs::DelayedEventAction::cancel);
            auto const third = schedule(fixture, message_request(fixture, alice, "c"));

            THEN("a finalised event does not count against the cap")
            {
                CHECK(cancelled.ok);
                CHECK(third.ok);
            }
        }
    }
}

SCENARIO("The delay is bounded by the configured maximum, with the errcode of the route's prefix",
         "[homeserver][delayed-events][schedule][limits]")
{
    GIVEN("a maximum of one hour")
    {
        auto fixture = Fixture{memory_config()};
        fixture.runtime().limits.max_delayed_event_delay_ms = 3'600'000U;

        WHEN("one millisecond more than the maximum is requested on each prefix, and the maximum itself")
        {
            auto stable = message_request(fixture, alice, "s", 3'600'001U);
            stable.stable_errcode = true;
            auto const unstable = message_request(fixture, alice, "u", 3'600'001U);
            auto const at_maximum = message_request(fixture, alice, "m", 3'600'000U);
            auto const stable_result = schedule(fixture, stable);
            auto const unstable_result = schedule(fixture, unstable);
            auto const maximum_result = schedule(fixture, at_maximum);

            THEN("both are 400 with their own errcode and the maximum is accepted")
            {
                CHECK(stable_result.status == 400U);
                CHECK(stable_result.errcode == "M_DELAY_TOO_LARGE");
                CHECK(stable_result.reason == "The requested delay exceeds the allowed maximum.");
                CHECK(unstable_result.status == 400U);
                CHECK(unstable_result.errcode == "ORG.MATRIX.MSC4140_DELAY_TOO_LARGE");
                CHECK(maximum_result.ok);
                CHECK(fixture.table().size() == 1U);
            }
        }
    }
}

SCENARIO("With the feature disabled nothing new is scheduled, but what was scheduled is still sent and managed",
         "[homeserver][delayed-events][schedule][disabled]")
{
    GIVEN("an event scheduled before the feature is turned off")
    {
        auto fixture = Fixture{memory_config()};
        auto const kept = scheduled_id(fixture, message_request(fixture, alice, "a", 10'000U));
        auto const cancelled = scheduled_id(fixture, message_request(fixture, alice, "b"));
        fixture.runtime().limits.delayed_events_enabled = false;
        auto const before = fixture.event_count();

        WHEN("a new event is scheduled and the old ones are managed and sent")
        {
            auto const refused = schedule(fixture, message_request(fixture, alice, "c"));
            auto const cancel = manage(fixture, alice, cancelled, hs::DelayedEventAction::cancel);
            drain_job(fixture, t0 + 10'000U);

            THEN("the schedule is 403 M_FORBIDDEN, the cancel works and the due event is sent")
            {
                CHECK(refused.status == 403U);
                CHECK(refused.errcode == "M_FORBIDDEN");
                CHECK(refused.reason == "Delayed events are not enabled on this homeserver.");
                CHECK(cancel.ok);
                CHECK(status_of(fixture, alice, kept) == db::DelayedEventStatus::sent);
                CHECK(fixture.event_count() == before + 1U);
                CHECK(fixture.table().size() == 2U);
            }
        }
    }
}

SCENARIO("Scheduling the same transaction again returns the same delay ID and stores one row",
         "[homeserver][delayed-events][schedule][idempotency]")
{
    GIVEN("an event scheduled with a transaction ID")
    {
        auto fixture = Fixture{memory_config()};
        auto const first = scheduled_id(fixture, message_request(fixture, alice, "txn-1"));

        WHEN("the same request is repeated, from another device, and with an empty transaction ID twice")
        {
            auto const again = schedule(fixture, message_request(fixture, alice, "txn-1"));
            auto other_device = message_request(fixture, alice, "txn-1");
            other_device.device_id = "D9";
            auto const elsewhere = schedule(fixture, other_device);
            auto const empty_one = schedule(fixture, state_request(fixture));
            auto const empty_two = schedule(fixture, state_request(fixture));

            THEN("the repeat finds the first, another device stores a second, and an empty ID never matches")
            {
                CHECK(again.ok);
                CHECK(again.value == first);
                CHECK(elsewhere.ok);
                CHECK(elsewhere.value != first);
                CHECK(empty_one.ok);
                CHECK(empty_two.ok);
                CHECK(empty_one.value != empty_two.value);
                CHECK(fixture.table().size() == 4U);
            }
        }
    }
}

SCENARIO("A delayed event the sender could not send now is refused when it is scheduled, as the ordinary routes refuse",
         "[homeserver][delayed-events][schedule][refusal]")
{
    GIVEN("a room, a user who is not in it and a user without the power to send state")
    {
        auto fixture = Fixture{memory_config()};
        auto const carol_token = sign_in(fixture.runtime(), "carol", "D3");
        auto const unknown_room = std::string{"!nowhere:example.org"};

        WHEN("each is scheduled and the same event is sent through the ordinary route")
        {
            auto unknown = message_request(fixture);
            unknown.room_id = unknown_room;
            auto const unknown_result = schedule(fixture, unknown);
            auto const unknown_ordinary = request(
                fixture.runtime(), "PUT", "/_matrix/client/v3/rooms/" + unknown_room + "/send/m.test.delayed/t1",
                fixture.alice_token, R"({"body":"x"})");
            auto const stranger_result = schedule(fixture, message_request(fixture, "@carol:example.org"));
            auto const stranger_ordinary = request(
                fixture.runtime(), "PUT", "/_matrix/client/v3/rooms/" + fixture.room_id + "/send/m.test.delayed/t1",
                carol_token, R"({"body":"x"})");
            auto const weak_result = schedule(fixture, state_request(fixture, bob));
            auto const weak_ordinary =
                request(fixture.runtime(), "PUT", "/_matrix/client/v3/rooms/" + fixture.room_id + "/state/m.test.state",
                        fixture.bob_token, R"({"v":1})");

            THEN("the status matches the ordinary route's, and nothing is stored")
            {
                CHECK_FALSE(unknown_result.ok);
                CHECK(unknown_result.status == unknown_ordinary.status);
                CHECK_FALSE(stranger_result.ok);
                CHECK(stranger_result.status == stranger_ordinary.status);
                CHECK(stranger_result.status == 403U);
                CHECK_FALSE(weak_result.ok);
                CHECK(weak_result.status == weak_ordinary.status);
                CHECK(weak_result.status == 403U);
                CHECK(fixture.table().size() == 0U);
            }
        }

        WHEN("an oversized type, transaction ID or content, or a NUL byte, is scheduled")
        {
            auto long_type = message_request(fixture);
            long_type.event_type = std::string(256U, 't');
            auto long_txn = message_request(fixture, alice, std::string(256U, 'x'));
            auto big_content = message_request(fixture);
            big_content.content_json = R"({"body":")" + std::string(65'536U, 'c') + R"("})";
            auto nul_type = message_request(fixture);
            nul_type.event_type = nul_text("m.test", "x");
            auto nul_txn = message_request(fixture, alice, nul_text("a", "b"));
            auto nul_key = state_request(fixture);
            nul_key.state_key = nul_text("a", "b");
            auto long_key = state_request(fixture);
            long_key.state_key = std::string(256U, 'k');
            auto no_delay = message_request(fixture, alice, "z", 0U);
            auto not_object = message_request(fixture);
            not_object.content_json = "[1]";

            THEN("each gets the ordinary answer and nothing is stored")
            {
                auto const type_result = schedule(fixture, long_type);
                CHECK(type_result.status == 413U);
                CHECK(type_result.errcode == "M_TOO_LARGE");
                CHECK(type_result.reason == "the event type is at most 255 bytes");
                auto const txn_result = schedule(fixture, long_txn);
                CHECK(txn_result.status == 400U);
                CHECK(txn_result.errcode == "M_INVALID_PARAM");
                CHECK(txn_result.reason == "the transaction ID is at most 255 bytes");
                auto const content_result = schedule(fixture, big_content);
                CHECK(content_result.status == 413U);
                CHECK(content_result.errcode == "M_TOO_LARGE");
                for (auto const* refused : {&nul_type, &nul_txn, &nul_key, &no_delay})
                {
                    auto const result = schedule(fixture, *refused);
                    CHECK(result.status == 400U);
                    CHECK(result.errcode == "M_INVALID_PARAM");
                }
                CHECK(schedule(fixture, long_key).status == 413U);
                CHECK(schedule(fixture, not_object).status == 400U);
                CHECK(fixture.table().size() == 0U);
            }
        }
    }
}

SCENARIO("A delayed event survives a restart, and one that fell due while the server was down is sent first",
         "[homeserver][delayed-events][persistence]")
{
    GIVEN("an event scheduled on a SQLite file and a runtime started again from the same file")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const config = sqlite_config(path);
        auto const overdue = GENERATE(false, true);
        auto id = std::string{};
        auto room_id = std::string{};
        {
            auto first = Fixture{config};
            id = scheduled_id(first, message_request(first, alice, "txn-1", 30'000U));
            room_id = first.room_id;
        }
        auto restarted = hs::start_client_server(config);
        REQUIRE(restarted.started);
        auto& homeserver = restarted.runtime.homeserver;
        homeserver.test_frozen_event_clock_ms = static_cast<std::int64_t>(t0);

        WHEN("the job runs just before the old deadline and then at it, or long after it")
        {
            auto const before = homeserver.database.persistent_store.events.size();
            auto const early = hs::send_due_delayed_events(restarted.runtime, t0 + 30'000U - 1U, {});
            auto const early_count = homeserver.database.persistent_store.events.size();
            auto const late_now = overdue ? t0 + 10'000'000U : t0 + 30'000U;
            auto const late = hs::send_due_delayed_events(restarted.runtime, late_now, {});

            THEN("the event kept its deadline, is not early and is sent by the first run that is due")
            {
                auto const* held = homeserver.database.persistent_store.delayed_events.find_owned(alice, id);
                REQUIRE(held != nullptr);
                CHECK(held->delayed_since_ms == t0);
                CHECK(held->delay_ms == 30'000U);
                CHECK(held->room_id == room_id);
                CHECK(held->status == db::DelayedEventStatus::sent);
                CHECK(early_count == before);
                CHECK(homeserver.database.persistent_store.events.size() == before + 1U);
                CHECK(early == std::chrono::milliseconds{5});
                CHECK(late == std::chrono::milliseconds{60'000});
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A failed outcome commit leaves the event sent once and never sent again",
         "[homeserver][delayed-events][job][at-least-once]")
{
    GIVEN("a due event whose finalising write fails")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, alice, "txn-1", 10'000U));
        auto const before = fixture.event_count();
        fixture.runtime().homeserver.database.persistent_store.force_failure_statement_names.insert(
            "finalise_delayed_event");

        WHEN("the job runs twice")
        {
            drain_job(fixture, t0 + 10'000U);
            drain_job(fixture, t0 + 20'000U);

            THEN("the event was sent once and memory says it was sent")
            {
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK_FALSE(fixture.table().is_being_sent(id));
            }
        }
    }
}

SCENARIO("Finalised events are kept per user up to a bound and for seven days",
         "[homeserver][delayed-events][job][retention]")
{
    GIVEN("a bound of two finalised events per user")
    {
        auto fixture = Fixture{memory_config()};
        fixture.runtime().limits.max_finalised_delayed_events_per_user = 2U;

        WHEN("three of alice's events are finalised")
        {
            auto const one = scheduled_id(fixture, message_request(fixture, alice, "1"));
            auto const two = scheduled_id(fixture, message_request(fixture, alice, "2"));
            auto const three = scheduled_id(fixture, message_request(fixture, alice, "3"));
            fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 1U;
            REQUIRE(manage(fixture, alice, one, hs::DelayedEventAction::cancel).ok);
            fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 2U;
            REQUIRE(manage(fixture, alice, two, hs::DelayedEventAction::cancel).ok);
            fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + 3U;
            REQUIRE(manage(fixture, alice, three, hs::DelayedEventAction::cancel).ok);

            THEN("the oldest is gone and answers 404, the others remain")
            {
                CHECK(fixture.table().find_owned(alice, one) == nullptr);
                CHECK(fixture.table().find_owned(alice, two) != nullptr);
                CHECK(fixture.table().find_owned(alice, three) != nullptr);
                CHECK(manage(fixture, alice, one, hs::DelayedEventAction::cancel).status == 404U);
            }
        }
    }

    GIVEN("a cancelled event finalised at t0 and one finalised a day later")
    {
        auto fixture = Fixture{memory_config()};
        auto const old_id = scheduled_id(fixture, message_request(fixture, alice, "old"));
        REQUIRE(manage(fixture, alice, old_id, hs::DelayedEventAction::cancel).ok);
        auto constexpr day = std::uint64_t{24U * 60U * 60U * 1000U};
        fixture.runtime().homeserver.test_delayed_event_clock_ms = t0 + day;
        auto const new_id = scheduled_id(fixture, message_request(fixture, alice, "new"));
        REQUIRE(manage(fixture, alice, new_id, hs::DelayedEventAction::cancel).ok);

        WHEN("the job runs just under seven days after the first, then at seven days and one millisecond")
        {
            std::ignore = run_job(fixture, t0 + 7U * day);
            auto const kept_at_seven_days = fixture.table().find_owned(alice, old_id) != nullptr;
            std::ignore = run_job(fixture, t0 + 7U * day + 1U);

            THEN("the older row goes only once it is past seven days and the newer one stays")
            {
                CHECK(kept_at_seven_days);
                CHECK(fixture.table().find_owned(alice, old_id) == nullptr);
                CHECK(fixture.table().find_owned(alice, new_id) != nullptr);
            }
        }
    }
}

SCENARIO("Deactivating an account deletes every delayed event of that user and nobody else's",
         "[homeserver][delayed-events][deactivation]")
{
    GIVEN("scheduled and finalised delayed events of alice and one of bob")
    {
        auto fixture = Fixture{memory_config()};
        auto const live = scheduled_id(fixture, message_request(fixture, alice, "a"));
        auto const done = scheduled_id(fixture, message_request(fixture, alice, "b"));
        REQUIRE(manage(fixture, alice, done, hs::DelayedEventAction::cancel).ok);
        auto const bobs = scheduled_id(fixture, message_request(fixture, bob, "c"));

        WHEN("alice's account is deactivated")
        {
            auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
            auto const result = hs::deactivate_user_account(fixture.runtime().homeserver, alice,
                                                            {std::string{alice}, std::string{alice}, "test"});

            THEN("none of her rows remain and bob's is untouched")
            {
                CHECK(result.ok);
                CHECK(fixture.table().find(live) == nullptr);
                CHECK(fixture.table().find(done) == nullptr);
                CHECK(fixture.table().find(bobs) != nullptr);
                CHECK(fixture.table().size() == 1U);
            }
        }
    }
}

SCENARIO("Deactivation succeeds when the delayed-events delete fails, and the job then fails the user's due event",
         "[homeserver][delayed-events][deactivation]")
{
    GIVEN("a scheduled event of bob and a delete of delayed events that fails")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, bob, "x", 10'000U));
        auto const before = fixture.event_count();
        fixture.runtime().homeserver.database.persistent_store.force_failure_statement_names.insert(
            "delete_delayed_events_of_user");

        WHEN("bob's account is deactivated and the job runs at the due time")
        {
            {
                auto const guard = hs::RuntimeLock{fixture.runtime().homeserver.mutex};
                auto const result = hs::deactivate_user_account(fixture.runtime().homeserver, bob,
                                                                {std::string{bob}, std::string{bob}, "test"});
                REQUIRE(result.ok);
            }
            auto const still_held = fixture.table().find(id) != nullptr;
            drain_job(fixture, t0 + 10'000U);

            THEN("the account is deactivated, and the event is failed M_USER_DEACTIVATED and not sent")
            {
                auto deactivated = false;
                for (auto const& user : fixture.runtime().homeserver.database.users)
                {
                    deactivated = deactivated || (user.user_id == bob && user.deactivated);
                }
                CHECK(deactivated);
                CHECK(still_held);
                CHECK(status_of(fixture, bob, id) == db::DelayedEventStatus::failed);
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, bob, id), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == "M_USER_DEACTIVATED");
                CHECK(fixture.event_count() == before);
            }
        }
        fixture.runtime().homeserver.database.persistent_store.force_failure_statement_names.clear();
    }
}

SCENARIO("The job's return value says when it should run next, and it stops when asked",
         "[homeserver][delayed-events][job][pacing]")
{
    GIVEN("a runtime with nothing scheduled")
    {
        auto fixture = Fixture{memory_config()};

        WHEN("the job runs")
        {
            auto const wait = run_job(fixture, t0);

            THEN("it asks for 60 seconds")
            {
                CHECK(wait == std::chrono::milliseconds{60'000});
            }
        }

        WHEN("an event due in 12.5 s and one due in two minutes are scheduled")
        {
            std::ignore = scheduled_id(fixture, message_request(fixture, alice, "a", 12'500U));
            std::ignore = scheduled_id(fixture, message_request(fixture, alice, "b", 120'000U));
            auto const near = run_job(fixture, t0 + 500U);
            auto const far = run_job(fixture, t0 - 1U);
            REQUIRE(
                manage(fixture, alice, fixture.table().earliest_due()->delay_id, hs::DelayedEventAction::cancel).ok);
            auto const capped = run_job(fixture, t0);

            THEN("the wait is the exact time to the next deadline, capped at 60 seconds")
            {
                CHECK(near == std::chrono::milliseconds{12'000});
                CHECK(far == std::chrono::milliseconds{12'501});
                CHECK(capped == std::chrono::milliseconds{60'000});
            }
        }
    }

    GIVEN("102 events due at once, due 1 ms apart")
    {
        auto fixture = Fixture{memory_config()};
        fixture.runtime().limits.max_scheduled_delayed_events_per_user = 1000U;
        auto ids = std::vector<std::string>{};
        for (auto index = 0; index < 102; ++index)
        {
            // Scheduled newest-deadline first, so the deadline order is not the order they were stored in.
            ids.push_back(scheduled_id(fixture, message_request(fixture, alice, std::to_string(index),
                                                                2'000U - static_cast<unsigned>(index))));
        }
        auto const before = fixture.event_count();

        WHEN("the job runs once")
        {
            auto const wait = run_job(fixture, t0 + 5'000U);

            THEN("it sent exactly the earliest one and asks to run again after the pace, never at once")
            {
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, ids[101]) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, ids[100]) == db::DelayedEventStatus::scheduled);
                CHECK(wait == std::chrono::milliseconds{5});
            }
        }

        WHEN("the job runs three times")
        {
            auto const first = run_job(fixture, t0 + 5'000U);
            auto const second = run_job(fixture, t0 + 5'000U);
            auto const third = run_job(fixture, t0 + 5'000U);

            THEN("three events are sent in deadline order, each run returning the pace")
            {
                CHECK(fixture.event_count() == before + 3U);
                CHECK(status_of(fixture, alice, ids[101]) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, ids[100]) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, ids[99]) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, ids[98]) == db::DelayedEventStatus::scheduled);
                CHECK(first == std::chrono::milliseconds{5});
                CHECK(second == std::chrono::milliseconds{5});
                CHECK(third == std::chrono::milliseconds{5});
            }
        }

        WHEN("the job is run until nothing is due")
        {
            auto const runs = drain_job(fixture, t0 + 5'000U);
            auto const last = run_job(fixture, t0 + 5'000U);

            THEN("it took one run per event, and the run with nothing due asks for 60 seconds")
            {
                CHECK(runs == 102U);
                CHECK(fixture.event_count() == before + 102U);
                CHECK(last == std::chrono::milliseconds{60'000});
            }
        }

        WHEN("the job runs with its stop flag already set")
        {
            auto stop = hs::StopFlag{};
            stop.request_stop();
            std::ignore = run_job(fixture, t0 + 5'000U, stop);

            THEN("nothing is sent")
            {
                CHECK(fixture.event_count() == before);
                CHECK(fixture.table().scheduled_count(alice) == 102U);
            }
        }
    }

    GIVEN("one event due now and one due in 2 ms")
    {
        auto fixture = Fixture{memory_config()};
        std::ignore = scheduled_id(fixture, message_request(fixture, alice, "a", 1'000U));
        std::ignore = scheduled_id(fixture, message_request(fixture, alice, "b", 1'002U));

        WHEN("the job runs at the first deadline")
        {
            auto const wait = run_job(fixture, t0 + 1'000U);

            THEN("the wait to the next deadline is raised to the pace")
            {
                CHECK(wait == std::chrono::milliseconds{5});
            }
        }
    }
}

SCENARIO("An exception while recording the outcome keeps the mark, so the event is not sent again by this process",
         "[homeserver][delayed-events][job][exception]")
{
    GIVEN("a due event, and the number of backend commits one send and its record make")
    {
        auto commits = std::size_t{0U};
        {
            auto calibration = Fixture{memory_config()};
            std::ignore = scheduled_id(calibration, message_request(calibration, alice, "boom", 10'000U));
            calibration.runtime().homeserver.database.persistent_store.test_before_backend_commit =
                [&commits](std::size_t) {
                    ++commits;
                };
            drain_job(calibration, t0 + 10'000U);
            calibration.runtime().homeserver.database.persistent_store.test_before_backend_commit = nullptr;
        }
        REQUIRE(commits >= 2U);

        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, alice, "boom", 10'000U));
        auto const before = fixture.event_count();
        auto seen = std::size_t{0U};
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = [&seen,
                                                                                             commits](std::size_t) {
            if (++seen == commits)
            {
                throw std::runtime_error{"simulated outcome commit failure"};
            }
        };

        WHEN("the job runs at the due time and twice afterwards")
        {
            CHECK_NOTHROW(std::ignore = run_job(fixture, t0 + 10'000U));
            auto const after_first = fixture.event_count();
            CHECK_NOTHROW(std::ignore = run_job(fixture, t0 + 20'000U));
            CHECK_NOTHROW(std::ignore = run_job(fixture, t0 + 30'000U));

            THEN("the event was sent once, the row is still scheduled and marked, and nothing is sent again")
            {
                REQUIRE(seen == commits);
                CHECK(after_first == before + 1U);
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK(fixture.table().is_being_sent(id));
            }
        }
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = nullptr;
    }
}

SCENARIO("The send action is subject to the user's rate limit for the send route",
         "[homeserver][delayed-events][manage][rate-limit]")
{
    GIVEN("a per-user policy of one send a minute for the send route and two scheduled events")
    {
        // The rate-limit engine reads the steady clock itself (`ClientServerClock`, no test seam), so this relies on
        // the two sends completing within the policy's 60-second window.
        auto limits = merovingian::config::ClientRateLimitsConfig{};
        limits.per_user["/_matrix/client/v3/rooms/{roomId}/send/"] = merovingian::http::RateLimitPolicy{1U, 60U};
        auto fixture = Fixture{memory_config(std::move(limits))};
        auto const first = scheduled_id(fixture, message_request(fixture, alice, "a", 60'000U));
        auto const second = scheduled_id(fixture, message_request(fixture, alice, "b", 60'000U));

        WHEN("the first is sent now, and then the second")
        {
            auto const sent = manage(fixture, alice, first, hs::DelayedEventAction::send);
            auto const limited = manage(fixture, alice, second, hs::DelayedEventAction::send);

            THEN("the second is 429 M_LIMIT_EXCEEDED with retry_after_ms and is still scheduled")
            {
                CHECK(sent.ok);
                CHECK_FALSE(limited.ok);
                CHECK(limited.status == 429U);
                CHECK(limited.errcode == "M_LIMIT_EXCEEDED");
                CHECK(limited.retry_after_ms > 0U);
                CHECK(status_of(fixture, alice, first) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, second) == db::DelayedEventStatus::scheduled);
                CHECK_FALSE(fixture.table().is_being_sent(second));
            }
        }
    }
}

SCENARIO("A restart is persisted: the reopened event's timer starts at the restart and it is sent at the new deadline",
         "[homeserver][delayed-events][persistence]")
{
    GIVEN("an event scheduled for 60 s on a SQLite file, restarted 10 s later, and the runtime started again")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto const config = sqlite_config(path);
        auto id = std::string{};
        {
            auto first = Fixture{config};
            id = scheduled_id(first, message_request(first, alice, "txn-1", 60'000U));
            first.runtime().homeserver.test_delayed_event_clock_ms = t0 + 10'000U;
            REQUIRE(manage(first, alice, id, hs::DelayedEventAction::restart).ok);
        }
        auto restarted = hs::start_client_server(config);
        REQUIRE(restarted.started);
        auto& homeserver = restarted.runtime.homeserver;
        homeserver.test_frozen_event_clock_ms = static_cast<std::int64_t>(t0);

        WHEN("the job runs at the original deadline and then at the new one")
        {
            auto const before = homeserver.database.persistent_store.events.size();
            std::ignore = hs::send_due_delayed_events(restarted.runtime, t0 + 60'000U, {});
            auto const at_original = homeserver.database.persistent_store.events.size();
            auto const* held = homeserver.database.persistent_store.delayed_events.find_owned(alice, id);
            REQUIRE(held != nullptr);
            auto const since = held->delayed_since_ms;
            auto const scheduled_at_original = held->status == db::DelayedEventStatus::scheduled;
            std::ignore = hs::send_due_delayed_events(restarted.runtime, t0 + 70'000U, {});

            THEN("the timer started at the restart, nothing was sent at the original deadline, and it is sent at the "
                 "new")
            {
                CHECK(since == t0 + 10'000U);
                CHECK(at_original == before);
                CHECK(scheduled_at_original);
                CHECK(homeserver.database.persistent_store.events.size() == before + 1U);
                CHECK(homeserver.database.persistent_store.delayed_events.find_owned(alice, id)->status ==
                      db::DelayedEventStatus::sent);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A send that throws in the job is recorded failed with M_UNKNOWN and is not sent again",
         "[homeserver][delayed-events][job][exception]")
{
    GIVEN("a due delayed event whose send throws from the store's commit")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, alice, "boom", 10'000U));
        auto armed = true;
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = [&armed](std::size_t) {
            if (armed)
            {
                armed = false;
                throw std::runtime_error{"simulated commit failure"};
            }
        };

        WHEN("the job runs at the due time, and again afterwards")
        {
            CHECK_NOTHROW(std::ignore = run_job(fixture, t0 + 10'000U));
            auto const after_first = fixture.event_count();
            CHECK_NOTHROW(std::ignore = run_job(fixture, t0 + 20'000U));

            THEN("the row is failed with M_UNKNOWN, unmarked, and the second run sends nothing")
            {
                REQUIRE(armed == false);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::failed);
                CHECK_FALSE(fixture.table().is_being_sent(id));
                auto const error = *object_member_as_object(
                    *object_member_as_object(looked_up(fixture, alice, id), "finalised"), "error");
                CHECK(*string_member(error, "errcode") == "M_UNKNOWN");
                CHECK(fixture.event_count() == after_first);
            }
        }
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = nullptr;
    }
}

SCENARIO("A send action that throws is answered 500 by the backstop and leaves the event scheduled and unmarked",
         "[homeserver][delayed-events][manage][exception]")
{
    GIVEN("a scheduled delayed event whose send throws from the store's commit")
    {
        auto fixture = Fixture{memory_config()};
        auto const id = scheduled_id(fixture, message_request(fixture, alice, "boom", 60'000U));
        auto armed = true;
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = [&armed](std::size_t) {
            if (armed)
            {
                armed = false;
                throw std::runtime_error{"simulated commit failure"};
            }
        };

        WHEN("the send action is requested, and then a restart")
        {
            auto const sent = request(fixture.runtime(), "POST", "/_matrix/client/v1/delayed_events/" + id + "/send",
                                      fixture.alice_token);
            auto const restart = request(fixture.runtime(), "POST",
                                         "/_matrix/client/v1/delayed_events/" + id + "/restart", fixture.alice_token);

            THEN("the first is 500, the row is scheduled and not marked, and the restart is 200")
            {
                REQUIRE(armed == false);
                CHECK(sent.status == 500U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK_FALSE(fixture.table().is_being_sent(id));
                CHECK(restart.status == 200U);
            }
        }
        fixture.runtime().homeserver.database.persistent_store.test_before_backend_commit = nullptr;
    }
}
