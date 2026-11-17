// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Delayed events (MSC4140, ADR-0823, ADR-0826): the client-server routes that call the service layer, the /versions
// and /capabilities entries and the built-in rate limits. Every request goes through
// `handle_client_server_request` on a real runtime. No scenario sleeps or starts the job's thread: time is
// `HomeserverRuntime::test_delayed_event_clock_ms` and the job body is called with its own `now_ms`. The feature is not
// in the Matrix v1.19 specification, so there is no conformance scenario.

#include "../support/AppserviceTestConfig.hpp"
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
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
#include "merovingian/homeserver/DelayedEvents.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/homeserver/StopFlag.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
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
constexpr auto v1 = std::string_view{"/_matrix/client/v1/delayed_events/"};
constexpr auto unstable = std::string_view{"/_matrix/client/unstable/org.matrix.msc4140/delayed_events/"};
constexpr auto delay_param = std::string_view{"org.matrix.msc4140.delay"};
constexpr auto message_content = std::string_view{R"({"body":"later"})"};

[[nodiscard]] auto memory_config(merovingian::config::ClientRateLimitsConfig limits = {}) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
        std::move(security),
        std::move(limits),
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto request(hs::ClientServerRuntime& runtime, std::string method, std::string target,
                           std::string const& token = {}, std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {std::move(method), std::move(target), token, std::move(body)})
        .response;
}

[[nodiscard]] auto errcode_of(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* code = string_member(body, "errcode");
    return code == nullptr ? std::string{} : *code;
}

[[nodiscard]] auto header_of(hs::LocalHttpResponse const& response, std::string_view name) -> std::string
{
    for (auto const& [key, value] : response.headers)
    {
        if (key == name)
        {
            return value;
        }
    }
    return {};
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
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Signs an existing user in on a new device; the access token.
[[nodiscard]] auto log_in(hs::ClientServerRuntime& runtime, std::string const& name, std::string const& device)
    -> std::string
{
    auto const login =
        request(runtime, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                    R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + device + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// A running homeserver with alice and bob in one public room. Alice created it.
class Fixture final
{
public:
    explicit Fixture(merovingian::config::Config const& config = memory_config())
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

    // The room's path, `/_matrix/client/v3/rooms/{roomId}`.
    [[nodiscard]] auto room_path() const -> std::string
    {
        return "/_matrix/client/v3/rooms/" + room_id;
    }

    // Moves both the delayed-event clock and the frozen event clock.
    auto set_time(std::uint64_t now_ms) -> void
    {
        runtime().homeserver.test_delayed_event_clock_ms = now_ms;
        runtime().homeserver.test_frozen_event_clock_ms = static_cast<std::int64_t>(now_ms);
    }

    // The job body at `now_ms`, run until no scheduled event is due then: one run sends at most one event. A bound
    // stops a job that makes no progress.
    auto run_job(std::uint64_t now_ms) -> void
    {
        for (auto runs = 0; runs < 1'000; ++runs)
        {
            auto const* next = table().earliest_due();
            if (next == nullptr || db::delayed_event_due_ms(*next) > now_ms)
            {
                return;
            }
            std::ignore = hs::send_due_delayed_events(runtime(), now_ms, hs::StopFlag{});
        }
    }

    std::string alice_token{};
    std::string bob_token{};
    std::string room_id{};

private:
    hs::ClientServerStartResult m_started;
};

// S1 and S2's body.
[[nodiscard]] auto schedule_body(std::uint64_t delay_ms, std::string_view content = message_content) -> std::string
{
    return R"({"delay_ms":)" + std::to_string(delay_ms) + R"(,"content":)" + std::string{content} + "}";
}

// PUT of S1 (`stable`) or S2 for `type` and `txn`.
[[nodiscard]] auto put_dedicated(Fixture& fixture, bool stable, std::string const& token, std::string_view type,
                                 std::string_view txn, std::string body) -> hs::LocalHttpResponse
{
    auto const path = stable
                          ? fixture.room_path() + "/delayed_event/"
                          : "/_matrix/client/unstable/org.matrix.msc4140/rooms/" + fixture.room_id + "/delayed_event/";
    return request(fixture.runtime(), "PUT", path + std::string{type} + "/" + std::string{txn}, token, std::move(body));
}

// PUT of L1: the ordinary send route with the delay in the query.
[[nodiscard]] auto put_send_delayed(Fixture& fixture, std::string const& token, std::string_view type,
                                    std::string_view txn, std::string_view query,
                                    std::string body = std::string{message_content}) -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "PUT",
                   fixture.room_path() + "/send/" + std::string{type} + "/" + std::string{txn} + "?" +
                       std::string{query},
                   token, std::move(body));
}

// PUT of L2: the ordinary state route; `tail` is what follows the event type, `/key`, `/` or nothing.
[[nodiscard]] auto put_state_delayed(Fixture& fixture, std::string const& token, std::string_view type,
                                     std::string_view tail, std::string_view query, std::string body = R"({"v":1})")
    -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "PUT",
                   fixture.room_path() + "/state/" + std::string{type} + std::string{tail} + "?" + std::string{query},
                   token, std::move(body));
}

[[nodiscard]] auto delay_id_of(hs::LocalHttpResponse const& response) -> std::string
{
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* id = string_member(body, "delay_id");
    REQUIRE(id != nullptr);
    REQUIRE_FALSE(id->empty());
    return *id;
}

// Schedules a message for alice by S2 and returns its delay ID.
[[nodiscard]] auto schedule_message(Fixture& fixture, std::string_view txn, std::uint64_t delay_ms = 60'000U,
                                    std::string const& token = {}) -> std::string
{
    return delay_id_of(put_dedicated(fixture, false, token.empty() ? fixture.alice_token : token, "m.test.delayed", txn,
                                     schedule_body(delay_ms)));
}

[[nodiscard]] auto post_action(Fixture& fixture, bool stable, std::string_view delay_id, std::string_view action,
                               std::string const& token, std::string body = {}, std::string_view query = {})
    -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "POST",
                   std::string{stable ? v1 : unstable} + std::string{delay_id} + "/" + std::string{action} +
                       std::string{query},
                   token, std::move(body));
}

[[nodiscard]] auto post_body_action(Fixture& fixture, std::string_view delay_id, std::string body,
                                    std::string const& token) -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "POST", std::string{unstable} + std::string{delay_id}, token, std::move(body));
}

[[nodiscard]] auto get_delayed(Fixture& fixture, bool stable, std::string_view delay_id, std::string const& token)
    -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "GET", std::string{stable ? v1 : unstable} + std::string{delay_id}, token);
}

[[nodiscard]] auto status_of(Fixture& fixture, std::string_view user, std::string_view delay_id)
    -> db::DelayedEventStatus
{
    auto const* row = fixture.table().find_owned(user, delay_id);
    REQUIRE(row != nullptr);
    return row->status;
}

// True when the room's timeline in alice's initial `/sync` holds an event of `type`.
[[nodiscard]] auto timeline_has(Fixture& fixture, std::string_view type) -> bool
{
    auto const response = request(fixture.runtime(), "GET", "/_matrix/client/v3/sync", fixture.alice_token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* joined = rooms == nullptr ? nullptr : object_member_as_object(*rooms, "join");
    auto const* room = joined == nullptr ? nullptr : object_member_as_object(*joined, fixture.room_id);
    auto const* timeline = room == nullptr ? nullptr : object_member_as_object(*room, "timeline");
    auto const* events = timeline == nullptr ? nullptr : object_member_as_array(*timeline, "events");
    if (events == nullptr)
    {
        return false;
    }
    for (auto const& entry : *events)
    {
        auto const* object = std::get_if<cj::Object>(&entry.storage());
        if (object != nullptr && string_member(*object, "type") != nullptr && *string_member(*object, "type") == type)
        {
            return true;
        }
    }
    return false;
}

[[nodiscard]] auto state_content(Fixture& fixture, std::string_view type, std::string_view key = {})
    -> hs::LocalHttpResponse
{
    return request(fixture.runtime(), "GET",
                   fixture.room_path() + "/state/" + std::string{type} + (key.empty() ? "" : "/" + std::string{key}),
                   fixture.alice_token);
}

} // namespace

SCENARIO("Every scheduling form answers a delay ID, sends nothing early and sends the event at its due time",
         "[homeserver][delayed-events][routes][schedule]")
{
    GIVEN("alice in a room, and one of the six forms that schedule an event")
    {
        auto const form = GENERATE(0, 1, 2, 3, 4, 5);
        auto fixture = Fixture{};
        auto const is_state = form >= 3;
        auto const event_type = std::string{is_state ? "m.test.state" : "m.test.delayed"};
        auto const before = fixture.event_count();
        auto const dedicated_body = schedule_body(30'000U, is_state ? std::string_view{R"({"v":1})"} : message_content);

        WHEN("it is scheduled for 30 seconds")
        {
            auto const response = [&]() -> hs::LocalHttpResponse {
                switch (form)
                {
                case 0:
                    return put_dedicated(fixture, true, fixture.alice_token, event_type, "t1", dedicated_body);
                case 1:
                    return put_dedicated(fixture, false, fixture.alice_token, event_type, "t1", dedicated_body);
                case 2:
                    return put_send_delayed(fixture, fixture.alice_token, event_type, "t1",
                                            std::string{delay_param} + "=30000");
                case 3:
                    return put_state_delayed(fixture, fixture.alice_token, event_type, "/key",
                                             std::string{delay_param} + "=30000");
                case 4:
                    return put_state_delayed(fixture, fixture.alice_token, event_type, "/",
                                             std::string{delay_param} + "=30000");
                default:
                    return put_state_delayed(fixture, fixture.alice_token, event_type, "",
                                             std::string{delay_param} + "=30000");
                }
            }();
            auto const id = delay_id_of(response);

            THEN("the answer is a delay_id, and nothing is sent before the due time")
            {
                CHECK(response.body.find("event_id") == std::string::npos);
                CHECK(fixture.event_count() == before);
                fixture.run_job(t0 + 29'999U);
                CHECK(fixture.event_count() == before);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
            AND_THEN("the job sends it at the due time and it is in /sync")
            {
                fixture.set_time(t0 + 30'000U);
                fixture.run_job(t0 + 30'000U);
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK(timeline_has(fixture, event_type));
            }
            AND_THEN("a state form produced the state key it named, and no other")
            {
                fixture.set_time(t0 + 30'000U);
                fixture.run_job(t0 + 30'000U);
                if (is_state)
                {
                    auto const keyed = state_content(fixture, event_type, "key");
                    auto const empty_key = state_content(fixture, event_type);
                    // Form 3 names the key `key`; forms 4 (`/`) and 5 (no key segment) mean the empty state key.
                    CHECK((form == 3 ? keyed.status : empty_key.status) == 200U);
                    CHECK((form == 3 ? empty_key.status : keyed.status) == 404U);
                    CHECK((form == 3 ? keyed.body : empty_key.body).find("\"v\":1") != std::string::npos);
                }
            }
        }
    }
}

SCENARIO("A dedicated route with a state_key schedules a state event, even with an empty key",
         "[homeserver][delayed-events][routes][schedule]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const state_key = GENERATE(std::string{"k"}, std::string{});

        WHEN("S1 is given a state_key member")
        {
            auto const body = R"({"delay_ms":5000,"content":{"v":2},"state_key":")" + state_key + R"("})";
            auto const id = delay_id_of(put_dedicated(fixture, true, fixture.alice_token, "m.test.state", "s1", body));

            THEN("the lookup shows a state event, and it replaces the state when due")
            {
                auto const found = parse_object(get_delayed(fixture, true, id, fixture.alice_token).body);
                REQUIRE(string_member(found, "state_key") != nullptr);
                CHECK(*string_member(found, "state_key") == state_key);
                fixture.set_time(t0 + 5'000U);
                fixture.run_job(t0 + 5'000U);
                auto const current = state_content(fixture, "m.test.state", state_key);
                CHECK(current.status == 200U);
                CHECK(current.body.find("\"v\":2") != std::string::npos);
            }
        }
    }
}

SCENARIO("A call membership leave scheduled on the state route survives the join and is moved by a restart",
         "[homeserver][delayed-events][routes][element-x]")
{
    GIVEN("alice scheduling the empty call.member for her device with Element X's requests")
    {
        auto fixture = Fixture{};
        auto const type = std::string{"org.matrix.msc3401.call.member"};
        auto const key = std::string{"_%40alice%3Aexample.org_D1"};
        auto const scheduled =
            put_state_delayed(fixture, fixture.alice_token, type, "/" + key, std::string{delay_param} + "=30000", "{}");
        auto const id = delay_id_of(scheduled);

        WHEN("the join is sent normally and the delayed event is restarted twenty seconds in")
        {
            auto const join = request(fixture.runtime(), "PUT", fixture.room_path() + "/state/" + type + "/" + key,
                                      fixture.alice_token, R"({"application":"m.call","call_id":""})");
            fixture.set_time(t0 + 20'000U);
            auto const restart = post_body_action(fixture, id, R"({"action":"restart"})", fixture.alice_token);

            THEN("the join did not cancel the leave, and the leave comes at the new due time")
            {
                CHECK(join.status == 200U);
                CHECK(restart.status == 200U);
                CHECK(restart.body == "{}");
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                fixture.run_job(t0 + 30'000U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK(state_content(fixture, type, "_%40alice%3Aexample.org_D1").body.find("m.call") !=
                      std::string::npos);
                fixture.set_time(t0 + 50'000U);
                fixture.run_job(t0 + 50'000U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                auto const current = state_content(fixture, type, "_%40alice%3Aexample.org_D1");
                CHECK(current.status == 200U);
                CHECK(current.body == "{}");
            }
        }
    }
}

SCENARIO("The Element Web flow schedules on the unstable path, restarts and then sends on the path form",
         "[homeserver][delayed-events][routes][element-web]")
{
    GIVEN("alice with a message scheduled by the unstable dedicated path")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "web");
        auto const before = fixture.event_count();

        WHEN("she restarts it and then sends it")
        {
            auto const restart = post_action(fixture, false, id, "restart", fixture.alice_token);
            auto const sent = post_action(fixture, false, id, "send", fixture.alice_token);

            THEN("both answer 200 {} and the event is sent at once")
            {
                CHECK(restart.status == 200U);
                CHECK(restart.body == "{}");
                CHECK(sent.status == 200U);
                CHECK(sent.body == "{}");
                CHECK(fixture.event_count() == before + 1U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK(timeline_has(fixture, "m.test.delayed"));
            }
        }
    }
}

SCENARIO("A request without the delay parameter sends at once as before", "[homeserver][delayed-events][routes][send]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const before = fixture.event_count();

        WHEN("she sends a message and a state event with no delay parameter")
        {
            auto const sent = request(fixture.runtime(), "PUT", fixture.room_path() + "/send/m.test.delayed/p1",
                                      fixture.alice_token, std::string{message_content});
            auto const state = request(fixture.runtime(), "PUT", fixture.room_path() + "/state/m.test.state/k",
                                       fixture.alice_token, R"({"v":1})");

            THEN("each answers an event_id and is stored")
            {
                CHECK(sent.status == 200U);
                CHECK(sent.body.find("event_id") != std::string::npos);
                CHECK(state.status == 200U);
                CHECK(state.body.find("event_id") != std::string::npos);
                CHECK(fixture.event_count() == before + 2U);
            }
        }
    }
}

SCENARIO("With delayed events disabled every scheduling form is 403 and nothing is sent",
         "[homeserver][delayed-events][routes][disabled]")
{
    GIVEN("a server with the feature switched off")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.delayed_events_enabled = false;
        auto const before = fixture.event_count();
        auto const form = GENERATE(0, 1, 2, 3, 4);

        WHEN("a form is used, with a body or parameter that would also be refused")
        {
            auto const response = [&]() -> hs::LocalHttpResponse {
                switch (form)
                {
                case 0:
                    return put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "t", "not even json{");
                case 1:
                    return put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "t", "{}");
                case 2:
                    return put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "t",
                                            std::string{delay_param} + "=banana");
                case 3:
                    return put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                             std::string{delay_param} + "=5000");
                default:
                    return put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "t",
                                            std::string{delay_param} + "=5000");
                }
            }();

            THEN("the answer is 403 M_FORBIDDEN, or the gate's M_NOT_JSON for a body that is not JSON, and no "
                 "event is sent")
            {
                if (form == 0)
                {
                    CHECK(response.status == 400U);
                    CHECK(errcode_of(response) == "M_NOT_JSON");
                }
                else
                {
                    CHECK(response.status == 403U);
                    CHECK(errcode_of(response) == "M_FORBIDDEN");
                }
                CHECK(fixture.event_count() == before);
                CHECK(state_content(fixture, "m.test.state", "k").status == 404U);
            }
        }

        WHEN("a disabled server is asked for its dedicated routes with a valid body")
        {
            auto const s1 =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "d1", schedule_body(5'000U));
            auto const s2 =
                put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "d2", schedule_body(5'000U));

            THEN("both are 403 M_FORBIDDEN")
            {
                CHECK(s1.status == 403U);
                CHECK(errcode_of(s1) == "M_FORBIDDEN");
                CHECK(s2.status == 403U);
                CHECK(errcode_of(s2) == "M_FORBIDDEN");
            }
        }
    }
}

SCENARIO("A delay parameter that is not one whole number of at least 1 is refused and nothing is sent",
         "[homeserver][delayed-events][routes][invalid-param]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const before = fixture.event_count();
        auto const query = GENERATE(
            std::string{"org.matrix.msc4140.delay="}, std::string{"org.matrix.msc4140.delay"},
            std::string{"org.matrix.msc4140.delay=abc"}, std::string{"org.matrix.msc4140.delay=+5"},
            std::string{"org.matrix.msc4140.delay=5.0"}, std::string{"org.matrix.msc4140.delay=%205"},
            std::string{"org.matrix.msc4140.delay=0x10"}, std::string{"org.matrix.msc4140.delay=-1"},
            std::string{"org.matrix.msc4140.delay=0"}, std::string{"org.matrix.msc4140.delay=99999999999999999999999"},
            std::string{"org.matrix.msc4140.delay=18446744073709551616"},
            std::string{"org.matrix.msc4140.delay=5000&org.matrix.msc4140.delay=6000"},
            std::string{"org.matrix.msc4140.delay=5000&ts=1&org.matrix.msc4140.delay=5000"},
            std::string{"org%2Ematrix.msc4140.delay=banana"});

        WHEN("the send route and the state route are called with it")
        {
            auto const send = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "bad", query);
            auto const state = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k", query);

            THEN("both answer 400 M_INVALID_PARAM, schedule nothing and send nothing")
            {
                INFO(query);
                CHECK(send.status == 400U);
                CHECK(errcode_of(send) == "M_INVALID_PARAM");
                CHECK(state.status == 400U);
                CHECK(errcode_of(state) == "M_INVALID_PARAM");
                CHECK(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("The delay parameter is read with leading zeros and an encoded name, and the body must still be an object",
         "[homeserver][delayed-events][routes][invalid-param]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const before = fixture.event_count();

        WHEN("the delay is written 007 and the parameter name percent-encoded")
        {
            auto const padded = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "z1",
                                                 std::string{delay_param} + "=0007");
            auto const encoded = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "z2",
                                                  "org%2Ematrix.msc4140.delay=5000");
            auto const not_object = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "z3",
                                                     std::string{delay_param} + "=5000", "[]");
            auto const state_encoded = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                                         "org%2Ematrix.msc4140.delay=5000");
            auto const state_padded = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                                        std::string{delay_param} + "=0007");

            THEN("the first two are scheduled, the third is M_BAD_JSON, and nothing is sent")
            {
                CHECK(delay_id_of(padded).size() > 0U);
                CHECK(delay_id_of(encoded).size() > 0U);
                CHECK(delay_id_of(state_encoded).size() > 0U);
                CHECK(delay_id_of(state_padded).size() > 0U);
                CHECK(not_object.status == 400U);
                CHECK(errcode_of(not_object) == "M_BAD_JSON");
                CHECK(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("The dedicated routes refuse a body that is not the documented object with M_BAD_JSON",
         "[homeserver][delayed-events][routes][bad-body]")
{
    GIVEN("alice in a room and a body")
    {
        auto fixture = Fixture{};
        auto const body = GENERATE(
            std::string{}, std::string{"   "}, std::string{"{}"}, std::string{"[]"}, std::string{"5"},
            std::string{R"("text")"}, std::string{R"({"content":{}})"}, std::string{R"({"delay_ms":5000})"},
            std::string{R"({"delay_ms":"5000","content":{}})"}, std::string{R"({"delay_ms":5000.5,"content":{}})"},
            std::string{R"({"delay_ms":5000.0,"content":{}})"}, std::string{R"({"delay_ms":true,"content":{}})"},
            std::string{R"({"delay_ms":null,"content":{}})"}, std::string{R"({"delay_ms":-5,"content":{}})"},
            std::string{R"({"delay_ms":0,"content":{}})"}, std::string{R"({"delay_ms":5000,"content":[]})"},
            std::string{R"({"delay_ms":5000,"content":"x"})"},
            std::string{R"({"delay_ms":5000,"content":{},"state_key":5})"},
            std::string{R"({"delay_ms":5000,"content":{},"state_key":null})"});
        auto const before = fixture.event_count();

        WHEN("each dedicated route is called with it")
        {
            auto const s1 = put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "b1", body);
            auto const s2 = put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "b2", body);

            THEN("both answer 400 M_BAD_JSON and nothing is stored")
            {
                INFO(body);
                CHECK(s1.status == 400U);
                CHECK(errcode_of(s1) == "M_BAD_JSON");
                CHECK(s2.status == 400U);
                CHECK(errcode_of(s2) == "M_BAD_JSON");
                CHECK(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("The dedicated routes answer the gate's M_NOT_JSON for a body that is not JSON and ignore unknown members",
         "[homeserver][delayed-events][routes][bad-body]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};

        WHEN("a body that is not JSON, and a body with unknown members, are sent")
        {
            auto const garbage =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "n1", "{\"delay_ms\"");
            auto const extra = put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "n2",
                                             R"({"delay_ms":5000,"content":{},"sticky_duration_ms":7,"extra":[1]})");

            THEN("the first is 400 M_NOT_JSON and the second schedules")
            {
                CHECK(garbage.status == 400U);
                CHECK(errcode_of(garbage) == "M_NOT_JSON");
                CHECK(delay_id_of(extra).size() > 0U);
            }
        }
    }
}

SCENARIO("A delay over the maximum names the stable errcode on S1 and the unstable one everywhere else",
         "[homeserver][delayed-events][routes][limits]")
{
    GIVEN("a maximum delay of one hour")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_delayed_event_delay_ms = 3'600'000U;
        auto const before = fixture.event_count();

        WHEN("each form asks for an hour and a millisecond")
        {
            auto const s1 =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "l1", schedule_body(3'600'001U));
            auto const s2 =
                put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "l2", schedule_body(3'600'001U));
            auto const l1 = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "l3",
                                             std::string{delay_param} + "=3600001");
            auto const l2 = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                              std::string{delay_param} + "=3600001");
            auto const exact = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "l4",
                                                std::string{delay_param} + "=3600000");

            THEN("each is 400 with its errcode, and the maximum itself is accepted")
            {
                CHECK(s1.status == 400U);
                CHECK(errcode_of(s1) == "M_DELAY_TOO_LARGE");
                for (auto const* other : {&s2, &l1, &l2})
                {
                    CHECK(other->status == 400U);
                    CHECK(errcode_of(*other) == "ORG.MATRIX.MSC4140_DELAY_TOO_LARGE");
                }
                CHECK(delay_id_of(exact).size() > 0U);
                CHECK(fixture.event_count() == before);
            }
        }
    }
}

SCENARIO("A user at the scheduled-event cap is answered 429 with Retry-After and retry_after_ms",
         "[homeserver][delayed-events][routes][limits]")
{
    GIVEN("a cap of one scheduled event and alice holding one")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_scheduled_delayed_events_per_user = 1U;
        std::ignore = schedule_message(fixture, "c1", 60'000U);

        WHEN("she schedules another by each form")
        {
            auto const s1 =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "c2", schedule_body(5'000U));
            auto const l1 = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "c3",
                                             std::string{delay_param} + "=5000");

            THEN("both are 429 M_LIMIT_EXCEEDED with the header and the body field")
            {
                for (auto const* denied : {&s1, &l1})
                {
                    CHECK(denied->status == 429U);
                    CHECK(errcode_of(*denied) == "M_LIMIT_EXCEEDED");
                    auto const denied_body = parse_object(denied->body);
                    auto const* retry = int_member(denied_body, "retry_after_ms");
                    REQUIRE(retry != nullptr);
                    CHECK(*retry == 60'000);
                    CHECK(header_of(*denied, "Retry-After") == "60");
                }
            }
        }
    }
}

SCENARIO("Management routes take an empty body, an empty object, unknown members, and answer the gate for non-JSON",
         "[homeserver][delayed-events][routes][manage]")
{
    GIVEN("alice with a scheduled message and a body")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "m1");
        auto const stable = GENERATE(true, false);
        auto const body =
            GENERATE(std::string{}, std::string{"{}"}, std::string{R"({"unknown":[1,2],"action":"cancel"})"});

        WHEN("restart is posted with that body")
        {
            auto const response = post_action(fixture, stable, id, "restart", fixture.alice_token, body);

            THEN("it is 200 {} and the action is the path's: the event is still scheduled")
            {
                CHECK(response.status == 200U);
                CHECK(response.body == "{}");
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }

        WHEN("restart is posted with a body that is not JSON")
        {
            auto const response = post_action(fixture, stable, id, "restart", fixture.alice_token, "not json");

            THEN("the gate answers 400 M_NOT_JSON before the route runs")
            {
                CHECK(response.status == 400U);
                CHECK(errcode_of(response) == "M_NOT_JSON");
            }
        }
    }
}

SCENARIO("Each management action follows the outcome table on both prefixes",
         "[homeserver][delayed-events][routes][manage]")
{
    GIVEN("alice with delayed messages in each state and a prefix")
    {
        auto fixture = Fixture{};
        auto const stable = GENERATE(true, false);
        auto const scheduled = schedule_message(fixture, "o1");
        auto const sent = schedule_message(fixture, "o2");
        auto const cancelled = schedule_message(fixture, "o3");
        REQUIRE(post_action(fixture, stable, sent, "send", fixture.alice_token).status == 200U);
        REQUIRE(post_action(fixture, stable, cancelled, "cancel", fixture.alice_token).status == 200U);
        auto const& token = fixture.alice_token;

        WHEN("each action is posted to each")
        {
            THEN("the answers are the ADR-0823 table's, 409 with M_UNKNOWN where it says so")
            {
                CHECK(post_action(fixture, stable, scheduled, "restart", token).status == 200U);
                CHECK(post_action(fixture, stable, sent, "send", token).status == 200U);
                for (auto const* action : {"restart", "cancel"})
                {
                    auto const response = post_action(fixture, stable, sent, action, token);
                    CHECK(response.status == 409U);
                    CHECK(errcode_of(response) == "M_UNKNOWN");
                }
                CHECK(post_action(fixture, stable, cancelled, "cancel", token).status == 200U);
                for (auto const* action : {"restart", "send"})
                {
                    auto const response = post_action(fixture, stable, cancelled, action, token);
                    CHECK(response.status == 409U);
                    CHECK(errcode_of(response) == "M_UNKNOWN");
                }
                CHECK(post_action(fixture, stable, scheduled, "cancel", token).status == 200U);
                CHECK(status_of(fixture, alice, scheduled) == db::DelayedEventStatus::cancelled);
            }
        }
    }
}

SCENARIO("A last path segment that is not an action is not a route", "[homeserver][delayed-events][routes][manage]")
{
    GIVEN("alice with a scheduled message")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "u1");

        WHEN("an unknown action, a trailing slash and a deeper path are posted on both prefixes")
        {
            THEN("each is the dispatcher's 404 M_UNRECOGNIZED and the event is untouched")
            {
                for (auto const base : {v1, unstable})
                {
                    for (auto const* tail : {"/destroy", "/send/", "/send/more", "/", ""})
                    {
                        auto const path = std::string{base} + id + tail;
                        auto const response = request(fixture.runtime(), "POST", path, fixture.alice_token, "{}");
                        INFO(path);
                        if (std::string_view{tail}.empty())
                        {
                            // `/v1/delayed_events/{id}` is no route (405) and the unstable one is M3 (400 missing
                            // action).
                            CHECK(response.status == (base == v1 ? 405U : 400U));
                        }
                        else
                        {
                            CHECK(response.status == 404U);
                            CHECK(errcode_of(response) == "M_UNRECOGNIZED");
                        }
                    }
                }
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("The action in the body of the unstable POST selects the operation",
         "[homeserver][delayed-events][routes][m3]")
{
    GIVEN("alice with delayed messages")
    {
        auto fixture = Fixture{};
        auto const restart_id = schedule_message(fixture, "p1");
        auto const send_id = schedule_message(fixture, "p2");
        auto const cancel_id = schedule_message(fixture, "p3");
        auto const before = fixture.event_count();

        WHEN("each action is posted")
        {
            auto const restart = post_body_action(fixture, restart_id, R"({"action":"restart"})", fixture.alice_token);
            auto const sent = post_body_action(fixture, send_id, R"({"action":"send","extra":1})", fixture.alice_token);
            auto const cancel = post_body_action(fixture, cancel_id, R"({"action":"cancel"})", fixture.alice_token);

            THEN("each acts and answers 200 {}")
            {
                CHECK(restart.status == 200U);
                CHECK(restart.body == "{}");
                CHECK(sent.status == 200U);
                CHECK(cancel.status == 200U);
                CHECK(status_of(fixture, alice, restart_id) == db::DelayedEventStatus::scheduled);
                CHECK(status_of(fixture, alice, send_id) == db::DelayedEventStatus::sent);
                CHECK(status_of(fixture, alice, cancel_id) == db::DelayedEventStatus::cancelled);
                CHECK(fixture.event_count() == before + 1U);
            }
        }

        WHEN("the body has no action, an unknown action, a non-string action or is not an object")
        {
            auto const missing = post_body_action(fixture, restart_id, R"({"other":"send"})", fixture.alice_token);
            auto const unknown = post_body_action(fixture, restart_id, R"({"action":"explode"})", fixture.alice_token);
            auto const number = post_body_action(fixture, restart_id, R"({"action":5})", fixture.alice_token);
            auto const array = post_body_action(fixture, restart_id, R"([])", fixture.alice_token);
            auto const empty = post_body_action(fixture, restart_id, "", fixture.alice_token);

            THEN("the answers are M_MISSING_PARAM, M_INVALID_PARAM and M_BAD_JSON, and nothing happens")
            {
                CHECK(missing.status == 400U);
                CHECK(errcode_of(missing) == "M_MISSING_PARAM");
                CHECK(unknown.status == 400U);
                CHECK(errcode_of(unknown) == "M_INVALID_PARAM");
                CHECK(number.status == 400U);
                CHECK(errcode_of(number) == "M_INVALID_PARAM");
                CHECK(array.status == 400U);
                CHECK(errcode_of(array) == "M_BAD_JSON");
                CHECK(empty.status == 400U);
                CHECK(errcode_of(empty) == "M_BAD_JSON");
                CHECK(status_of(fixture, alice, restart_id) == db::DelayedEventStatus::scheduled);
                CHECK(fixture.event_count() == before);
            }
        }

        WHEN("the same body is posted to the stable prefix")
        {
            auto const response = request(fixture.runtime(), "POST", std::string{v1} + restart_id, fixture.alice_token,
                                          R"({"action":"restart"})");

            THEN("there is no such route: 405 M_UNRECOGNIZED, the dispatcher's answer for a method a path lacks")
            {
                CHECK(response.status == 405U);
                CHECK(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("A failed send action answers what the ordinary send answers and leaves the event scheduled",
         "[homeserver][delayed-events][routes][manage]")
{
    GIVEN("bob with a delayed message, who then leaves the room")
    {
        auto fixture = Fixture{};
        auto const message_id = schedule_message(fixture, "f1", 60'000U, fixture.bob_token);
        REQUIRE(request(fixture.runtime(), "POST", fixture.room_path() + "/leave", fixture.bob_token, "{}").status ==
                200U);

        WHEN("the send action is posted on each route form, and an ordinary send of the same event is made")
        {
            auto const stable = post_action(fixture, true, message_id, "send", fixture.bob_token);
            auto const unstable_form = post_action(fixture, false, message_id, "send", fixture.bob_token);
            auto const body_form = post_body_action(fixture, message_id, R"({"action":"send"})", fixture.bob_token);
            auto const ordinary = request(fixture.runtime(), "PUT", fixture.room_path() + "/send/m.test.delayed/o-1",
                                          fixture.bob_token, std::string{message_content});

            THEN("the status and errcode are the ordinary route's, and the event is still scheduled")
            {
                CHECK(ordinary.status >= 400U);
                for (auto const* delayed : {&stable, &unstable_form, &body_form})
                {
                    CHECK(delayed->status == ordinary.status);
                    CHECK(errcode_of(*delayed) == errcode_of(ordinary));
                }
                CHECK(status_of(fixture, bob, message_id) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("Lookup shows a scheduled, a sent, a cancelled and a failed event on both prefixes",
         "[homeserver][delayed-events][routes][lookup]")
{
    GIVEN("alice's events in the four states, the failed one bob's")
    {
        auto fixture = Fixture{};
        auto const scheduled = schedule_message(fixture, "g1", 60'000U);
        auto const sent = schedule_message(fixture, "g2", 60'000U);
        auto const cancelled = schedule_message(fixture, "g3", 60'000U);
        auto const failed = schedule_message(fixture, "g4", 10'000U, fixture.bob_token);
        REQUIRE(post_action(fixture, true, sent, "send", fixture.alice_token).status == 200U);
        REQUIRE(post_action(fixture, true, cancelled, "cancel", fixture.alice_token).status == 200U);
        REQUIRE(request(fixture.runtime(), "POST", fixture.room_path() + "/leave", fixture.bob_token, "{}").status ==
                200U);
        fixture.set_time(t0 + 10'000U);
        fixture.run_job(t0 + 10'000U);

        WHEN("each is looked up on both prefixes")
        {
            auto const body = [&](std::string const& id, std::string const& token) {
                auto const stable = get_delayed(fixture, true, id, token);
                auto const other = get_delayed(fixture, false, id, token);
                REQUIRE(stable.status == 200U);
                REQUIRE(other.status == 200U);
                REQUIRE(stable.body == other.body);
                return parse_object(stable.body);
            };
            auto const found_scheduled = body(scheduled, fixture.alice_token);
            auto const found_sent = body(sent, fixture.alice_token);
            auto const found_cancelled = body(cancelled, fixture.alice_token);
            auto const found_failed = body(failed, fixture.bob_token);

            THEN("the members are the service's")
            {
                CHECK(*string_member(found_scheduled, "delay_id") == scheduled);
                CHECK(*string_member(found_scheduled, "room_id") == fixture.room_id);
                CHECK(*string_member(found_scheduled, "type") == "m.test.delayed");
                CHECK(string_member(found_scheduled, "state_key") == nullptr);
                CHECK(*int_member(found_scheduled, "delay_ms") == 60'000);
                CHECK(*int_member(found_scheduled, "delayed_since_ts") == static_cast<std::int64_t>(t0));
                CHECK(object_member_as_object(found_scheduled, "content") != nullptr);
                CHECK(object_member(found_scheduled, "finalised") == nullptr);

                auto const* sent_final = object_member_as_object(found_sent, "finalised");
                REQUIRE(sent_final != nullptr);
                CHECK(string_member(*sent_final, "event_id") != nullptr);
                CHECK(int_member(*sent_final, "finalised_ts") != nullptr);
                CHECK(string_member(*sent_final, "error") == nullptr);

                auto const* cancelled_final = object_member_as_object(found_cancelled, "finalised");
                REQUIRE(cancelled_final != nullptr);
                CHECK(string_member(*cancelled_final, "event_id") == nullptr);
                CHECK(object_member(*cancelled_final, "error") == nullptr);

                auto const* failed_final = object_member_as_object(found_failed, "finalised");
                REQUIRE(failed_final != nullptr);
                CHECK(string_member(*failed_final, "event_id") == nullptr);
                CHECK(object_member_as_object(*failed_final, "error") != nullptr);
            }
        }
    }
}

SCENARIO("An unknown delay ID and another user's get the same 404 on every management and lookup route",
         "[homeserver][delayed-events][routes][not-found]")
{
    GIVEN("alice's scheduled event and bob, who asks about it and about an ID that does not exist")
    {
        auto fixture = Fixture{};
        auto const alice_id = schedule_message(fixture, "x1");
        auto const due_before = db::delayed_event_due_ms(*fixture.table().find_owned(alice, alice_id));
        struct Route final
        {
            std::string method;
            std::string tail;
            std::string body;
            bool stable;
        };
        auto const routes = std::vector<Route>{
            {"POST", "/send",    "",                        true },
            {"POST", "/cancel",  "",                        true },
            {"POST", "/restart", "{}",                      true },
            {"POST", "/send",    "",                        false},
            {"POST", "/cancel",  "{}",                      false},
            {"POST", "/restart", "",                        false},
            {"POST", "",         R"({"action":"send"})",    false},
            {"POST", "",         R"({"action":"cancel"})",  false},
            {"POST", "",         R"({"action":"restart"})", false},
            {"GET",  "",         "",                        true },
            {"GET",  "",         "",                        false},
        };

        WHEN("bob calls every route with each ID")
        {
            THEN("the two answers are equal in status, body and headers, and alice's event is untouched")
            {
                for (auto const& route : routes)
                {
                    auto const base = std::string{route.stable ? v1 : unstable};
                    auto const unknown = request(fixture.runtime(), route.method,
                                                 base + "no-such-delay-id" + route.tail, fixture.bob_token, route.body);
                    auto const foreign = request(fixture.runtime(), route.method, base + alice_id + route.tail,
                                                 fixture.bob_token, route.body);
                    INFO(route.method << " " << route.tail << (route.stable ? " stable" : " unstable"));
                    CHECK(unknown.status == 404U);
                    CHECK(errcode_of(unknown) == "M_NOT_FOUND");
                    CHECK(foreign.status == unknown.status);
                    CHECK(foreign.body == unknown.body);
                    CHECK(foreign.headers == unknown.headers);
                }
                CHECK(status_of(fixture, alice, alice_id) == db::DelayedEventStatus::scheduled);
                CHECK(db::delayed_event_due_ms(*fixture.table().find_owned(alice, alice_id)) == due_before);
            }
        }
    }
}

SCENARIO("Every route needs a valid token and a suspended or locked account gets the gate's answer",
         "[homeserver][delayed-events][routes][auth]")
{
    GIVEN("alice with a scheduled event")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "a1");
        struct Route final
        {
            std::string method;
            std::string target;
            std::string body;
        };
        auto const room = fixture.room_path();
        auto const routes = std::vector<Route>{
            {"PUT",  room + "/delayed_event/m.test.delayed/a2",                      schedule_body(5'000U)       },
            {"PUT",
             "/_matrix/client/unstable/org.matrix.msc4140/rooms/" + fixture.room_id +
                 "/delayed_event/m.test.delayed/a3",                                 schedule_body(5'000U)       },
            {"PUT",  room + "/send/m.test.delayed/a4?org.matrix.msc4140.delay=5000", std::string{message_content}},
            {"PUT",  room + "/state/m.test.state/k?org.matrix.msc4140.delay=5000",   R"({"v":1})"                },
            {"POST", std::string{v1} + id + "/restart",                              ""                          },
            {"POST", std::string{unstable} + id + "/cancel",                         ""                          },
            {"POST", std::string{unstable} + id,                                     R"({"action":"restart"})"   },
            {"GET",  std::string{v1} + id,                                           ""                          },
            {"GET",  std::string{unstable} + id,                                     ""                          },
        };

        WHEN("the routes are called with no token and with a token the server does not know")
        {
            THEN("they are 401 M_MISSING_TOKEN and 401 M_UNKNOWN_TOKEN")
            {
                for (auto const& route : routes)
                {
                    INFO(route.method << " " << route.target);
                    auto const none = request(fixture.runtime(), route.method, route.target, {}, route.body);
                    auto const bad =
                        request(fixture.runtime(), route.method, route.target, "not-a-real-token", route.body);
                    CHECK(none.status == 401U);
                    CHECK(errcode_of(none) == "M_MISSING_TOKEN");
                    CHECK(bad.status == 401U);
                    CHECK(errcode_of(bad) == "M_UNKNOWN_TOKEN");
                }
            }
        }

        WHEN("alice is suspended, or locked")
        {
            auto const locked = GENERATE(false, true);
            auto& homeserver = fixture.runtime().homeserver;
            REQUIRE(hs::bootstrap_admin_user(homeserver, "admin", password).ok);
            REQUIRE(
                hs::set_local_user_moderation(homeserver, "@admin:example.org", alice, !locked, locked, "t", "t").ok);

            THEN("every route is the moderation gate's refusal and nothing changes")
            {
                for (auto const& route : routes)
                {
                    INFO(route.method << " " << route.target);
                    auto const response =
                        request(fixture.runtime(), route.method, route.target, fixture.alice_token, route.body);
                    CHECK(response.status == (locked ? 401U : 403U));
                    CHECK(errcode_of(response) == (locked ? "M_USER_LOCKED" : "M_USER_SUSPENDED"));
                }
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("An application service acting for a user manages that user's delayed event and no one else's",
         "[homeserver][delayed-events][routes][appservice]")
{
    GIVEN("an application service whose namespace holds alice and bob, and alice's delayed event")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@.*:example.org"};
        auto fixture = Fixture{appservice_test_config({bridge})};
        auto const token = bridge.as_token();
        auto const id = schedule_message(fixture, "as1");
        auto const as_alice = std::string{"?user_id=@alice:example.org"};
        auto const as_bob = std::string{"?user_id=@bob:example.org"};
        auto const before = fixture.event_count();

        WHEN("it restarts and then sends alice's event as alice")
        {
            auto const restart =
                request(fixture.runtime(), "POST", std::string{unstable} + id + "/restart" + as_alice, token);
            auto const sent =
                request(fixture.runtime(), "POST", std::string{unstable} + id + "/send" + as_alice, token);

            THEN("both are 200 and the event is sent as alice")
            {
                CHECK(restart.status == 200U);
                CHECK(sent.status == 200U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::sent);
                CHECK(fixture.event_count() == before + 1U);
            }
        }

        WHEN("it acts as bob on alice's event, and as alice on a lookup")
        {
            auto const restart =
                request(fixture.runtime(), "POST", std::string{unstable} + id + "/restart" + as_bob, token);
            auto const cancel =
                request(fixture.runtime(), "POST", std::string{unstable} + id + "/cancel" + as_bob, token);
            auto const lookup = request(fixture.runtime(), "GET", std::string{unstable} + id + as_alice, token);

            THEN("bob's attempts are 404 M_NOT_FOUND and alice's event is untouched, while her lookup works")
            {
                CHECK(restart.status == 404U);
                CHECK(errcode_of(restart) == "M_NOT_FOUND");
                CHECK(cancel.status == 404U);
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
                CHECK(lookup.status == 200U);
            }
        }
    }
}

SCENARIO("/versions and /capabilities advertise delayed events with the configured limits",
         "[homeserver][delayed-events][routes][advertisement]")
{
    GIVEN("a server with the feature on, or off")
    {
        auto fixture = Fixture{};
        auto const enabled = GENERATE(true, false);
        fixture.runtime().limits.delayed_events_enabled = enabled;
        fixture.runtime().limits.max_delayed_event_delay_ms = 7'200'000U;
        fixture.runtime().limits.max_scheduled_delayed_events_per_user = 17U;

        WHEN("/versions and /capabilities are read")
        {
            auto const versions = parse_object(request(fixture.runtime(), "GET", "/_matrix/client/versions").body);
            auto const capabilities_response =
                request(fixture.runtime(), "GET", "/_matrix/client/v3/capabilities", fixture.alice_token);
            REQUIRE(capabilities_response.status == 200U);
            auto const capabilities =
                *object_member_as_object(parse_object(capabilities_response.body), "capabilities");

            THEN("both flags equal enabled, and both capabilities carry the limits, or zeros when disabled")
            {
                auto const* features = object_member_as_object(versions, "unstable_features");
                REQUIRE(features != nullptr);
                for (auto const* flag : {"org.matrix.msc4140", "org.matrix.msc4140.stable"})
                {
                    auto const* value = bool_member(*features, flag);
                    REQUIRE(value != nullptr);
                    CHECK(*value == enabled);
                }
                for (auto const* name : {"m.delayed_events", "org.matrix.msc4140.delayed_events"})
                {
                    auto const* entry = object_member_as_object(capabilities, name);
                    REQUIRE(entry != nullptr);
                    REQUIRE(int_member(*entry, "max_delay_ms") != nullptr);
                    REQUIRE(int_member(*entry, "max_scheduled") != nullptr);
                    CHECK(*int_member(*entry, "max_delay_ms") == (enabled ? 7'200'000 : 0));
                    CHECK(*int_member(*entry, "max_scheduled") == (enabled ? 17 : 0));
                }
            }
        }
    }
}

SCENARIO("The built-in per-user limits stop the 121st management request and the 61st scheduling request",
         "[homeserver][delayed-events][routes][rate-limit]")
{
    // The rate-limit engine reads the steady clock itself (`ClientServerClock`, no test seam), so this scenario relies
    // on its 121 (or 61) in-process requests completing within the policy's 60-second window.
    GIVEN("alice and bob on one server with the default rate limits")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.max_scheduled_delayed_events_per_user = 1000U;

        WHEN("alice makes 121 lookups of an ID that does not exist")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto index = 0; index < 121; ++index)
            {
                statuses.push_back(get_delayed(fixture, true, "none", fixture.alice_token).status);
            }
            auto const bob_answer = get_delayed(fixture, true, "none", fixture.bob_token);

            THEN("the first 120 are 404, the 121st is 429 M_LIMIT_EXCEEDED, and bob is not limited")
            {
                for (auto index = std::size_t{0U}; index < 120U; ++index)
                {
                    CHECK(statuses[index] == 404U);
                }
                CHECK(statuses[120] == 429U);
                CHECK(bob_answer.status == 404U);
            }
        }

        WHEN("alice schedules 61 events on the dedicated route")
        {
            auto statuses = std::vector<std::uint16_t>{};
            auto last = hs::LocalHttpResponse{};
            for (auto index = 0; index < 61; ++index)
            {
                last = put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "r" + std::to_string(index),
                                     schedule_body(60'000U));
                statuses.push_back(last.status);
            }
            auto const bob_answer =
                put_dedicated(fixture, true, fixture.bob_token, "m.test.delayed", "r0", schedule_body(60'000U));

            THEN("the first 60 are scheduled, the 61st is 429 M_LIMIT_EXCEEDED, and bob is not limited")
            {
                for (auto index = std::size_t{0U}; index < 60U; ++index)
                {
                    CHECK(statuses[index] == 200U);
                }
                CHECK(statuses[60] == 429U);
                CHECK(errcode_of(last) == "M_LIMIT_EXCEEDED");
                CHECK(bob_answer.status == 200U);
            }
        }
    }
}

SCENARIO("A method a delayed-event path does not serve, and the listing, get the dispatcher's standard answers",
         "[homeserver][delayed-events][routes][methods]")
{
    GIVEN("alice with a scheduled event")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "w1");

        WHEN("the wrong methods are used, and the listing is asked for")
        {
            auto const get_schedule =
                request(fixture.runtime(), "GET", fixture.room_path() + "/delayed_event/m.test.delayed/w2",
                        fixture.alice_token);
            auto const post_schedule =
                request(fixture.runtime(), "POST", fixture.room_path() + "/delayed_event/m.test.delayed/w2",
                        fixture.alice_token, schedule_body(5'000U));
            auto const delete_event = request(fixture.runtime(), "DELETE", std::string{v1} + id, fixture.alice_token);
            auto const put_event =
                request(fixture.runtime(), "PUT", std::string{unstable} + id, fixture.alice_token, "{}");
            auto const get_action =
                request(fixture.runtime(), "GET", std::string{v1} + id + "/send", fixture.alice_token);
            auto const put_action =
                request(fixture.runtime(), "PUT", std::string{v1} + id + "/send", fixture.alice_token, "{}");
            auto const list_stable =
                request(fixture.runtime(), "GET", std::string{v1}.substr(0U, v1.size() - 1U), fixture.alice_token);
            auto const list_unstable = request(
                fixture.runtime(), "GET", std::string{unstable}.substr(0U, unstable.size() - 1U), fixture.alice_token);
            auto const list_slash = request(fixture.runtime(), "GET", std::string{v1}, fixture.alice_token);

            THEN("a served path with another method is 405 M_UNRECOGNIZED and the listing is 404 M_UNRECOGNIZED")
            {
                for (auto const* wrong :
                     {&get_schedule, &post_schedule, &delete_event, &put_event, &get_action, &put_action})
                {
                    CHECK(wrong->status == 405U);
                    CHECK(errcode_of(*wrong) == "M_UNRECOGNIZED");
                }
                for (auto const* listing : {&list_stable, &list_unstable, &list_slash})
                {
                    CHECK(listing->status == 404U);
                    CHECK(errcode_of(*listing) == "M_UNRECOGNIZED");
                }
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("A NUL in the content of a delayed event is refused as a raw byte and kept as an escape",
         "[homeserver][delayed-events][routes][nul]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};
        auto const before = fixture.event_count();
        auto const raw_nul = std::string{"{\"a\":\"x"} + std::string(1U, '\0') + "y\"}";
        auto const escaped_nul = std::string{R"({"a":"x\u0000y"})"};

        WHEN("the legacy forms carry a raw NUL byte inside a string")
        {
            auto const l1 = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "n1",
                                             std::string{delay_param} + "=5000", raw_nul);
            auto const l2 = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                              std::string{delay_param} + "=5000", raw_nul);

            THEN("each is 400 M_NOT_JSON from the gate, and nothing is stored or sent")
            {
                for (auto const* response : {&l1, &l2})
                {
                    CHECK(response->status == 400U);
                    CHECK(errcode_of(*response) == "M_NOT_JSON");
                }
                CHECK(fixture.event_count() == before);
            }
        }

        WHEN("each form carries the escape \u0000 in a string")
        {
            auto const l1 = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "n2",
                                             std::string{delay_param} + "=5000", escaped_nul);
            auto const l2 = put_state_delayed(fixture, fixture.alice_token, "m.test.state", "/k",
                                              std::string{delay_param} + "=5000", escaped_nul);
            auto const s1 = put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "n3",
                                          schedule_body(5'000U, escaped_nul));
            auto const s2 = put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "n4",
                                          schedule_body(5'000U, escaped_nul));

            THEN("each is accepted and no stored content holds a raw NUL byte")
            {
                for (auto const* response : {&l1, &l2, &s1, &s2})
                {
                    auto const id = delay_id_of(*response);
                    auto const* row = fixture.table().find_owned(alice, id);
                    REQUIRE(row != nullptr);
                    CHECK(row->content_json.find('\0') == std::string::npos);
                    CHECK(row->content_json.find(R"(\u0000)") != std::string::npos);
                    CHECK(get_delayed(fixture, true, id, fixture.alice_token).status == 200U);
                }
            }
            AND_THEN("after the job each is sent and the sent event holds the escape, as the client sent it")
            {
                auto ids = std::vector<std::string>{};
                for (auto const* response : {&l1, &l2, &s1, &s2})
                {
                    ids.push_back(delay_id_of(*response));
                }
                fixture.set_time(t0 + 5'000U);
                fixture.run_job(t0 + 5'000U);
                CHECK(fixture.event_count() == before + 4U);
                for (auto const& id : ids)
                {
                    auto const* row = fixture.table().find_owned(alice, id);
                    REQUIRE(row != nullptr);
                    CHECK(row->status == db::DelayedEventStatus::sent);
                    auto const event = request(fixture.runtime(), "GET",
                                               fixture.room_path() + "/event/" + row->event_id, fixture.alice_token);
                    REQUIRE(event.status == 200U);
                    CHECK(event.body.find(R"("a":"x\u0000y")") != std::string::npos);
                }
            }
        }
    }
}

SCENARIO("Any other route that sends from the caller's body refuses the delay parameter",
         "[homeserver][delayed-events][routes][invalid-param]")
{
    GIVEN("alice in a room, with delayed events on or off")
    {
        auto fixture = Fixture{};
        fixture.runtime().limits.delayed_events_enabled = GENERATE(true, false);
        auto const before = fixture.event_count();

        WHEN("POST .../send and PUT .../redact/... carry the parameter")
        {
            auto const sent =
                request(fixture.runtime(), "POST", fixture.room_path() + "/send?" + std::string{delay_param} + "=5000",
                        fixture.alice_token, R"({"type":"m.test.delayed","content":{"body":"now"}})");
            auto const redact =
                request(fixture.runtime(), "PUT",
                        fixture.room_path() + "/redact/$somewhere/t1?" + std::string{delay_param} + "=5000",
                        fixture.alice_token, "{}");

            THEN("each is 400 M_INVALID_PARAM and nothing is sent")
            {
                CHECK(sent.status == 400U);
                CHECK(errcode_of(sent) == "M_INVALID_PARAM");
                CHECK(redact.status == 400U);
                CHECK(errcode_of(redact) == "M_INVALID_PARAM");
                CHECK(fixture.event_count() == before);
                CHECK_FALSE(timeline_has(fixture, "m.test.delayed"));
            }
        }
    }
}

SCENARIO("The delayed branch comes before the ordinary route's idempotency lookup, and the two namespaces are separate",
         "[homeserver][delayed-events][routes][idempotency]")
{
    GIVEN("alice in a room")
    {
        auto fixture = Fixture{};

        WHEN("an ordinary send is made, then the same path and transaction ID with the delay parameter")
        {
            auto const ordinary = request(fixture.runtime(), "PUT", fixture.room_path() + "/send/m.test.delayed/tx1",
                                          fixture.alice_token, std::string{message_content});
            REQUIRE(ordinary.status == 200U);
            REQUIRE(string_member(parse_object(ordinary.body), "event_id") != nullptr);
            auto const before = fixture.event_count();
            auto const delayed = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "tx1",
                                                  std::string{delay_param} + "=5000");

            THEN("the answer is a delay_id, not the cached event_id, and nothing new is in the timeline")
            {
                REQUIRE(delayed.status == 200U);
                auto const body = parse_object(delayed.body);
                CHECK(string_member(body, "delay_id") != nullptr);
                CHECK(string_member(body, "event_id") == nullptr);
                CHECK(fixture.event_count() == before);
            }
        }

        WHEN("an event is scheduled with a transaction ID, then sent ordinarily with the same one")
        {
            auto const delayed = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "tx2",
                                                  std::string{delay_param} + "=5000");
            REQUIRE(delayed.status == 200U);
            auto const before = fixture.event_count();
            auto const ordinary = request(fixture.runtime(), "PUT", fixture.room_path() + "/send/m.test.delayed/tx2",
                                          fixture.alice_token, std::string{message_content});

            THEN("the ordinary send sends an ordinary event")
            {
                REQUIRE(ordinary.status == 200U);
                CHECK(string_member(parse_object(ordinary.body), "event_id") != nullptr);
                CHECK(fixture.event_count() == before + 1U);
            }
        }
    }
}

SCENARIO(
    "The send action under the user's per-user limit for the send route is 429 with Retry-After and stays scheduled",
    "[homeserver][delayed-events][routes][rate-limit]")
{
    GIVEN("a per-user policy of one send a minute for the send route and two scheduled events")
    {
        // The engine reads the steady clock itself (no test seam): the two sends below rely on completing within the
        // policy's 60-second window.
        auto limits = merovingian::config::ClientRateLimitsConfig{};
        limits.per_user["/_matrix/client/v3/rooms/{roomId}/send/"] = merovingian::http::RateLimitPolicy{1U, 60U};
        auto fixture = Fixture{memory_config(std::move(limits))};
        auto const first = schedule_message(fixture, "a");
        auto const second = schedule_message(fixture, "b");

        WHEN("the first is sent now and then the second")
        {
            auto const sent = post_action(fixture, true, first, "send", fixture.alice_token);
            auto const limited = post_action(fixture, true, second, "send", fixture.alice_token);

            THEN("the second is 429 M_LIMIT_EXCEEDED with retry_after_ms and Retry-After, and is still scheduled")
            {
                CHECK(sent.status == 200U);
                CHECK(limited.status == 429U);
                CHECK(errcode_of(limited) == "M_LIMIT_EXCEEDED");
                auto const limited_body = parse_object(limited.body);
                CHECK(int_member(limited_body, "retry_after_ms") != nullptr);
                CHECK_FALSE(header_of(limited, "Retry-After").empty());
                CHECK(status_of(fixture, alice, second) == db::DelayedEventStatus::scheduled);
            }
        }
    }
}

SCENARIO("Scheduling wakes the job once per scheduled event, and a refusal or a restart does not",
         "[homeserver][delayed-events][routes][wake]")
{
    GIVEN("a runtime whose wake hook counts")
    {
        auto fixture = Fixture{};
        auto wakes = 0;
        fixture.runtime().homeserver.delayed_events_wake = [&wakes]() {
            ++wakes;
        };

        WHEN("an event is scheduled, a schedule is refused, and the event is restarted")
        {
            auto const scheduled =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "w1", schedule_body(5'000U));
            auto const after_schedule = wakes;
            auto const refused =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "w2", schedule_body(0U));
            auto const after_refusal = wakes;
            auto const restart = post_action(fixture, true, delay_id_of(scheduled), "restart", fixture.alice_token);

            THEN("one wake for the schedule, none for the refusal and none for the restart")
            {
                CHECK(after_schedule == 1);
                CHECK(refused.status == 400U);
                CHECK(after_refusal == 1);
                CHECK(restart.status == 200U);
                CHECK(wakes == 1);
            }
        }
        fixture.runtime().homeserver.delayed_events_wake = nullptr;
    }
}

SCENARIO("Ending the scheduling device leaves the delayed event scheduled, and another device manages it",
         "[homeserver][delayed-events][routes][device]")
{
    GIVEN("two events scheduled by device D1 of alice, and a second device D3")
    {
        auto fixture = Fixture{};
        auto const restarted = schedule_message(fixture, "a", 60'000U);
        auto const cancelled = schedule_message(fixture, "b", 60'000U);
        auto const other_token = log_in(fixture.runtime(), "alice", "D3");
        auto const delete_device = GENERATE(false, true);
        auto const before = fixture.event_count();

        WHEN("D1 is logged out or deleted")
        {
            if (delete_device)
            {
                REQUIRE(request(fixture.runtime(), "DELETE", "/_matrix/client/v3/devices/D1", other_token,
                                R"({"auth":{"type":"m.login.password","password":")" + std::string{password} + R"("}})")
                            .status == 200U);
            }
            else
            {
                REQUIRE(
                    request(fixture.runtime(), "POST", "/_matrix/client/v3/logout", fixture.alice_token, "{}").status ==
                    200U);
            }
            fixture.set_time(t0 + 10'000U);
            auto const restart = post_action(fixture, true, restarted, "restart", other_token);
            auto const cancel = post_action(fixture, true, cancelled, "cancel", other_token);

            THEN("both rows were still scheduled, D3 restarts one and cancels the other, and the restarted one is sent "
                 "when due")
            {
                CHECK(restart.status == 200U);
                CHECK(cancel.status == 200U);
                CHECK(status_of(fixture, alice, cancelled) == db::DelayedEventStatus::cancelled);
                fixture.run_job(t0 + 69'999U);
                CHECK(status_of(fixture, alice, restarted) == db::DelayedEventStatus::scheduled);
                fixture.set_time(t0 + 70'000U);
                fixture.run_job(t0 + 70'000U);
                CHECK(status_of(fixture, alice, restarted) == db::DelayedEventStatus::sent);
                CHECK(fixture.event_count() == before + 1U);
            }
        }
    }
}

SCENARIO(
    "Content of exactly 65,536 bytes is accepted and 65,537 is refused 413 on the dedicated route and the query form",
    "[homeserver][delayed-events][routes][size]")
{
    GIVEN("alice in a room and content objects of 65,536 and 65,537 serialised bytes")
    {
        auto fixture = Fixture{};
        auto const exact = R"({"a":")" + std::string(65'528U, 'x') + R"("})";
        auto const over = R"({"a":")" + std::string(65'529U, 'x') + R"("})";
        REQUIRE(exact.size() == 65'536U);
        REQUIRE(over.size() == 65'537U);

        WHEN("each is scheduled on the dedicated route and on the query form")
        {
            auto const dedicated_ok =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "s1", schedule_body(5'000U, exact));
            auto const dedicated_over =
                put_dedicated(fixture, true, fixture.alice_token, "m.test.delayed", "s2", schedule_body(5'000U, over));
            auto const query_ok = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "q1",
                                                   std::string{delay_param} + "=5000", exact);
            auto const query_over = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "q2",
                                                     std::string{delay_param} + "=5000", over);

            THEN("65,536 is scheduled and 65,537 is 413 M_TOO_LARGE, on both")
            {
                CHECK(delay_id_of(dedicated_ok).size() > 0U);
                CHECK(delay_id_of(query_ok).size() > 0U);
                CHECK(dedicated_over.status == 413U);
                CHECK(errcode_of(dedicated_over) == "M_TOO_LARGE");
                CHECK(query_over.status == 413U);
                CHECK(errcode_of(query_over) == "M_TOO_LARGE");
                CHECK(fixture.table().scheduled_count(alice) == 2U);
            }
        }
    }
}

SCENARIO("An application service scheduling for a user is recorded as such, and a user's own request is not",
         "[homeserver][delayed-events][routes][appservice]")
{
    GIVEN("an application service whose namespace holds alice")
    {
        auto bridge = TestAppservice{.id = "bridge", .users_regex = "@.*:example.org"};
        auto fixture = Fixture{appservice_test_config({bridge})};
        auto const token = bridge.as_token();
        auto const as_alice = std::string{"user_id=@alice:example.org"};

        WHEN("it schedules as alice, and alice schedules directly")
        {
            auto const by_service = request(fixture.runtime(), "PUT",
                                            "/_matrix/client/unstable/org.matrix.msc4140/rooms/" + fixture.room_id +
                                                "/delayed_event/m.test.delayed/as1?" + as_alice,
                                            token, schedule_body(5'000U));
            auto const by_user =
                put_dedicated(fixture, false, fixture.alice_token, "m.test.delayed", "u1", schedule_body(5'000U));

            THEN("the stored row of the first has via_appservice and the second does not")
            {
                auto const* service_row = fixture.table().find_owned(alice, delay_id_of(by_service));
                auto const* user_row = fixture.table().find_owned(alice, delay_id_of(by_user));
                REQUIRE(service_row != nullptr);
                REQUIRE(user_row != nullptr);
                CHECK(service_row->via_appservice);
                CHECK_FALSE(user_row->via_appservice);
            }
        }

        WHEN("the ts parameter is sent with the delay parameter, by the service and by alice")
        {
            auto const by_service = request(fixture.runtime(), "PUT",
                                            fixture.room_path() + "/send/m.test.delayed/ts1?" + as_alice + "&ts=1&" +
                                                std::string{delay_param} + "=5000",
                                            token, std::string{message_content});
            auto const by_user = put_send_delayed(fixture, fixture.alice_token, "m.test.delayed", "ts2",
                                                  "ts=1&" + std::string{delay_param} + "=5000");
            auto const service_id = delay_id_of(by_service);
            auto const user_id = delay_id_of(by_user);
            fixture.set_time(t0 + 5'000U);
            fixture.run_job(t0 + 5'000U);

            THEN("both are scheduled, ts is ignored, and each event's origin_server_ts is the send time")
            {
                for (auto const& id : {service_id, user_id})
                {
                    auto const* row = fixture.table().find_owned(alice, id);
                    REQUIRE(row != nullptr);
                    REQUIRE(row->status == db::DelayedEventStatus::sent);
                    auto const event = request(fixture.runtime(), "GET",
                                               fixture.room_path() + "/event/" + row->event_id, fixture.alice_token);
                    REQUIRE(event.status == 200U);
                    auto const event_body = parse_object(event.body);
                    auto const* stamp = int_member(event_body, "origin_server_ts");
                    REQUIRE(stamp != nullptr);
                    CHECK(*stamp == static_cast<std::int64_t>(t0 + 5'000U));
                }
            }
        }
    }
}

SCENARIO("A failed store write on restart is answered 500 M_UNKNOWN and leaves the event scheduled with its timer",
         "[homeserver][delayed-events][routes]")
{
    GIVEN("an event scheduled at t0 and an update of its timer that fails once")
    {
        auto fixture = Fixture{};
        auto const id = schedule_message(fixture, "r1", 60'000U);
        fixture.runtime().homeserver.database.persistent_store.force_failure_statement_names.insert(
            "restart_delayed_event");

        WHEN("alice posts the restart halfway through the delay, and then reads the event")
        {
            fixture.set_time(t0 + 30'000U);
            auto const restart = post_action(fixture, true, id, "restart", fixture.alice_token);
            auto const shown = get_delayed(fixture, true, id, fixture.alice_token);

            THEN("the restart is HTTP 500 M_UNKNOWN and the event is still scheduled since t0")
            {
                CHECK(restart.status == 500U);
                CHECK(errcode_of(restart) == "M_UNKNOWN");
                REQUIRE(shown.status == 200U);
                CHECK(*int_member(parse_object(shown.body), "delayed_since_ts") == static_cast<std::int64_t>(t0));
                CHECK(status_of(fixture, alice, id) == db::DelayedEventStatus::scheduled);
            }
        }
        fixture.runtime().homeserver.database.persistent_store.force_failure_statement_names.clear();
    }
}
