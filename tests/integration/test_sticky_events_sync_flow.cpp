// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Sticky events (MSC4354, MSC4480) in `/sync` and sliding sync (ADR-0855), end to end: a real runtime and store, events
// sent through the API and then recorded as sticky with `database::record_sticky_event` (the send path that records
// them itself is tested with it). Time is `PersistentStore::test_sticky_clock_ms`; no scenario sleeps. The feature is
// not in the Matrix v1.19 specification, so there is no conformance scenario.

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
#include "merovingian/database/PersistentStickyEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/StickyEventStore.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/DispatchResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
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

constexpr auto t0 = std::int64_t{1'700'000'000'000};
constexpr auto one_hour_ms = std::int64_t{3'600'000};
constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto sliding_path = std::string_view{"/_matrix/client/unstable/org.matrix.msc4186/sync"};
// A timeline that holds nothing, so a sticky event shows only in the sticky section.
constexpr auto no_timeline_filter = std::string_view{R"({"room":{"timeline":{"limit":0}}})"};

[[nodiscard]] auto config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// The ids of the `event_id` members of the array at `path` below `root`; empty when the path is absent.
[[nodiscard]] auto ids_at(cj::Object const& root, std::vector<std::string_view> const& path) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    auto const* current = &root;
    for (auto it = path.begin(); it != path.end(); ++it)
    {
        if (std::next(it) == path.end())
        {
            auto const* array = object_member_as_array(*current, *it);
            if (array == nullptr)
            {
                return ids;
            }
            for (auto const& value : *array)
            {
                auto const* event = std::get_if<cj::Object>(&value.storage());
                auto const* id = event != nullptr ? string_member(*event, "event_id") : nullptr;
                ids.push_back(id != nullptr ? *id : std::string{"?"});
            }
            return ids;
        }
        current = object_member_as_object(*current, *it);
        if (current == nullptr)
        {
            return ids;
        }
    }
    return ids;
}

// A running homeserver with alice, who made a public room, and bob, who has not joined it.
class Fixture final
{
public:
    Fixture()
        : m_started{hs::start_client_server(config())}
    {
        REQUIRE(m_started.started);
        m_alice_token = sign_in("alice", "D1");
        m_bob_token = sign_in("bob", "D2");
        auto const created =
            send("POST", "/_matrix/client/v3/createRoom", m_alice_token, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        m_room_id = *string_member(parse_object(created.body), "room_id");
        m_started.runtime.homeserver.database.persistent_store.test_sticky_clock_ms = t0;
    }

    [[nodiscard]] auto runtime() noexcept -> hs::ClientServerRuntime&
    {
        return m_started.runtime;
    }

    [[nodiscard]] auto send(std::string method, std::string target, std::string const& token, std::string body = {})
        -> hs::LocalHttpResponse
    {
        return hs::handle_client_server_request(runtime(),
                                                {std::move(method), std::move(target), token, std::move(body)})
            .response;
    }

    // Alice sets the room's history visibility.
    auto set_history_visibility(std::string_view visibility) -> void
    {
        REQUIRE(send("PUT", "/_matrix/client/v3/rooms/" + m_room_id + "/state/m.room.history_visibility", m_alice_token,
                     R"({"history_visibility":")" + std::string{visibility} + R"("})")
                    .status == 200U);
    }

    auto bob_joins() -> void
    {
        REQUIRE(send("POST", "/_matrix/client/v3/join/" + m_room_id, m_bob_token, "{}").status == 200U);
    }

    // Alice sends a message and records it as sticky until `expires_at_ms`; its event ID.
    [[nodiscard]] auto sticky_message(std::string const& text, std::int64_t expires_at_ms = t0 + one_hour_ms)
        -> std::string
    {
        auto const event_id = plain_message(text);
        auto& store = runtime().homeserver.database.persistent_store;
        REQUIRE(db::record_sticky_event(store, {event_id, m_room_id, std::string{alice}, t0, expires_at_ms}, {200U}, t0)
                    .recorded);
        return event_id;
    }

    // Alice sends a message that is not sticky; its event ID.
    [[nodiscard]] auto plain_message(std::string const& text) -> std::string
    {
        auto const sent = send("PUT", "/_matrix/client/v3/rooms/" + m_room_id + "/send/m.room.message/" + text + "-txn",
                               m_alice_token, R"({"msgtype":"m.text","body":")" + text + R"("})");
        REQUIRE(sent.status == 200U);
        return *string_member(parse_object(sent.body), "event_id");
    }

    [[nodiscard]] auto sync(std::string const& token, std::string const& query = {}) -> cj::Object
    {
        auto const response = send("GET", "/_matrix/client/v3/sync" + query, token);
        REQUIRE(response.status == 200U);
        return parse_object_json(response.body);
    }

    // A `/sync` of `token` with `filter`, and `since` when given.
    [[nodiscard]] auto filtered_sync(std::string const& token, std::string_view filter, std::string const& since = {})
        -> cj::Object
    {
        return sync(token, "?filter=" + std::string{filter} + (since.empty() ? std::string{} : "&since=" + since));
    }

    // A sliding sync that asks for the extension under `extension_json`, from `pos` when given.
    [[nodiscard]] auto sliding(std::string const& token, std::string const& body, std::string const& pos = {},
                               bool can_wait = false, std::string const& timeout = {}) -> hs::DispatchResult
    {
        auto target = std::string{sliding_path};
        auto separator = '?';
        if (!pos.empty())
        {
            target += separator + std::string{"pos="} + pos;
            separator = '&';
        }
        if (!timeout.empty())
        {
            target += separator + std::string{"timeout="} + timeout;
        }
        return hs::handle_client_server_request(runtime(), {"POST", std::move(target), token, body}, can_wait);
    }

    [[nodiscard]] auto alice_token() const noexcept -> std::string const&
    {
        return m_alice_token;
    }

    [[nodiscard]] auto bob_token() const noexcept -> std::string const&
    {
        return m_bob_token;
    }

    [[nodiscard]] auto room_id() const noexcept -> std::string const&
    {
        return m_room_id;
    }

private:
    std::string m_alice_token{};
    std::string m_bob_token{};
    std::string m_room_id{};

    [[nodiscard]] auto sign_in(std::string const& name, std::string const& device) -> std::string
    {
        REQUIRE(send("POST", "/_matrix/client/v3/register", {}, registration_json(name, password)).status == 200U);
        auto const login = send("POST", "/_matrix/client/v3/login", {},
                                R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                                    R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" +
                                    device + R"("})");
        REQUIRE(login.status == 200U);
        return *string_member(parse_object(login.body), "access_token");
    }

    hs::ClientServerStartResult m_started;
};

[[nodiscard]] auto sticky_of(Fixture const& fixture, cj::Object const& body, std::string_view key = "sticky")
    -> std::vector<std::string>
{
    return ids_at(body, {"rooms", "join", fixture.room_id(), key, "events"});
}

} // namespace

SCENARIO("a joined room's sticky section holds the sticky events its timeline does not", "[sticky-events][integration]")
{
    GIVEN("alice's room with three sticky messages and bob joined before them")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto const m1 = fixture.sticky_message("one");
        auto const m2 = fixture.sticky_message("two");
        auto const m3 = fixture.sticky_message("three");

        WHEN("bob's initial sync has no timeline")
        {
            auto const body = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);
            THEN("every sticky event is in the section, oldest first, and both names carry the same array")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{m1, m2, m3});
                REQUIRE(sticky_of(fixture, body, "msc4354_sticky") == sticky_of(fixture, body));
            }
        }

        WHEN("bob's initial sync keeps only the newest event in the timeline")
        {
            auto const body = fixture.filtered_sync(fixture.bob_token(), R"({"room":{"timeline":{"limit":1}}})");
            THEN("the newest is in the timeline only and the older ones are in the section")
            {
                REQUIRE(ids_at(body, {"rooms", "join", fixture.room_id(), "timeline", "events"}) ==
                        std::vector<std::string>{m3});
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{m1, m2});
            }
        }

        WHEN("bob's timeline filter refuses messages")
        {
            auto const body =
                fixture.filtered_sync(fixture.bob_token(), R"({"room":{"timeline":{"not_types":["m.room.message"]}}})");
            THEN("the messages are in the section")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{m1, m2, m3});
            }
        }

        WHEN("bob's timeline holds all three")
        {
            auto const body = fixture.sync(fixture.bob_token());
            THEN("there is no section")
            {
                REQUIRE(
                    object_member_as_object(*object_member_as_object(*object_member_as_object(body, "rooms"), "join"),
                                            fixture.room_id()) != nullptr);
                REQUIRE(sticky_of(fixture, body).empty());
                REQUIRE(sticky_of(fixture, body, "msc4354_sticky").empty());
            }
        }
    }
}

SCENARIO("a room's sticky section holds every unexpired sticky event, past 100", "[sticky-events][integration]")
{
    GIVEN("alice's room with 101 sticky messages and bob joined before them")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto sent = std::vector<std::string>{};
        for (auto index = 0; index < 101; ++index)
        {
            sent.push_back(fixture.sticky_message("cap-" + std::to_string(index)));
        }

        WHEN("bob's initial sync has no timeline")
        {
            auto const body = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);

            THEN("the section holds all 101, oldest first, under both names")
            {
                // MSC4354: every unexpired sticky event is delivered; classic /sync has no cursor for more (ADR-0858).
                REQUIRE(sticky_of(fixture, body) == sent);
                REQUIRE(sticky_of(fixture, body, "msc4354_sticky") == sent);
            }
        }
    }
}

SCENARIO("an incremental sync carries only the sticky events after its position", "[sticky-events][integration]")
{
    GIVEN("bob has synced a room holding one sticky message, and alice sends another")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto const first = fixture.sticky_message("one");
        auto const initial = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);
        REQUIRE(sticky_of(fixture, initial) == std::vector<std::string>{first});
        auto const second = fixture.sticky_message("two");

        WHEN("bob syncs from his token with an empty timeline")
        {
            auto const body =
                fixture.filtered_sync(fixture.bob_token(), no_timeline_filter, *string_member(initial, "next_batch"));
            THEN("only the new event is in the section, and the room is not dropped as empty")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{second});
            }
        }

        WHEN("bob syncs from his token with full_state")
        {
            auto const body =
                fixture.sync(fixture.bob_token(), "?full_state=true&filter=" + std::string{no_timeline_filter} +
                                                      "&since=" + *string_member(initial, "next_batch"));
            THEN("every unexpired sticky event is in the section")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{first, second});
            }
        }
    }
}

SCENARIO("a user who joins after the position gets every unexpired sticky event", "[sticky-events][integration]")
{
    GIVEN("bob synced before he joined a room that already holds sticky events")
    {
        auto fixture = Fixture{};
        auto const m1 = fixture.sticky_message("one");
        auto const m2 = fixture.sticky_message("two");
        auto const before = fixture.sync(fixture.bob_token());
        fixture.bob_joins();

        WHEN("bob syncs again from his token")
        {
            auto const body =
                fixture.filtered_sync(fixture.bob_token(), no_timeline_filter, *string_member(before, "next_batch"));
            THEN("both events are in the section although they are older than his token")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{m1, m2});
            }
        }
    }
}

SCENARIO("an ignored sender's and an expired sticky event are left out", "[sticky-events][integration]")
{
    GIVEN("bob joined a room with one sticky message from alice that expires in a minute")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto const message = fixture.sticky_message("one", t0 + 60'000);
        REQUIRE(sticky_of(fixture, fixture.filtered_sync(fixture.bob_token(), no_timeline_filter)) ==
                std::vector<std::string>{message});

        WHEN("the clock passes its expiry")
        {
            fixture.runtime().homeserver.database.persistent_store.test_sticky_clock_ms = t0 + 61'000;
            auto const body = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);
            THEN("the section is absent")
            {
                REQUIRE(sticky_of(fixture, body).empty());
                REQUIRE(sticky_of(fixture, body, "msc4354_sticky").empty());
            }
        }

        WHEN("bob ignores alice")
        {
            REQUIRE(fixture
                        .send("PUT", "/_matrix/client/v3/user/@bob:example.org/account_data/m.ignored_user_list",
                              fixture.bob_token(), R"({"ignored_users":{"@alice:example.org":{}}})")
                        .status == 200U);
            auto const body = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);
            THEN("the section is absent")
            {
                REQUIRE(sticky_of(fixture, body).empty());
            }
        }
    }
}

SCENARIO("a room whose only news is a sticky event is not dropped", "[sticky-events][integration]")
{
    GIVEN("bob synced a room and a sticky message the timeline filter hides arrives")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto const filter = std::string{R"({"room":{"timeline":{"not_types":["m.room.message"]}}})"};
        auto const initial = fixture.filtered_sync(fixture.bob_token(), filter);
        auto const quiet = fixture.filtered_sync(fixture.bob_token(), filter, *string_member(initial, "next_batch"));
        REQUIRE(object_member_as_object(*object_member_as_object(quiet, "rooms"), "join")->empty());
        auto const message = fixture.sticky_message("one");

        WHEN("bob syncs from his token")
        {
            auto const body = fixture.filtered_sync(fixture.bob_token(), filter, *string_member(quiet, "next_batch"));
            THEN("the room is in the response with the event in its section")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{message});
            }
        }
    }
}

SCENARIO("a lazy-loading /sync carries the member event of a sticky sender who joined after the timeline's start",
         "[sticky-events][integration][lazy]")
{
    // MSC4480: a sticky event's sender is a timeline sender for lazy-loaded members. The member is the one in force
    // when the client can place it: at the timeline's start when that state holds it, else as of the response
    // (ADR-0862).
    GIVEN("alice synced, then sent a sticky message, then bob joined and sent one")
    {
        auto fixture = Fixture{};
        auto const before = fixture.sync(fixture.alice_token());
        auto const plain =
            fixture.send("PUT", "/_matrix/client/v3/rooms/" + fixture.room_id() + "/send/m.test.plain/p1",
                         fixture.alice_token(), R"({"body":"before bob"})");
        REQUIRE(plain.status == 200U);
        auto const alices = fixture.sticky_message("one");
        fixture.bob_joins();
        auto& store = fixture.runtime().homeserver.database.persistent_store;
        auto const bobs_sent =
            fixture.send("PUT", "/_matrix/client/v3/rooms/" + fixture.room_id() + "/send/m.room.message/b1",
                         fixture.bob_token(), R"({"msgtype":"m.text","body":"two"})");
        REQUIRE(bobs_sent.status == 200U);
        auto const bobs = *string_member(parse_object(bobs_sent.body), "event_id");
        REQUIRE(db::record_sticky_event(store, {bobs, fixture.room_id(), "@bob:example.org", t0, t0 + one_hour_ms},
                                        {200U}, t0)
                    .recorded);
        auto const bob_join = db::find_current_state_event_id(store, fixture.room_id(), "m.room.member",
                                                              "@bob:example.org");
        REQUIRE(bob_join.has_value());
        auto const bob_join_id = bob_join.value_or(std::string{});
        auto const since = *string_member(before, "next_batch");

        WHEN("alice syncs from her token with lazy members and a timeline filter that matches nothing")
        {
            auto const body = fixture.filtered_sync(
                fixture.alice_token(),
                R"({"room":{"state":{"lazy_load_members":true},"timeline":{"types":["m.nothing"]}}})", since);
            THEN("both sticky events are sent, and bob's join is in the state")
            {
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{alices, bobs});
                auto const state = ids_at(body, {"rooms", "join", fixture.room_id(), "state", "events"});
                REQUIRE(std::ranges::find(state, bob_join_id) != state.end());
            }
        }

        WHEN("alice syncs with lazy members and a timeline of only the message sent before bob joined")
        {
            auto const body = fixture.filtered_sync(
                fixture.alice_token(),
                R"({"room":{"state":{"lazy_load_members":true},"timeline":{"types":["m.test.plain"]}}})", since);
            THEN("the timeline starts before bob joined, and bob's join is still in the state")
            {
                auto const timeline = ids_at(body, {"rooms", "join", fixture.room_id(), "timeline", "events"});
                REQUIRE(timeline.size() == 1U);
                REQUIRE(sticky_of(fixture, body) == std::vector<std::string>{alices, bobs});
                auto const state = ids_at(body, {"rooms", "join", fixture.room_id(), "state", "events"});
                REQUIRE(std::ranges::find(state, bob_join_id) != state.end());
            }
        }
    }
}

SCENARIO("with sticky events disabled /sync has no section", "[sticky-events][integration]")
{
    GIVEN("a room with a sticky message and the feature off")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        std::ignore = fixture.sticky_message("one");
        fixture.runtime().limits.sticky_events_enabled = false;

        WHEN("bob syncs with no timeline")
        {
            auto const body = fixture.filtered_sync(fixture.bob_token(), no_timeline_filter);
            THEN("neither key is present")
            {
                auto const* room = object_member_as_object(
                    *object_member_as_object(*object_member_as_object(body, "rooms"), "join"), fixture.room_id());
                REQUIRE(room != nullptr);
                REQUIRE(object_member(*room, "sticky") == nullptr);
                REQUIRE(object_member(*room, "msc4354_sticky") == nullptr);
            }
        }
    }
}

namespace
{

[[nodiscard]] auto list_request(std::string_view extension_json, std::string_view conn = "c1",
                                std::string_view timeline_limit = "0") -> std::string
{
    return R"({"conn_id":")" + std::string{conn} + R"(","lists":{"all":{"ranges":[[0,10]],"timeline_limit":)" +
           std::string{timeline_limit} + R"(,"required_state":[]}},"extensions":{)" + std::string{extension_json} +
           "}}";
}

[[nodiscard]] auto parsed(hs::DispatchResult const& result) -> cj::Object
{
    REQUIRE(result.status == hs::DispatchResult::Status::complete);
    REQUIRE(result.response.status == 200U);
    return parse_object_json(result.response.body);
}

[[nodiscard]] auto sliding_ids(Fixture const& fixture, cj::Object const& body, std::string_view name = "sticky_events")
    -> std::vector<std::string>
{
    return ids_at(body, {"extensions", name, "rooms", fixture.room_id(), "events"});
}

constexpr auto stable_extension = std::string_view{R"("sticky_events":{"enabled":true})"};

// The `unsigned` member `key` of the event `event_id` in the array at `path` below `root`; null when absent.
[[nodiscard]] auto unsigned_int_at(cj::Object const& root, std::vector<std::string_view> const& path,
                                   std::string_view event_id, std::string_view key) -> std::int64_t const*
{
    auto const* current = &root;
    for (auto it = path.begin(); std::next(it) != path.end(); ++it)
    {
        current = object_member_as_object(*current, *it);
        if (current == nullptr)
        {
            return nullptr;
        }
    }
    auto const* array = object_member_as_array(*current, path.back());
    if (array == nullptr)
    {
        return nullptr;
    }
    for (auto const& value : *array)
    {
        auto const* event = std::get_if<cj::Object>(&value.storage());
        auto const* id = event != nullptr ? string_member(*event, "event_id") : nullptr;
        if (id != nullptr && *id == event_id)
        {
            auto const* unsigned_object = object_member_as_object(*event, "unsigned");
            return unsigned_object != nullptr ? int_member(*unsigned_object, key) : nullptr;
        }
    }
    return nullptr;
}

} // namespace

SCENARIO("a sticky event in a timeline carries its remaining time under both names", "[sticky-events][integration]")
{
    GIVEN("alice's room with a sticky message, a minute after it was received")
    {
        auto fixture = Fixture{};
        auto const message = fixture.sticky_message("one");
        fixture.runtime().homeserver.database.persistent_store.test_sticky_clock_ms = t0 + 60'000;
        auto const expected = one_hour_ms - 60'000;

        WHEN("alice's /sync timeline holds it")
        {
            auto const body = fixture.sync(fixture.alice_token());
            auto const path = std::vector<std::string_view>{"rooms", "join", fixture.room_id(), "timeline", "events"};
            THEN("the event carries the remaining time")
            {
                auto const* stable = unsigned_int_at(body, path, message, "sticky_duration_remaining_ms");
                auto const* unstable = unsigned_int_at(body, path, message, "msc4354_sticky_duration_ttl_ms");
                REQUIRE(stable != nullptr);
                REQUIRE(*stable == expected);
                REQUIRE(unstable != nullptr);
                REQUIRE(*unstable == expected);
            }
        }

        WHEN("alice's sliding sync timeline holds it")
        {
            auto const body = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension, "c1", "1")));
            auto const path = std::vector<std::string_view>{"rooms", fixture.room_id(), "timeline"};
            THEN("the event carries the remaining time and the extension does not repeat it")
            {
                auto const* stable = unsigned_int_at(body, path, message, "sticky_duration_remaining_ms");
                auto const* unstable = unsigned_int_at(body, path, message, "msc4354_sticky_duration_ttl_ms");
                REQUIRE(stable != nullptr);
                REQUIRE(*stable == expected);
                REQUIRE(unstable != nullptr);
                REQUIRE(*unstable == expected);
                REQUIRE(sliding_ids(fixture, body).empty());
            }
        }

        WHEN("the sticky event has expired")
        {
            fixture.runtime().homeserver.database.persistent_store.test_sticky_clock_ms = t0 + one_hour_ms;
            auto const body = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension, "c1", "1")));
            THEN("the timeline event carries no remaining time")
            {
                auto const path = std::vector<std::string_view>{"rooms", fixture.room_id(), "timeline"};
                REQUIRE(unsigned_int_at(body, path, message, "sticky_duration_remaining_ms") == nullptr);
                REQUIRE(unsigned_int_at(body, path, message, "msc4354_sticky_duration_ttl_ms") == nullptr);
            }
        }
    }
}

SCENARIO("the sliding sync sticky_events extension answers under the names the request used",
         "[sticky-events][integration]")
{
    GIVEN("alice's room with a sticky message")
    {
        auto fixture = Fixture{};
        auto const message = fixture.sticky_message("one");

        WHEN("the request uses the stable name")
        {
            auto const body = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension)));
            THEN("only the stable name answers")
            {
                REQUIRE(sliding_ids(fixture, body) == std::vector<std::string>{message});
                REQUIRE(sliding_ids(fixture, body, "org.matrix.msc4354.sticky_events").empty());
            }
        }

        WHEN("the request uses the unstable name")
        {
            auto const body = parsed(fixture.sliding(
                fixture.alice_token(), list_request(R"("org.matrix.msc4354.sticky_events":{"enabled":true})")));
            THEN("only the unstable name answers")
            {
                REQUIRE(sliding_ids(fixture, body, "org.matrix.msc4354.sticky_events") ==
                        std::vector<std::string>{message});
                REQUIRE(sliding_ids(fixture, body).empty());
            }
        }

        WHEN("the request uses both names")
        {
            auto const body = parsed(fixture.sliding(
                fixture.alice_token(),
                list_request(
                    R"("sticky_events":{"enabled":true},"org.matrix.msc4354.sticky_events":{"enabled":true})")));
            THEN("both names carry the same events")
            {
                REQUIRE(sliding_ids(fixture, body) == std::vector<std::string>{message});
                REQUIRE(sliding_ids(fixture, body, "org.matrix.msc4354.sticky_events") ==
                        std::vector<std::string>{message});
            }
        }

        WHEN("the request enables nothing")
        {
            auto const body =
                parsed(fixture.sliding(fixture.alice_token(), list_request(R"("sticky_events":{"enabled":false})")));
            THEN("there is no answer")
            {
                REQUIRE(sliding_ids(fixture, body).empty());
            }
        }

        WHEN("the limit is zero")
        {
            auto const result =
                fixture.sliding(fixture.alice_token(), list_request(R"("sticky_events":{"enabled":true,"limit":0})"));
            THEN("the request is refused")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(*string_member(parse_object(result.response.body), "errcode") == "M_INVALID_PARAM");
            }
        }

        WHEN("the limit is above the maximum")
        {
            auto const result = fixture.sliding(fixture.alice_token(),
                                                list_request(R"("sticky_events":{"enabled":true,"limit":5000})"));
            THEN("it is accepted")
            {
                REQUIRE(result.response.status == 200U);
            }
        }

        WHEN("the feature is off")
        {
            fixture.runtime().limits.sticky_events_enabled = false;
            auto const body = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension)));
            THEN("the extension is accepted and answers nothing")
            {
                REQUIRE(sliding_ids(fixture, body).empty());
            }
        }
    }
}

SCENARIO("sliding sync sends a backlog over several responses and answers a poll at once for it",
         "[sticky-events][integration]")
{
    GIVEN("alice's room with three sticky messages and a limit of two")
    {
        auto fixture = Fixture{};
        auto const m1 = fixture.sticky_message("one");
        auto const m2 = fixture.sticky_message("two");
        auto const m3 = fixture.sticky_message("three");
        auto const request = list_request(R"("sticky_events":{"enabled":true,"limit":2})");
        auto const first = parsed(fixture.sliding(fixture.alice_token(), request));
        auto const first_pos = *string_member(first, "pos");
        REQUIRE(sliding_ids(fixture, first) == std::vector<std::string>{m1, m2});

        WHEN("the client acknowledges and asks again with a long poll")
        {
            auto const second = fixture.sliding(fixture.alice_token(), request, first_pos, /*can_wait=*/true, "30000");
            THEN("the answer is at once, with the rest")
            {
                REQUIRE(sliding_ids(fixture, parsed(second)) == std::vector<std::string>{m3});
            }
        }

        WHEN("the rest has been delivered")
        {
            auto const second = parsed(fixture.sliding(fixture.alice_token(), request, first_pos));
            auto const poll = fixture.sliding(fixture.alice_token(), request, *string_member(second, "pos"),
                                              /*can_wait=*/true, "30000");
            THEN("a further poll waits")
            {
                REQUIRE(poll.status == hs::DispatchResult::Status::needs_wait);
            }
        }
    }
}

SCENARIO("sliding sync pages a backlog of one event at a time while no stream advances",
         "[sticky-events][integration][pos]")
{
    // ADR-0862: a page that delivers sticky events at its request's stream position carries a pos of its own, so the
    // next request acknowledges it; without it the third event would never be sent.
    GIVEN("alice's room with three sticky messages, a limit of one and no timeline")
    {
        auto fixture = Fixture{};
        auto const m1 = fixture.sticky_message("one");
        auto const m2 = fixture.sticky_message("two");
        auto const m3 = fixture.sticky_message("three");
        auto const request = list_request(R"("sticky_events":{"enabled":true,"limit":1})");
        auto const first = parsed(fixture.sliding(fixture.alice_token(), request));
        auto const first_pos = *string_member(first, "pos");
        REQUIRE(sliding_ids(fixture, first) == std::vector<std::string>{m1});
        auto const second = parsed(fixture.sliding(fixture.alice_token(), request, first_pos));
        auto const second_pos = *string_member(second, "pos");
        REQUIRE(sliding_ids(fixture, second) == std::vector<std::string>{m2});

        WHEN("the client acknowledges the second page")
        {
            auto const third = parsed(fixture.sliding(fixture.alice_token(), request, second_pos));
            THEN("the second page had a pos of its own, and the third page carries the last event")
            {
                REQUIRE(second_pos != first_pos);
                REQUIRE(sliding_ids(fixture, third) == std::vector<std::string>{m3});
            }
        }

        WHEN("the second request is retried at the first pos, and the client then goes on from its answer")
        {
            auto const retried = parsed(fixture.sliding(fixture.alice_token(), request, first_pos));
            auto const after_retry =
                parsed(fixture.sliding(fixture.alice_token(), request, *string_member(retried, "pos")));
            THEN("the retry is answered with the same event and pos, and the next page with the last event")
            {
                REQUIRE(sliding_ids(fixture, retried) == std::vector<std::string>{m2});
                REQUIRE(*string_member(retried, "pos") == second_pos);
                REQUIRE(sliding_ids(fixture, after_retry) == std::vector<std::string>{m3});
            }
        }
    }
}

SCENARIO("a repeated sliding sync pos is answered with the same sticky events", "[sticky-events][integration]")
{
    GIVEN("a connection that enabled the extension at its second request")
    {
        auto fixture = Fixture{};
        auto const message = fixture.sticky_message("one");
        auto const none = parsed(fixture.sliding(fixture.alice_token(), list_request("")));
        // A stream that advanced, so the next response's pos differs from this request's: a request that repeats the
        // pos of the response it got, with nothing advanced, cannot be told from a retry.
        std::ignore = fixture.plain_message("filler");
        auto const pos = *string_member(none, "pos");
        auto const request = list_request(stable_extension);

        WHEN("the same request is sent twice and then the response's pos is acknowledged")
        {
            auto const one = parsed(fixture.sliding(fixture.alice_token(), request, pos));
            auto const two = parsed(fixture.sliding(fixture.alice_token(), request, pos));
            auto const three = parsed(fixture.sliding(fixture.alice_token(), request, *string_member(two, "pos")));
            THEN("both answers hold the event and the acknowledged one does not")
            {
                REQUIRE(sliding_ids(fixture, one) == std::vector<std::string>{message});
                REQUIRE(sliding_ids(fixture, two) == std::vector<std::string>{message});
                REQUIRE(sliding_ids(fixture, three).empty());
            }
        }
    }
}

SCENARIO("sliding sync sends a room that re-enters the extension's scope only what it has not had",
         "[sticky-events][integration]")
{
    GIVEN("a connection that was sent the room's first sticky message")
    {
        auto fixture = Fixture{};
        auto const m1 = fixture.sticky_message("one");
        auto const in_scope = list_request(R"("sticky_events":{"enabled":true,"lists":["all"]})");
        auto const out_of_scope = list_request(R"("sticky_events":{"enabled":true,"lists":[]})");
        auto const first = parsed(fixture.sliding(fixture.alice_token(), in_scope));
        REQUIRE(sliding_ids(fixture, first) == std::vector<std::string>{m1});
        auto const second = parsed(fixture.sliding(fixture.alice_token(), out_of_scope, *string_member(first, "pos")));
        REQUIRE(sliding_ids(fixture, second).empty());
        auto const m2 = fixture.sticky_message("two");

        WHEN("the room is in scope again")
        {
            auto const third = parsed(fixture.sliding(fixture.alice_token(), in_scope, *string_member(second, "pos")));
            THEN("only the newer event is sent")
            {
                REQUIRE(sliding_ids(fixture, third) == std::vector<std::string>{m2});
            }
        }
    }
}

SCENARIO("sliding sync does not send a sticky event its timeline carried", "[sticky-events][integration]")
{
    GIVEN("a room whose timeline in the first response holds its sticky message")
    {
        auto fixture = Fixture{};
        std::ignore = fixture.sticky_message("one");
        auto const request = list_request(std::string{stable_extension}, "c1", "20");
        auto const first = parsed(fixture.sliding(fixture.alice_token(), request));
        REQUIRE(sliding_ids(fixture, first).empty());

        WHEN("the client acknowledges the response")
        {
            auto const second = parsed(fixture.sliding(fixture.alice_token(), request, *string_member(first, "pos")));
            THEN("it is not sent by the extension either")
            {
                REQUIRE(sliding_ids(fixture, second).empty());
            }
        }
    }
}

SCENARIO("a new sliding sync connection is sent every sticky event again", "[sticky-events][integration]")
{
    GIVEN("a connection that was sent a sticky message")
    {
        auto fixture = Fixture{};
        auto const message = fixture.sticky_message("one");
        auto const first = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension, "c1")));
        REQUIRE(sliding_ids(fixture, first) == std::vector<std::string>{message});

        WHEN("another connection asks")
        {
            auto const other = parsed(fixture.sliding(fixture.alice_token(), list_request(stable_extension, "c2")));
            THEN("it is sent too")
            {
                REQUIRE(sliding_ids(fixture, other) == std::vector<std::string>{message});
            }
        }

        WHEN("the extension is left out and then asked for again")
        {
            std::ignore = fixture.plain_message("filler");
            auto const second =
                parsed(fixture.sliding(fixture.alice_token(), list_request(""), *string_member(first, "pos")));
            auto const third = parsed(
                fixture.sliding(fixture.alice_token(), list_request(stable_extension), *string_member(second, "pos")));
            THEN("the event is sent again")
            {
                REQUIRE(sliding_ids(fixture, third) == std::vector<std::string>{message});
            }
        }
    }
}

namespace
{

// A list request whose list lazy-loads members, with `extension_json` and nothing in the timeline.
[[nodiscard]] auto lazy_list_request(std::string_view extension_json) -> std::string
{
    return R"({"conn_id":"lazy","lists":{"all":{"ranges":[[0,10]],"timeline_limit":0,)"
           R"("required_state":[["m.room.member","$LAZY"]]}},"extensions":{)" +
           std::string{extension_json} + "}}";
}

// How many m.room.member events for `user` the room's required_state holds; 0 when the room is not in `rooms`.
[[nodiscard]] auto required_member_count(Fixture const& fixture, cj::Object const& body, std::string_view user)
    -> std::size_t
{
    auto const* rooms = object_member_as_object(body, "rooms");
    auto const* room = rooms != nullptr ? object_member_as_object(*rooms, fixture.room_id()) : nullptr;
    auto const* state = room != nullptr ? object_member_as_array(*room, "required_state") : nullptr;
    if (state == nullptr)
    {
        return 0U;
    }
    return static_cast<std::size_t>(std::ranges::count_if(*state, [user](cj::Value const& value) {
        auto const* event = std::get_if<cj::Object>(&value.storage());
        auto const* type = event != nullptr ? string_member(*event, "type") : nullptr;
        auto const* key = event != nullptr ? string_member(*event, "state_key") : nullptr;
        return type != nullptr && *type == "m.room.member" && key != nullptr && *key == user;
    }));
}

} // namespace

// MSC4508: `lists` and `rooms` name the lists and room subscriptions an extension applies to; absent is all, an empty
// array is none, and a room named without a subscription is not reached (ADR-0858).
SCENARIO("the sliding sync sticky_events extension follows its lists and rooms scope", "[sticky-events][integration]")
{
    GIVEN("alice's room, in her list `all`, with a sticky message")
    {
        auto fixture = Fixture{};
        auto const message = fixture.sticky_message("one");
        auto const& room = fixture.room_id();

        WHEN("the extension names the list")
        {
            auto const body = parsed(fixture.sliding(
                fixture.alice_token(), list_request(R"("sticky_events":{"enabled":true,"lists":["all"]})")));
            THEN("the event is sent")
            {
                REQUIRE(sliding_ids(fixture, body) == std::vector<std::string>{message});
            }
        }

        WHEN("the extension names no list, another list, or the room without a subscription")
        {
            auto const none = parsed(
                fixture.sliding(fixture.alice_token(), list_request(R"("sticky_events":{"enabled":true,"lists":[]})")));
            auto const other = parsed(fixture.sliding(
                fixture.alice_token(), list_request(R"("sticky_events":{"enabled":true,"lists":["other"]})", "c2")));
            auto const unsubscribed = parsed(fixture.sliding(
                fixture.alice_token(),
                list_request(R"("sticky_events":{"enabled":true,"lists":[],"rooms":[")" + room + R"("]})", "c3")));
            THEN("nothing is sent")
            {
                REQUIRE(sliding_ids(fixture, none).empty());
                REQUIRE(sliding_ids(fixture, other).empty());
                REQUIRE(sliding_ids(fixture, unsubscribed).empty());
            }
        }

        WHEN("the extension names no list but the room's subscription")
        {
            auto const request = R"({"conn_id":"sub","room_subscriptions":{")" + room +
                                 R"(":{"timeline_limit":0,"required_state":[]}},"extensions":{"sticky_events":)" +
                                 R"({"enabled":true,"lists":[],"rooms":[")" + room + R"("]}}})";
            auto const body = parsed(fixture.sliding(fixture.alice_token(), request));
            THEN("the event is sent")
            {
                REQUIRE(sliding_ids(fixture, body) == std::vector<std::string>{message});
            }
        }
    }
}

// MSC4480: the senders of the sticky events sent count as timeline senders for lazy-loaded members, so their member
// events go in required_state and the room is sent for them even with an empty timeline (ADR-0858).
SCENARIO("sliding sync lazy-loads the member events of sticky senders", "[sticky-events][integration]")
{
    GIVEN("bob joined alice's room and synced it with lazy-loaded members, then alice sent a sticky message")
    {
        auto fixture = Fixture{};
        fixture.bob_joins();
        auto const first = parsed(fixture.sliding(fixture.bob_token(), lazy_list_request("")));
        REQUIRE(required_member_count(fixture, first, alice) == 0U);
        auto const message = fixture.sticky_message("one");

        WHEN("bob asks for the extension from his position")
        {
            auto const second = parsed(fixture.sliding(fixture.bob_token(), lazy_list_request(stable_extension),
                                                       *string_member(first, "pos")));

            THEN("the event is sent and the room carries alice's member event, though its timeline is empty")
            {
                REQUIRE(sliding_ids(fixture, second) == std::vector<std::string>{message});
                REQUIRE(required_member_count(fixture, second, alice) == 1U);
            }

            AND_WHEN("alice sends another sticky message and bob asks again")
            {
                auto const another = fixture.sticky_message("two");
                auto const third = parsed(fixture.sliding(fixture.bob_token(), lazy_list_request(stable_extension),
                                                          *string_member(second, "pos")));
                THEN("alice's member event is not sent again")
                {
                    REQUIRE(sliding_ids(fixture, third) == std::vector<std::string>{another});
                    REQUIRE(required_member_count(fixture, third, alice) == 0U);
                }
            }
        }
    }
}

// MSC4354: "History visibility checks MUST NOT be applied to unexpired sticky events"; any joined user may see them
// while they remain sticky (ADR-0858).
SCENARIO("a user who joins later reads an unexpired sticky event whatever the history visibility",
         "[sticky-events][integration]")
{
    GIVEN("a joined-visibility room with a sticky and a plain message sent before bob joined")
    {
        auto fixture = Fixture{};
        fixture.set_history_visibility("joined");
        auto const sticky = fixture.sticky_message("one", t0 + 60'000);
        auto const plain = fixture.plain_message("two");
        auto const event_path = "/_matrix/client/v3/rooms/" + fixture.room_id() + "/event/";
        fixture.bob_joins();

        WHEN("bob reads both through /event, and the sticky one through /context")
        {
            auto const sticky_event = fixture.send("GET", event_path + sticky, fixture.bob_token());
            auto const plain_event = fixture.send("GET", event_path + plain, fixture.bob_token());
            auto const context = fixture.send(
                "GET", "/_matrix/client/v3/rooms/" + fixture.room_id() + "/context/" + sticky, fixture.bob_token());

            THEN("the sticky event is served and the plain one is not")
            {
                REQUIRE(sticky_event.status == 200U);
                REQUIRE(*string_member(parse_object(sticky_event.body), "event_id") == sticky);
                REQUIRE(plain_event.status == 404U);
                REQUIRE(context.status == 200U);
            }
        }

        WHEN("the clock reaches its expiry and bob reads it")
        {
            fixture.runtime().homeserver.database.persistent_store.test_sticky_clock_ms = t0 + 60'000;
            auto const sticky_event = fixture.send("GET", event_path + sticky, fixture.bob_token());
            THEN("it is hidden again, as joined visibility asks")
            {
                REQUIRE(sticky_event.status == 404U);
            }
        }
    }
}
