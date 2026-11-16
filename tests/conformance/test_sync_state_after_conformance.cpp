// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /_matrix/client/v3/sync `use_state_after` and the `state_after` section of joined and left rooms
// (client-server-api.md, GET /sync, "Joined Room", "Left Room"; ADR-0763 to ADR-0765).
#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/core/QueryParams.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::canonicaljson::Object;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto k_state_after = std::string_view{"&use_state_after=true"};
constexpr auto k_state_before = std::string_view{"&use_state_after=false"};
constexpr auto k_no_filter = std::string_view{"{}"};
constexpr auto k_one_event = std::string_view{R"({"room":{"timeline":{"limit":1}}})"};
constexpr auto k_lazy = std::string_view{R"({"room":{"state":{"lazy_load_members":true}}})"};
constexpr auto k_lazy_one_event =
    std::string_view{R"({"room":{"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};
constexpr auto k_include_leave = std::string_view{R"({"room":{"include_leave":true}})"};

[[nodiscard]] auto state_after_config() -> merovingian::config::Config
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

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto user_id(std::string_view localpart) -> std::string
{
    return "@" + std::string{localpart} + ":example.org";
}

[[nodiscard]] auto register_user(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "access_token");
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token, std::string const& preset)
    -> std::string
{
    auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":")" + preset + R"("})");
    REQUIRE(created.status == 200U);
    return *string_member(parse_object(created.body), "room_id");
}

auto room_post(ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string const& action,
               std::string body = "{}") -> void
{
    REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/" + action, token, std::move(body)).status ==
            200U);
}

auto say(ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string const& text) -> void
{
    static auto counter = std::uint64_t{0U};
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/sa" + std::to_string(++counter),
             token, R"({"msgtype":"m.text","body":")" + text + R"("})");
    REQUIRE(sent.status == 200U);
}

auto set_topic(ClientServerRuntime& rt, std::string const& token, std::string const& room_id, std::string const& topic)
    -> std::string
{
    auto const sent = call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.topic/", token,
                           R"({"topic":")" + topic + R"("})");
    REQUIRE(sent.status == 200U);
    return *string_member(parse_object(sent.body), "event_id");
}

auto set_display_name(ClientServerRuntime& rt, std::string const& token, std::string const& room_id,
                      std::string const& localpart, std::string const& name) -> void
{
    auto const sent =
        call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/" + user_id(localpart), token,
             R"({"membership":"join","displayname":")" + name + R"("})");
    REQUIRE(sent.status == 200U);
}

struct Synced final
{
    Object body{};
    std::string next_batch{};
};

[[nodiscard]] auto sync(ClientServerRuntime& rt, std::string const& token, std::string_view filter,
                        std::string const& since = {}, std::string_view extra = {}) -> Synced
{
    auto target =
        std::string{"/_matrix/client/v3/sync?filter="} + merovingian::core::percent_encode_path_component(filter);
    if (!since.empty())
    {
        target += "&since=" + merovingian::core::percent_encode_path_component(since);
    }
    target += extra;
    auto const reply = call(rt, "GET", target, token);
    REQUIRE(reply.status == 200U);
    auto body = parse_object(reply.body);
    auto next = *string_member(body, "next_batch");
    return {std::move(body), std::move(next)};
}

// rooms.<section>.<room_id>, or nullptr.
[[nodiscard]] auto room_section(Synced const& synced, std::string_view section, std::string const& room_id)
    -> Object const*
{
    auto const* rooms = object_member_as_object(synced.body, "rooms");
    auto const* group = rooms == nullptr ? nullptr : object_member_as_object(*rooms, section);
    return group == nullptr ? nullptr : object_member_as_object(*group, room_id);
}

[[nodiscard]] auto required_room(Synced const& synced, std::string_view section, std::string const& room_id)
    -> Object const&
{
    auto const* room = room_section(synced, section, room_id);
    REQUIRE(room != nullptr);
    return *room;
}

// Whether `room` has the member `part`, whatever it holds.
[[nodiscard]] auto has_part(Object const& room, std::string_view part) -> bool
{
    return object_member_as_object(room, part) != nullptr;
}

// The events of `room.<part>`, which must be present.
[[nodiscard]] auto events_of(Object const& room, std::string_view part) -> std::vector<Object>
{
    auto const* section = object_member_as_object(room, part);
    REQUIRE(section != nullptr);
    auto const* events = object_member_as_array(*section, "events");
    REQUIRE(events != nullptr);
    auto out = std::vector<Object>{};
    for (auto const& entry : *events)
    {
        out.push_back(std::get<Object>(entry.storage()));
    }
    return out;
}

using Keys = std::multiset<std::string>;

[[nodiscard]] auto event_types(std::vector<Object> const& events) -> Keys
{
    auto types = Keys{};
    for (auto const& event : events)
    {
        types.insert(*string_member(event, "type"));
    }
    return types;
}

// The state_key of every m.room.member event.
[[nodiscard]] auto member_keys(std::vector<Object> const& events) -> Keys
{
    auto keys = Keys{};
    for (auto const& event : events)
    {
        if (*string_member(event, "type") == "m.room.member")
        {
            keys.insert(*string_member(event, "state_key"));
        }
    }
    return keys;
}

// `content.<field>` of the event of (type, state_key), or nullopt when `events` has none.
[[nodiscard]] auto content_of(std::vector<Object> const& events, std::string_view type, std::string_view state_key,
                              std::string_view field) -> std::optional<std::string>
{
    for (auto const& event : events)
    {
        auto const* key = string_member(event, "state_key");
        if (*string_member(event, "type") == type && key != nullptr && *key == state_key)
        {
            auto const* content = object_member_as_object(event, "content");
            auto const* value = content == nullptr ? nullptr : string_member(*content, field);
            return value == nullptr ? std::optional<std::string>{} : std::optional<std::string>{*value};
        }
    }
    return std::nullopt;
}

// The `content.topic` of every m.room.topic event in `events`.
[[nodiscard]] auto topics_in(std::vector<Object> const& events) -> std::vector<std::string>
{
    auto topics = std::vector<std::string>{};
    for (auto const& event : events)
    {
        if (*string_member(event, "type") == "m.room.topic")
        {
            auto const* content = object_member_as_object(event, "content");
            topics.push_back(*string_member(*content, "topic"));
        }
    }
    return topics;
}

auto require_state_after_only(Object const& room) -> void
{
    REQUIRE(has_part(room, "state_after"));
    REQUIRE_FALSE(has_part(room, "state"));
}

auto require_state_only(Object const& room) -> void
{
    REQUIRE(has_part(room, "state"));
    REQUIRE_FALSE(has_part(room, "state_after"));
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state`,
// `state_after` URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// "If this is set to true, servers MUST respond with the state between the previous sync and the end of the timeline in
// state_after and MUST omit state. If false, servers MUST respond with the state between the previous sync and the
// start of the timeline in state and MUST omit state_after." "By default, this is false." `state_after`: "all state up
// to the end of the timeline, if since is not given, or full_state is true".
SCENARIO("An initial sync answers state_after or state as use_state_after asks",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room whose topic changed inside the last two events")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        say(rt, alice, room, "a");
        set_topic(rt, alice, room, "second");
        say(rt, alice, room, "b");
        constexpr auto two_events = std::string_view{R"({"room":{"timeline":{"limit":2}}})"};

        WHEN("alice syncs with use_state_after=true")
        {
            auto const synced = sync(rt, alice, two_events, {}, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after is the whole state at the end of the timeline, and state is omitted")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after) == Keys{user_id("alice")});
            }
        }
        WHEN("alice syncs with use_state_after=false")
        {
            auto const synced = sync(rt, alice, two_events, {}, k_state_before);
            auto const& joined = required_room(synced, "join", room);

            THEN("state is the state at the start of the timeline, and state_after is omitted")
            {
                require_state_only(joined);
                REQUIRE(topics_in(events_of(joined, "state")) == std::vector<std::string>{"first"});
            }
        }
        WHEN("alice syncs without the parameter")
        {
            auto const synced = sync(rt, alice, two_events);
            auto const& joined = required_room(synced, "join", room);

            THEN("it is as if it were false")
            {
                require_state_only(joined);
                REQUIRE(topics_in(events_of(joined, "state")) == std::vector<std::string>{"first"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `state_after`: "Updates to the state, between the time indicated by the since parameter, and the end of the
// timeline". "If this field is set, even if it is empty, clients MUST only update their local state with events in this
// list, and MUST NOT update their local state with events in timeline." "Required if use_state_after was set to true in
// the request, even if it is empty."
SCENARIO("An incremental sync's state_after holds what changed up to the end of the timeline",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room alice has synced")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);

        WHEN("only a message arrived")
        {
            say(rt, alice, room, "hello");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after is present and empty, and state is omitted")
            {
                require_state_after_only(joined);
                REQUIRE(events_of(joined, "state_after").empty());
            }
        }
        WHEN("only a message arrived and the parameter is false or absent")
        {
            say(rt, alice, room, "hello");
            auto const off = sync(rt, alice, k_no_filter, initial.next_batch, k_state_before);
            auto const absent = sync(rt, alice, k_no_filter, initial.next_batch);

            THEN("state is present and state_after is omitted")
            {
                require_state_only(required_room(off, "join", room));
                require_state_only(required_room(absent, "join", room));
            }
        }
        WHEN("the timeline carries a topic change")
        {
            say(rt, alice, room, "before");
            set_topic(rt, alice, room, "second");
            say(rt, alice, room, "after");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after repeats the change, as the client takes no state from the timeline, and nothing else")
            {
                require_state_after_only(joined);
                REQUIRE(topics_in(events_of(joined, "timeline")) == std::vector<std::string>{"second"});
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("the topic changed twice since the last sync")
        {
            set_topic(rt, alice, room, "second");
            set_topic(rt, alice, room, "third");
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds the value at the end of the timeline, once")
            {
                REQUIRE(topics_in(events_of(required_room(synced, "join", room), "state_after")) ==
                        std::vector<std::string>{"third"});
            }
        }
        WHEN("a topic change falls in the gap of a limited sync")
        {
            set_topic(rt, alice, room, "second");
            say(rt, alice, room, "one");
            say(rt, alice, room, "two");
            auto const synced = sync(rt, alice, k_one_event, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds the change and not the state that did not change")
            {
                auto const* timeline = object_member_as_object(joined, "timeline");
                REQUIRE(timeline != nullptr);
                REQUIRE(events_of(joined, "timeline").size() == 1U);
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("the timeline filter hides a topic change")
        {
            constexpr auto hide_topic = std::string_view{R"({"room":{"timeline":{"not_types":["m.room.topic"]}}})"};
            set_topic(rt, alice, room, "hidden");
            auto const synced = sync(rt, alice, hide_topic, initial.next_batch, k_state_after);

            THEN("state_after still reports it, because the next sync starts after it")
            {
                auto const& joined = required_room(synced, "join", room);
                REQUIRE(events_of(joined, "timeline").empty());
                REQUIRE(topics_in(events_of(joined, "state_after")) == std::vector<std::string>{"hidden"});
                auto const next = sync(rt, alice, hide_topic, synced.next_batch, k_state_after);
                auto const* again = room_section(next, "join", room);
                REQUIRE((again == nullptr || events_of(*again, "state_after").empty()));
            }
        }
        WHEN("the state filter excludes the type that changed")
        {
            constexpr auto no_topic = std::string_view{R"({"room":{"state":{"not_types":["m.room.topic"]}}})"};
            set_topic(rt, alice, room, "second");
            auto const synced = sync(rt, alice, no_topic, initial.next_batch, k_state_after);

            THEN("state_after is present and does not hold it")
            {
                auto const& joined = required_room(synced, "join", room);
                require_state_after_only(joined);
                REQUIRE(events_of(joined, "state_after").empty());
            }
        }
        WHEN("nothing happened")
        {
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("the room is not reported")
            {
                REQUIRE(room_section(synced, "join", room) == nullptr);
            }
        }
        WHEN("more state changes than one delta chain can hold happened")
        {
            for (auto index = 0; index < 120; ++index)
            {
                set_topic(rt, alice, room, "t" + std::to_string(index));
            }
            auto const synced = sync(rt, alice, k_one_event, initial.next_batch, k_state_after);

            THEN("state_after still holds only the key that changed, with its last value")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.topic"});
                REQUIRE(topics_in(after) == std::vector<std::string>{"t119"});
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `use_state_after`: "the state between the previous sync and the end of the timeline". State resolution can move a key
// back to an older event: no event of the window is about that key, and only comparing the two states shows the change.
SCENARIO("state_after reports a key that state resolution moved back to an older event",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room with a forked graph whose resolved topic went back to an earlier event")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        auto const old_topic = set_topic(rt, alice, room, "old");
        set_topic(rt, alice, room, "new");
        auto const initial = sync(rt, alice, k_no_filter, {}, k_state_after);
        say(rt, alice, room, "the event that arrived with the fork");

        auto& store = rt.homeserver.database.persistent_store;
        store.forward_extremities.push_back({room, old_topic});
        for (auto& row : store.state)
        {
            if (row.room_id == room && row.event_type == "m.room.topic")
            {
                row.event_id = old_topic;
            }
        }
        merovingian::database::rebuild_state_index(store);

        WHEN("alice syncs with use_state_after=true")
        {
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, k_state_after);

            THEN("state_after holds the older event, and the unchanged state stays out")
            {
                auto const after = events_of(required_room(synced, "join", room), "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"old"});
                REQUIRE_FALSE(event_types(after).contains("m.room.create"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `full_state`: "If this is set to true, then all state events will be returned, even if since is non-empty."
// `state_after`: "all state up to the end of the timeline, if since is not given, or full_state is true".
SCENARIO("full_state=true returns the whole state in the section use_state_after names",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room alice has synced, whose topic changed since")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, alice, k_no_filter);
        set_topic(rt, alice, room, "second");

        WHEN("alice asks for the full state with use_state_after=true")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds all state, the timeline's change included, and state is omitted")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"second"});
            }
        }
        WHEN("alice asks for the full state with use_state_after=false")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_before};
            auto const synced = sync(rt, alice, k_no_filter, initial.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state holds all state up to the start of the timeline, and state_after is omitted")
            {
                require_state_only(joined);
                auto const state = events_of(joined, "state");
                REQUIRE(event_types(state).contains("m.room.create"));
                REQUIRE(topics_in(state) == std::vector<std::string>{"first"});
            }
        }
        WHEN("nothing changed and alice asks for the full state with use_state_after=true")
        {
            auto const caught_up = sync(rt, alice, k_no_filter, initial.next_batch);
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_no_filter, caught_up.next_batch, extra);

            THEN("the room is still reported, with all state")
            {
                auto const& joined = required_room(synced, "join", room);
                require_state_after_only(joined);
                REQUIRE(event_types(events_of(joined, "state_after")).contains("m.room.create"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// A room the client had no state for: it joined inside the window, so a delta would tell it nothing.
SCENARIO("state_after of a room joined in the window is the room's whole state",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room bob joins after his first sync")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        auto const initial = sync(rt, bob, k_no_filter, {}, k_state_after);
        room_post(rt, bob, room, "join");

        WHEN("bob syncs with use_state_after=true")
        {
            auto const synced = sync(rt, bob, k_no_filter, initial.next_batch, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds all state, his own join included, and state is omitted")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(topics_in(after) == std::vector<std::string>{"first"});
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "membership") == "join");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, Left Room
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// Left Room `state`: "The state updates for the room up to the start of the timeline. MUST be omitted if
// use_state_after was set to true in the request." `state_after`: "The state updates for the room up to the end of the
// timeline. If this field is set, even if it is empty, clients MUST only update their local state with events in this
// list, and MUST NOT update their local state with events in timeline." Room History Visibility: "After a user has left
// a room, they may see any events which they were allowed to see before they left the room, but no events received
// after they left."
SCENARIO("A left room answers state_after or state as use_state_after asks",
         "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room dave joined and synced, and whose topic changed before he left")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        set_topic(rt, alice, room, "first");
        room_post(rt, dave, room, "join");
        auto const synced_before = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "changed before the leave");
        room_post(rt, dave, room, "leave");
        set_topic(rt, alice, room, "changed after the leave");

        WHEN("dave makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_include_leave, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is the state up to his leave, the leave included, and state is omitted")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"changed before the leave"});
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        WHEN("dave makes an initial sync with include_leave, without the parameter and with it false")
        {
            auto const absent = sync(rt, dave, k_include_leave);
            auto const off = sync(rt, dave, k_include_leave, {}, k_state_before);

            THEN("state is present and state_after is omitted")
            {
                require_state_only(required_room(absent, "leave", room));
                require_state_only(required_room(off, "leave", room));
            }
        }
        WHEN("dave makes an incremental sync with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds what changed up to his leave and the leave, though the timeline carries it")
            {
                require_state_after_only(left);
                REQUIRE(content_of(events_of(left, "timeline"), "m.room.member", user_id("dave"), "membership") ==
                        "leave");
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"changed before the leave"});
                REQUIRE(event_types(after) == Keys{"m.room.member", "m.room.topic"});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        WHEN("dave makes an incremental sync without the parameter")
        {
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch);

            THEN("state is present and state_after is omitted")
            {
                require_state_only(required_room(synced, "leave", room));
            }
        }
        WHEN("dave makes an incremental sync with full_state=true and use_state_after=true")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, extra);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after is present and state is omitted; he is no longer a member, so it stays a delta")
            {
                require_state_after_only(left);
                REQUIRE_FALSE(event_types(events_of(left, "state_after")).contains("m.room.create"));
            }
        }
        WHEN("dave makes an incremental sync with full_state=true and use_state_after=false")
        {
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_before};
            auto const synced = sync(rt, dave, k_no_filter, synced_before.next_batch, extra);

            THEN("state is present and state_after is omitted")
            {
                require_state_only(required_room(synced, "leave", room));
            }
        }
    }
    GIVEN("a room dave left and synced, then was banned from after its topic changed")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");
        auto const after_leave = sync(rt, dave, k_no_filter, {}, k_state_after);
        set_topic(rt, alice, room, "secret");
        room_post(rt, alice, room, "ban", R"({"user_id":")" + user_id("dave") + R"("})");

        WHEN("dave syncs with use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_no_filter, after_leave.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds his ban and nothing of what happened after he left")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(topics_in(after).empty());
                REQUIRE(event_types(after) == Keys{"m.room.member"});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
            }
        }
        WHEN("dave makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_include_leave, {}, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("state_after is the room as of his leave, with his own membership the ban")
            {
                REQUIRE(topics_in(after).empty());
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
            }
        }
    }
    GIVEN("a private room erin was invited to and declined, never having joined")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "private_chat");
        set_topic(rt, alice, room, "secret");
        room_post(rt, alice, room, "invite", R"({"user_id":")" + user_id("erin") + R"("})");
        room_post(rt, erin, room, "leave");

        WHEN("erin makes an initial sync with include_leave and use_state_after=true")
        {
            auto const synced = sync(rt, erin, k_include_leave, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds only her own leave, as she never could read the room")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(event_types(after) == Keys{"m.room.member"});
                REQUIRE(content_of(after, "m.room.member", user_id("erin"), "membership") == "leave");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /_matrix/client/v3/sync, query parameter `use_state_after`; Joined Room `state_after`
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3sync
//
// `state_after`: "State updates for m.room.member events will be incomplete if lazy_load_members is enabled in the
// /sync filter, and only return the member events required to display the senders of the timeline events in this
// response." Lazy-loading room members: "servers MUST include the syncing user's own membership event ... when the full
// state of rooms is requested". Redundancy follows ADR-0450; a timeline event is not state here, so ADR-0764 forces
// every change.
SCENARIO("Lazy-loading selects the members of state_after", "[conformance][client-server][sync][state-after]")
{
    GIVEN("a room of alice, bob and carol, in which bob and carol have spoken")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const carol = register_user(rt, "carol");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, bob, room, "join");
        room_post(rt, carol, room, "join");
        set_topic(rt, alice, room, "first");
        say(rt, carol, room, "carol");
        say(rt, bob, room, "bob");

        WHEN("alice makes an initial sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after keeps other state and only the sender's and her own membership")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(topics_in(after) == std::vector<std::string>{"first"});
                REQUIRE(member_keys(after) == Keys{user_id("alice"), user_id("bob")});
            }
        }
        WHEN("alice makes an initial sync with lazy-loading and use_state_after=false")
        {
            auto const synced = sync(rt, alice, k_lazy_one_event, {}, k_state_before);
            auto const& joined = required_room(synced, "join", room);

            THEN("state holds those members, and state_after is omitted")
            {
                require_state_only(joined);
                REQUIRE(member_keys(events_of(joined, "state")) == Keys{user_id("alice"), user_id("bob")});
            }
        }
        WHEN("carol speaks in two incremental syncs, each acknowledging the last")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, carol, room, "carol again");
            auto const second = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            say(rt, carol, room, "carol once more");
            auto const third = sync(rt, alice, k_lazy, second.next_batch, k_state_after);

            THEN("carol's membership comes once, then is redundant")
            {
                REQUIRE(member_keys(events_of(required_room(second, "join", room), "state_after")) ==
                        Keys{user_id("carol")});
                auto const after = events_of(required_room(third, "join", room), "state_after");
                require_state_after_only(required_room(third, "join", room));
                REQUIRE(member_keys(after).empty());
            }
        }
        WHEN("the response that carried carol's membership is lost and the client retries")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, carol, room, "carol again");
            auto const lost = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            REQUIRE(member_keys(events_of(required_room(lost, "join", room), "state_after")) == Keys{user_id("carol")});
            auto const retried = sync(rt, alice, k_lazy, first.next_batch, k_state_after);

            THEN("it is sent again")
            {
                REQUIRE(member_keys(events_of(required_room(retried, "join", room), "state_after")) ==
                        Keys{user_id("carol")});
            }
        }
        WHEN("bob speaks and then changes his display name in the same window")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            say(rt, bob, room, "still bob");
            set_display_name(rt, bob, room, "bob", "Bobby");
            auto const synced = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds his membership as of the end of the timeline, once")
            {
                REQUIRE(member_keys(after) == Keys{user_id("bob")});
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "displayname") == "Bobby");
            }
        }
        WHEN("the timeline carries a membership change about someone who did not speak")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            room_post(rt, alice, room, "kick", R"({"user_id":")" + user_id("carol") + R"("})");
            auto const synced = sync(rt, alice, k_lazy, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds it, because the client takes no state from the timeline")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("carol"), "membership") == "leave");
            }
        }
        WHEN("a membership change falls in the gap of a limited sync")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            room_post(rt, carol, room, "leave");
            say(rt, bob, room, "one");
            say(rt, bob, room, "two");
            auto const synced = sync(rt, alice, k_lazy_one_event, first.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "join", room), "state_after");

            THEN("state_after holds it, and the state that did not change stays out")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("carol"), "membership") == "leave");
                REQUIRE(topics_in(after).empty());
            }
        }
        WHEN("alice asks for the full state with lazy-loading and use_state_after=true")
        {
            auto const first = sync(rt, alice, k_lazy_one_event, {}, k_state_after);
            auto const acknowledged = sync(rt, alice, k_lazy_one_event, first.next_batch, k_state_after);
            auto const extra = std::string{"&full_state=true"} + std::string{k_state_after};
            auto const synced = sync(rt, alice, k_lazy_one_event, acknowledged.next_batch, extra);
            auto const& joined = required_room(synced, "join", room);

            THEN("state_after holds her own membership and all other state")
            {
                require_state_after_only(joined);
                auto const after = events_of(joined, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after).contains(user_id("alice")));
                REQUIRE_FALSE(member_keys(after).contains(user_id("carol")));
            }
        }
        WHEN("the client acknowledged bob, and bob leaves and rejoins")
        {
            auto const bob_first = sync(rt, bob, k_lazy, {}, k_state_after);
            say(rt, alice, room, "alice");
            auto const bob_second = sync(rt, bob, k_lazy, bob_first.next_batch, k_state_after);
            auto const bob_third = sync(rt, bob, k_lazy, bob_second.next_batch, k_state_after);
            room_post(rt, bob, room, "leave");
            auto const bob_left = sync(rt, bob, k_lazy, bob_third.next_batch, k_state_after);
            room_post(rt, bob, room, "join");
            say(rt, alice, room, "welcome back");
            auto const rejoined = sync(rt, bob, k_lazy, bob_left.next_batch, k_state_after);
            auto const after = events_of(required_room(rejoined, "join", room), "state_after");

            THEN("the tracker is not consulted, and his own join is in state_after though the timeline carries it")
            {
                REQUIRE(member_keys(after).contains(user_id("alice")));
                REQUIRE(content_of(after, "m.room.member", user_id("bob"), "membership") == "join");
                REQUIRE(event_types(after).contains("m.room.create"));
            }
        }
    }
    GIVEN("a room of alice and dave that dave leaves after bob spoke")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const bob = register_user(rt, "bob");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, bob, room, "join");
        room_post(rt, dave, room, "join");
        auto const before = sync(rt, dave, k_lazy_one_event, {}, k_state_after);
        say(rt, bob, room, "bob");
        room_post(rt, dave, room, "leave");

        WHEN("dave makes an incremental sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy, before.next_batch, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after holds his leave and the sender's membership")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(member_keys(after) == Keys{user_id("bob"), user_id("dave")});
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
        WHEN("dave makes an initial sync with include_leave, lazy-loading and use_state_after=true")
        {
            constexpr auto lazy = std::string_view{
                R"({"room":{"include_leave":true,"timeline":{"limit":1},"state":{"lazy_load_members":true}}})"};
            auto const synced = sync(rt, dave, lazy, {}, k_state_after);
            auto const& left = required_room(synced, "leave", room);

            THEN("state_after keeps other state and holds only his own membership among members")
            {
                require_state_after_only(left);
                auto const after = events_of(left, "state_after");
                REQUIRE(event_types(after).contains("m.room.create"));
                REQUIRE(member_keys(after) == Keys{user_id("dave")});
            }
        }
    }
    GIVEN("a room dave joins, speaks in and leaves, all after his last sync")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const room = create_room(rt, alice, "public_chat");
        auto const before = sync(rt, dave, k_lazy, {}, k_state_after);
        room_post(rt, dave, room, "join");
        say(rt, dave, room, "hello and goodbye");
        room_post(rt, dave, room, "leave");

        WHEN("dave syncs with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy, before.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("his own membership is there once, as the leave, so his earlier join cannot override it")
            {
                REQUIRE(member_keys(after).count(user_id("dave")) == 1U);
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "leave");
            }
        }
    }
    GIVEN("a room dave left and synced, which erin then joined, and from which dave was then banned")
    {
        auto started = merovingian::homeserver::start_client_server(state_after_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_user(rt, "alice");
        auto const dave = register_user(rt, "dave");
        auto const erin = register_user(rt, "erin");
        auto const room = create_room(rt, alice, "public_chat");
        room_post(rt, dave, room, "join");
        room_post(rt, dave, room, "leave");
        auto const after_leave = sync(rt, dave, k_lazy_one_event, {}, k_state_after);
        room_post(rt, erin, room, "join");
        say(rt, erin, room, "dave cannot know I am here");
        room_post(rt, alice, room, "ban", R"({"user_id":")" + user_id("dave") + R"("})");

        WHEN("dave makes a limited incremental sync with lazy-loading and use_state_after=true")
        {
            auto const synced = sync(rt, dave, k_lazy_one_event, after_leave.next_batch, k_state_after);
            auto const after = events_of(required_room(synced, "leave", room), "state_after");

            THEN("state_after holds his ban and does not show who joined after he left")
            {
                REQUIRE(content_of(after, "m.room.member", user_id("dave"), "membership") == "ban");
                REQUIRE_FALSE(member_keys(after).contains(user_id("erin")));
            }
        }
    }
}
