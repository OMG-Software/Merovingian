// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Bundled aggregations: `unsigned.m.relations` on events served to a client, built by the server from
// the child events that point at them (ADR-0430).
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::canonicaljson::Object;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto aggregation_config() -> merovingian::config::Config
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

[[nodiscard]] auto register_token(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!"));
    REQUIRE(registered.status == 200U);
    return *string_member(parse_object(registered.body), "access_token");
}

struct Room final
{
    ClientServerRuntime& rt;
    std::string id;

    [[nodiscard]] auto send(std::string const& token, std::string const& txn, std::string const& body,
                            std::string const& type = "m.room.message") const -> std::string
    {
        auto const reply = call(rt, "PUT", "/_matrix/client/v3/rooms/" + id + "/send/" + type + "/" + txn, token, body);
        REQUIRE(reply.status == 200U);
        return *string_member(parse_object(reply.body), "event_id");
    }

    [[nodiscard]] auto message(std::string const& token, std::string const& txn, std::string const& text) const
        -> std::string
    {
        return send(token, txn, R"({"msgtype":"m.text","body":")" + text + R"("})");
    }

    [[nodiscard]] auto child(std::string const& token, std::string const& txn, std::string_view rel_type,
                             std::string const& parent, std::string const& text = "child") const -> std::string
    {
        return send(token, txn,
                    R"({"msgtype":"m.text","body":")" + text + R"(","m.relates_to":{"rel_type":")" +
                        std::string{rel_type} + R"(","event_id":")" + parent + R"("}})");
    }

    [[nodiscard]] auto edit(std::string const& token, std::string const& txn, std::string const& parent,
                            std::string const& text) const -> std::string
    {
        return send(token, txn,
                    R"({"msgtype":"m.text","body":"* )" + text + R"(","m.new_content":{"msgtype":"m.text","body":")" +
                        text + R"("},"m.relates_to":{"rel_type":"m.replace","event_id":")" + parent + R"("}})");
    }

    [[nodiscard]] auto event(std::string const& token, std::string const& event_id) const -> Object
    {
        auto const reply = call(rt, "GET", "/_matrix/client/v3/rooms/" + id + "/event/" + event_id, token);
        REQUIRE(reply.status == 200U);
        return parse_object(reply.body);
    }
};

// `unsigned.m.relations` of a client event, or nullptr.
[[nodiscard]] auto relations_of(Object const& event) -> Object const*
{
    auto const* unsigned_data = object_member_as_object(event, "unsigned");
    return unsigned_data == nullptr ? nullptr : object_member_as_object(*unsigned_data, "m.relations");
}

[[nodiscard]] auto bundle(Object const& event, std::string_view rel_type) -> Object const*
{
    auto const* relations = relations_of(event);
    return relations == nullptr ? nullptr : object_member_as_object(*relations, rel_type);
}

[[nodiscard]] auto event_in(merovingian::canonicaljson::Array const* events, std::string const& event_id)
    -> std::optional<Object>
{
    if (events == nullptr)
    {
        return std::nullopt;
    }
    for (auto const& entry : *events)
    {
        auto const& event = std::get<Object>(entry.storage());
        auto const* id = string_member(event, "event_id");
        if (id != nullptr && *id == event_id)
        {
            return event;
        }
    }
    return std::nullopt;
}

[[nodiscard]] auto latest_event_id(Object const& event) -> std::string
{
    auto const* thread = bundle(event, "m.thread");
    REQUIRE(thread != nullptr);
    auto const* latest = object_member_as_object(*thread, "latest_event");
    REQUIRE(latest != nullptr);
    return *string_member(*latest, "event_id");
}

[[nodiscard]] auto count_of(Object const& event) -> std::int64_t
{
    auto const* thread = bundle(event, "m.thread");
    REQUIRE(thread != nullptr);
    return *int_member(*thread, "count");
}

[[nodiscard]] auto participated(Object const& event) -> bool
{
    auto const* thread = bundle(event, "m.thread");
    REQUIRE(thread != nullptr);
    return *bool_member(*thread, "current_user_participated");
}

auto ignore_user(ClientServerRuntime& rt, std::string const& token, std::string const& localpart,
                 std::string const& ignored) -> void
{
    auto const reply =
        call(rt, "PUT", "/_matrix/client/v3/user/%40" + localpart + "%3Aexample.org/account_data/m.ignored_user_list",
             token, R"({"ignored_users":{"@)" + ignored + R"(:example.org":{}}})");
    REQUIRE(reply.status == 200U);
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Section: Aggregations of child events; Server-side aggregation of m.thread relationships
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#aggregations-of-child-events
//
// "The endpoints where the server should include bundled aggregations are: /messages, /context,
// /event, the three /relations forms, /sync when the relevant section has a `limited` value of
// true, POST /search for any matching events under room_events, /threads."
SCENARIO("A thread root carries its m.thread aggregation on every endpoint the spec lists",
         "[conformance][client-server][aggregations]")
{
    GIVEN("alice's thread root, two replies from bob, one of which bob edited, and carol who only reads")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const bob = register_token(rt, "bob");
        auto const carol = register_token(rt, "carol");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        REQUIRE(created.status == 200U);
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, bob, "{}").status == 200U);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, carol, "{}").status == 200U);
        auto const root = room.message(alice, "t1", "rootword");
        auto const first = room.child(bob, "t2", "m.thread", root, "first");
        auto const second = room.child(bob, "t3", "m.thread", root, "second");
        std::ignore = room.edit(bob, "t4", first, "first edited");

        WHEN("each endpoint is asked for the root")
        {
            auto const base = "/_matrix/client/v3/rooms/" + room.id;

            THEN("GET /event bundles the thread with its latest event, count and the viewer's participation")
            {
                auto const as_alice = room.event(alice, root);
                auto const as_bob = room.event(bob, root);
                auto const as_carol = room.event(carol, root);
                REQUIRE(count_of(as_alice) == 2);
                REQUIRE(latest_event_id(as_alice) == second);
                // Spec: participated is true for "the sender of the thread root event".
                REQUIRE(participated(as_alice));
                // Spec: ... or "the sender of an event which references the thread root".
                REQUIRE(participated(as_bob));
                REQUIRE_FALSE(participated(as_carol));
            }

            THEN("GET /messages bundles it")
            {
                auto const reply = call(rt, "GET", base + "/messages?dir=b&limit=50", carol);
                REQUIRE(reply.status == 200U);
                auto const found = event_in(object_member_as_array(parse_object(reply.body), "chunk"), root);
                REQUIRE(found.has_value());
                REQUIRE(count_of(*found) == 2);
            }

            THEN("GET /context bundles the event")
            {
                auto const reply = call(rt, "GET", base + "/context/" + root, carol);
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* target = object_member_as_object(body, "event");
                REQUIRE(target != nullptr);
                REQUIRE(count_of(*target) == 2);
            }

            THEN("GET /threads bundles it, the latest event carrying its own aggregation")
            {
                auto const reply = call(rt, "GET", "/_matrix/client/v1/rooms/" + room.id + "/threads", carol);
                REQUIRE(reply.status == 200U);
                auto const found = event_in(object_member_as_array(parse_object(reply.body), "chunk"), root);
                REQUIRE(found.has_value());
                REQUIRE(count_of(*found) == 2);
            }

            THEN("POST /search bundles a matching event")
            {
                auto const reply = call(rt, "POST", "/_matrix/client/v3/search", carol,
                                        R"({"search_categories":{"room_events":{"search_term":"rootword"}}})");
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* categories = object_member_as_object(body, "search_categories");
                REQUIRE(categories != nullptr);
                auto const* room_events = object_member_as_object(*categories, "room_events");
                REQUIRE(room_events != nullptr);
                auto const* results = object_member_as_array(*room_events, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 1U);
                auto const& hit = std::get<Object>((*results)[0].storage());
                auto const* result = object_member_as_object(hit, "result");
                REQUIRE(result != nullptr);
                REQUIRE(count_of(*result) == 2);
            }

            THEN("GET /relations bundles each child it lists, here the edited reply's m.replace")
            {
                for (auto const* suffix : {"", "/m.thread", "/m.thread/m.room.message"})
                {
                    auto const reply =
                        call(rt, "GET", "/_matrix/client/v1/rooms/" + room.id + "/relations/" + root + suffix, carol);
                    REQUIRE(reply.status == 200U);
                    auto const listed = event_in(object_member_as_array(parse_object(reply.body), "chunk"), first);
                    REQUIRE(listed.has_value());
                    auto const* replace = bundle(*listed, "m.replace");
                    REQUIRE(replace != nullptr);
                    auto const* content = object_member_as_object(*replace, "content");
                    REQUIRE(content != nullptr);
                    REQUIRE(*string_member(*content, "body") == "* first edited");
                }
            }

            THEN("GET /sync bundles it when the room's timeline is limited, and not when it is whole")
            {
                auto const limited_sync = call(
                    rt, "GET",
                    "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A10%7D%7D%7D",
                    carol);
                REQUIRE(limited_sync.status == 200U);
                auto const body = parse_object(limited_sync.body);
                auto const* joined = object_member_as_object(*object_member_as_object(body, "rooms"), "join");
                auto const* timeline = object_member_as_object(*object_member_as_object(*joined, room.id), "timeline");
                REQUIRE(timeline != nullptr);
                auto const* limited = bool_member(*timeline, "limited");
                auto const found = event_in(object_member_as_array(*timeline, "events"), root);
                if (limited != nullptr && *limited && found.has_value())
                {
                    REQUIRE(count_of(*found) == 2);
                }
                else if (found.has_value())
                {
                    // Spec: an unlimited section's events are not aggregated; the client aggregates.
                    REQUIRE(relations_of(*found) == nullptr);
                }
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Server-side aggregation of m.replace relationships" and
// "Validity of replacement events".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-aggregation-of-mreplace-relationships
SCENARIO("An edited event carries its most recent valid replacement", "[conformance][client-server][aggregations]")
{
    GIVEN("alice's message, an edit by bob, an edit missing m.new_content, and alice's valid edit")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const bob = register_token(rt, "bob");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, bob, "{}").status == 200U);
        auto const original = room.message(alice, "a1", "original");
        std::ignore = room.edit(bob, "b1", original, "bob hijack");
        std::ignore = room.child(alice, "a2", "m.replace", original, "no new content");
        auto const good = room.edit(alice, "a3", original, "alice edit");

        WHEN("the original is fetched")
        {
            auto const served = room.event(bob, original);

            THEN("only the valid edit is bundled, formatted as a normal event, with the content left intact")
            {
                auto const* replace = bundle(served, "m.replace");
                REQUIRE(replace != nullptr);
                // Spec: another sender's edit and one without m.new_content are ignored.
                REQUIRE(*string_member(*replace, "event_id") == good);
                REQUIRE(*string_member(*replace, "sender") == "@alice:example.org");
                REQUIRE(*string_member(*replace, "type") == "m.room.message");
                // Spec: "the content of the original event is left intact".
                auto const* content = object_member_as_object(served, "content");
                REQUIRE(*string_member(*content, "body") == "original");
            }
        }

        WHEN("a later valid edit is added and then redacted")
        {
            auto const later = room.edit(alice, "a4", original, "alice later");
            auto const first = room.event(alice, original);
            auto const* both = bundle(first, "m.replace");
            REQUIRE(both != nullptr);
            // Spec: the most recent is by origin_server_ts, then the lexicographically largest event_id.
            auto const good_ts = *int_member(room.event(alice, good), "origin_server_ts");
            auto const later_ts = *int_member(room.event(alice, later), "origin_server_ts");
            auto const expected = std::tie(later_ts, later) > std::tie(good_ts, good) ? later : good;
            REQUIRE(*string_member(*both, "event_id") == expected);
            REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room.id + "/redact/" + expected + "/r1", alice, "{}")
                        .status == 200U);

            THEN("the redacted edit is removed and the other one takes its place")
            {
                auto const after = room.event(alice, original);
                auto const* replace = bundle(after, "m.replace");
                REQUIRE(replace != nullptr);
                REQUIRE(*string_member(*replace, "event_id") == (expected == later ? good : later));
            }
        }

        WHEN("the original is redacted")
        {
            REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room.id + "/redact/" + original + "/r2", alice, "{}")
                        .status == 200U);

            THEN("no m.replace is bundled with it, though the edits still exist")
            {
                auto const served = room.event(alice, original);
                REQUIRE(bundle(served, "m.replace") == nullptr);
                REQUIRE(room.event(alice, good).size() > 0U);
            }
        }

        WHEN("an edit of the edit is looked for")
        {
            std::ignore = room.edit(alice, "a5", good, "edit of an edit");

            THEN("an edit is never given a replacement bundle")
            {
                REQUIRE(bundle(room.event(alice, good), "m.replace") == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Server-side aggregation of m.reference" and
// "Server-side aggregation of m.annotation relationships".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#server-side-aggregation-of-mreference
SCENARIO("References are listed in a chunk, annotations are not aggregated",
         "[conformance][client-server][aggregations]")
{
    GIVEN("a message with two references and a reaction")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        auto const target = room.message(alice, "m1", "target");
        auto const one = room.child(alice, "m2", "m.reference", target);
        auto const two = room.child(alice, "m3", "m.reference", target);
        std::ignore = room.send(
            alice, "m4", R"({"m.relates_to":{"rel_type":"m.annotation","event_id":")" + target + R"(","key":"x"}})",
            "m.reaction");

        WHEN("the target is fetched")
        {
            auto const served = room.event(alice, target);

            THEN("m.reference lists exactly the referencing events and m.annotation is absent")
            {
                auto const* reference = bundle(served, "m.reference");
                REQUIRE(reference != nullptr);
                auto const* chunk = object_member_as_array(*reference, "chunk");
                REQUIRE(chunk != nullptr);
                REQUIRE(chunk->size() == 2U);
                REQUIRE(event_in(chunk, one).has_value());
                REQUIRE(event_in(chunk, two).has_value());
                REQUIRE(bundle(served, "m.annotation") == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Aggregations of child events".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#aggregations-of-child-events
SCENARIO("An aggregation never counts what the viewer must not see", "[conformance][client-server][aggregations]")
{
    GIVEN("a thread root with replies from bob and dave, and carol who ignores bob")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const bob = register_token(rt, "bob");
        auto const carol = register_token(rt, "carol");
        auto const dave = register_token(rt, "dave");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        for (auto const* token : {&bob, &carol, &dave})
        {
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, *token, "{}").status == 200U);
        }
        auto const root = room.message(alice, "r1", "root");
        std::ignore = room.child(bob, "r2", "m.thread", root);
        auto const from_dave = room.child(dave, "r3", "m.thread", root);
        ignore_user(rt, carol, "carol", "bob");

        WHEN("the root is fetched by carol and by alice")
        {
            auto const as_carol = room.event(carol, root);
            auto const as_alice = room.event(alice, root);

            THEN("spec: events from ignored users are not counted and are never the latest event")
            {
                REQUIRE(count_of(as_carol) == 1);
                REQUIRE(latest_event_id(as_carol) == from_dave);
                REQUIRE(count_of(as_alice) == 2);
            }
        }
    }

    GIVEN("a thread root, and a reply sent after bob left the room")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const bob = register_token(rt, "bob");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, bob, "{}").status == 200U);
        auto const root = room.message(alice, "v1", "root");
        auto const before = room.child(alice, "v2", "m.thread", root, "before");
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/rooms/" + room.id + "/leave", bob, "{}").status == 200U);
        std::ignore = room.child(alice, "v3", "m.thread", root, "after");

        WHEN("bob, who has left, fetches the root")
        {
            auto const as_bob = room.event(bob, root);
            auto const as_alice = room.event(alice, root);

            THEN("the reply he could not read is neither counted nor offered as the latest event")
            {
                REQUIRE(count_of(as_bob) == 1);
                REQUIRE(latest_event_id(as_bob) == before);
                REQUIRE(count_of(as_alice) == 2);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Aggregations of child events": "State events do not
// currently receive bundled aggregations", and ClientEvent `unsigned` is built by the server.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#aggregations-of-child-events
SCENARIO("State events get no aggregation and a stored m.relations is never passed through",
         "[conformance][client-server][aggregations]")
{
    GIVEN("a room name state event with a reference to it, and a message whose stored unsigned is forged")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        auto const name_reply =
            call(rt, "PUT", "/_matrix/client/v3/rooms/" + room.id + "/state/m.room.name/", alice, R"({"name":"Room"})");
        REQUIRE(name_reply.status == 200U);
        auto const name_event = *string_member(parse_object(name_reply.body), "event_id");
        std::ignore = room.child(alice, "s1", "m.reference", name_event);
        auto const message = room.message(alice, "s2", "plain");
        auto& store = rt.homeserver.database.persistent_store;
        auto const stored = store.events.find(message);
        REQUIRE(stored != store.events.end());
        auto forged =
            std::string{R"({"unsigned":{"m.relations":{"m.thread":{"count":99}}},)"} + stored->json.substr(1U);
        REQUIRE(merovingian::database::replace_event_json(store, message, std::move(forged)));

        WHEN("both are fetched")
        {
            auto const state = room.event(alice, name_event);
            auto const forged_served = room.event(alice, message);

            THEN("the state event has none and the forged one is not served")
            {
                REQUIRE(relations_of(state) == nullptr);
                REQUIRE(relations_of(forged_served) == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Aggregations of child events": the server includes bundled
// aggregations in `GET /sync` "when the relevant section has a `limited` value of true".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#aggregations-of-child-events
SCENARIO("A sync section carries aggregations only when it is limited", "[conformance][client-server][aggregations]")
{
    GIVEN("a root and one reply, read by carol")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const carol = register_token(rt, "carol");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/join/" + room.id, carol, "{}").status == 200U);
        auto const root = room.message(alice, "y1", "root");
        std::ignore = room.child(alice, "y2", "m.thread", root);

        auto const timeline_of = [&](std::string const& filter) {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/sync?filter=" + filter, carol);
            REQUIRE(reply.status == 200U);
            auto const body = parse_object(reply.body);
            auto const* rooms = object_member_as_object(body, "rooms");
            REQUIRE(rooms != nullptr);
            auto const* joined = object_member_as_object(*rooms, "join");
            REQUIRE(joined != nullptr);
            auto const* section = object_member_as_object(*joined, room.id);
            REQUIRE(section != nullptr);
            auto timeline = *object_member_as_object(*section, "timeline");
            return timeline;
        };

        WHEN("the timeline is cut to the last two events, so it is limited")
        {
            auto const timeline = timeline_of("%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A2%7D%7D%7D");

            THEN("the root in it carries its thread")
            {
                REQUIRE(*bool_member(timeline, "limited"));
                auto const found = event_in(object_member_as_array(timeline, "events"), root);
                REQUIRE(found.has_value());
                // Spec: a `limited` section's events are aggregated.
                REQUIRE(count_of(*found) == 1);
            }
        }

        WHEN("the whole history fits in the timeline")
        {
            auto const timeline = timeline_of("%7B%7D");

            THEN("it is not limited and the root has no aggregation")
            {
                REQUIRE_FALSE(*bool_member(timeline, "limited"));
                auto const found = event_in(object_member_as_array(timeline, "events"), root);
                REQUIRE(found.has_value());
                // Spec: the client aggregates the children it was sent in the same section.
                REQUIRE(relations_of(*found) == nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, "Aggregations of child events" and ClientEvent `unsigned`: the
// server builds `unsigned`; a stored `unsigned.m.relations` is sender-controlled and is never served,
// not on the event, not on its nested `latest_event` or `m.replace`.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#aggregations-of-child-events
SCENARIO("A forged unsigned.m.relations on a nested child never reaches /sync",
         "[conformance][client-server][aggregations]")
{
    GIVEN("a limited room whose reply and edit store a forged unsigned.m.relations")
    {
        auto started = merovingian::homeserver::start_client_server(aggregation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = register_token(rt, "alice");
        auto const created = call(rt, "POST", "/_matrix/client/v3/createRoom", alice, R"({"preset":"public_chat"})");
        auto const room = Room{rt, *string_member(parse_object(created.body), "room_id")};
        auto const root = room.message(alice, "f1", "root");
        auto const reply = room.child(alice, "f2", "m.thread", root);
        auto const edit = room.edit(alice, "f3", root, "edited");
        auto& store = rt.homeserver.database.persistent_store;
        for (auto const* id : {&root, &reply, &edit})
        {
            auto const stored = store.events.find(*id);
            REQUIRE(stored != store.events.end());
            auto forged = std::string{R"({"unsigned":{"m.relations":{"m.thread":{"count":99,"FORGED":1}}},)"} +
                          stored->json.substr(1U);
            REQUIRE(merovingian::database::replace_event_json(store, *id, std::move(forged)));
        }

        WHEN("alice syncs with a timeline cut to the last three events")
        {
            auto const reply_body =
                call(rt, "GET",
                     "/_matrix/client/v3/sync?filter=%7B%22room%22%3A%7B%22timeline%22%3A%7B%22limit%22%3A3%7D%7D%7D",
                     alice);
            REQUIRE(reply_body.status == 200U);

            THEN("the timeline is limited, the real aggregation is served and nothing forged is")
            {
                REQUIRE(reply_body.body.find("FORGED") == std::string::npos);
                auto const body = parse_object(reply_body.body);
                auto const* joined = object_member_as_object(*object_member_as_object(body, "rooms"), "join");
                auto const* timeline = object_member_as_object(*object_member_as_object(*joined, room.id), "timeline");
                REQUIRE(*bool_member(*timeline, "limited"));
                auto const found = event_in(object_member_as_array(*timeline, "events"), root);
                REQUIRE(found.has_value());
                REQUIRE(count_of(*found) == 1);
                REQUIRE(bundle(*found, "m.replace") != nullptr);
            }
        }
    }
}
