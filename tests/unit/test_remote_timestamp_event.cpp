// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Asking other servers for timestamp_to_event (ADR-0299).
//
// Spec: server-server-api.md GET /_matrix/federation/v1/timestamp_to_event/{roomId}: "A good heuristic
// for which servers to try first is to sort by servers that have been in the room the longest"; "the
// local homeserver ... should determine, using the `origin_server_ts` property, whether the returned
// event is closer to the requested timestamp than the closest event that it could find locally".

#include "merovingian/database/event_table.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/remote_timestamp_event.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::database::TimeDirection;
using merovingian::homeserver::parse_timestamp_to_event_answer;
using merovingian::homeserver::timestamp_is_closer;
using merovingian::homeserver::timestamp_to_event_candidate_servers;

constexpr auto room_id = "!room:ours.example";
constexpr auto our_server = "ours.example";

auto add_membership(merovingian::database::PersistentStore& store, std::string user_id, std::string membership,
                    std::uint64_t stream_ordering, std::string room = room_id) -> void
{
    store.memberships.push_back({std::move(room), std::move(user_id), std::move(membership), stream_ordering});
}

} // namespace

SCENARIO("The servers asked for timestamp_to_event are those longest in the room, never this one, at most three",
         "[homeserver][timestamp-to-event][remote-timestamp-event]")
{
    GIVEN("a room whose joined users are on this server and on four others, joined at different times")
    {
        auto store = merovingian::database::PersistentStore{};
        add_membership(store, "@alice:ours.example", "join", 1U);
        add_membership(store, "@d1:late.example", "join", 400U);
        add_membership(store, "@b1:mid.example", "join", 300U);
        add_membership(store, "@a1:early.example", "join", 200U);
        // A second, later user of an earlier server does not move it down; its earliest join counts.
        add_membership(store, "@a2:early.example", "join", 900U);
        add_membership(store, "@z1:last.example", "join", 800U);

        WHEN("the candidates are chosen")
        {
            auto const servers = timestamp_to_event_candidate_servers(store, room_id, our_server);

            THEN("they are ordered by the earliest current join of any user, and cut at three")
            {
                REQUIRE(servers == std::vector<std::string>{"early.example", "mid.example", "late.example"});
            }
        }
    }

    GIVEN("a room where some remote users have left, were banned or invited, and another room has its own members")
    {
        auto store = merovingian::database::PersistentStore{};
        add_membership(store, "@gone:left.example", "leave", 5U);
        add_membership(store, "@bad:banned.example", "ban", 6U);
        add_membership(store, "@maybe:invited.example", "invite", 7U);
        add_membership(store, "@in:member.example", "join", 8U);
        add_membership(store, "@else:elsewhere.example", "join", 1U, "!other:ours.example");

        WHEN("the candidates are chosen")
        {
            auto const servers = timestamp_to_event_candidate_servers(store, room_id, our_server);

            THEN("only servers with a joined user in this room are candidates")
            {
                REQUIRE(servers == std::vector<std::string>{"member.example"});
            }
        }
    }

    GIVEN("a room only this server is in")
    {
        auto store = merovingian::database::PersistentStore{};
        add_membership(store, "@alice:ours.example", "join", 1U);

        WHEN("the candidates are chosen")
        {
            auto const servers = timestamp_to_event_candidate_servers(store, room_id, our_server);

            THEN("there is nobody to ask")
            {
                REQUIRE(servers.empty());
            }
        }
    }
}

SCENARIO("A timestamp_to_event answer from another server is trusted for nothing but its two fields",
         "[homeserver][timestamp-to-event][remote-timestamp-event]")
{
    GIVEN("answers of different shapes")
    {
        WHEN("the answer is the one the spec shows")
        {
            auto const answer = parse_timestamp_to_event_answer(
                R"({"event_id":"$143273582443PhrSn:example.org","origin_server_ts":1432735824653})");

            THEN("both fields are read, and extra members are ignored")
            {
                REQUIRE(answer.has_value());
                REQUIRE(answer->event_id == "$143273582443PhrSn:example.org");
                REQUIRE(answer->origin_server_ts == 1432735824653);
                REQUIRE(parse_timestamp_to_event_answer(R"({"event_id":"$a","origin_server_ts":1,"extra":[1]})")
                            .has_value());
            }
        }

        WHEN("a field is missing, of the wrong type, or the event ID is not an event ID")
        {
            THEN("the answer is refused")
            {
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"event_id":"$a"})").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"origin_server_ts":1})").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"event_id":1,"origin_server_ts":1})").has_value());
                REQUIRE_FALSE(
                    parse_timestamp_to_event_answer(R"({"event_id":"$a","origin_server_ts":"1"})").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"event_id":"a","origin_server_ts":1})").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"event_id":"","origin_server_ts":1})").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer(R"({"event_id":"$)" + std::string(300U, 'x') +
                                                              R"(","origin_server_ts":1})")
                                  .has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer("[]").has_value());
                REQUIRE_FALSE(parse_timestamp_to_event_answer("not json").has_value());
            }
        }
    }
}

SCENARIO("A remote answer replaces the local one only if it is on the right side of the timestamp and closer",
         "[homeserver][timestamp-to-event][remote-timestamp-event]")
{
    GIVEN("a request at 1000 and a local answer at 1500 looking forwards")
    {
        WHEN("a remote answer is judged")
        {
            THEN("only one between the timestamp and the local answer wins; the boundary at the timestamp counts")
            {
                REQUIRE(timestamp_is_closer(1200, 1500, 1000, TimeDirection::forwards));
                REQUIRE(timestamp_is_closer(1000, 1500, 1000, TimeDirection::forwards));
                REQUIRE_FALSE(timestamp_is_closer(1500, 1500, 1000, TimeDirection::forwards));
                REQUIRE_FALSE(timestamp_is_closer(1800, 1500, 1000, TimeDirection::forwards));
                REQUIRE_FALSE(timestamp_is_closer(999, 1500, 1000, TimeDirection::forwards));
            }
        }
    }

    GIVEN("a request at 1000 and a local answer at 500 looking backwards")
    {
        WHEN("a remote answer is judged")
        {
            THEN("only one between the local answer and the timestamp wins; the boundary at the timestamp counts")
            {
                REQUIRE(timestamp_is_closer(800, 500, 1000, TimeDirection::backwards));
                REQUIRE(timestamp_is_closer(1000, 500, 1000, TimeDirection::backwards));
                REQUIRE_FALSE(timestamp_is_closer(500, 500, 1000, TimeDirection::backwards));
                REQUIRE_FALSE(timestamp_is_closer(300, 500, 1000, TimeDirection::backwards));
                REQUIRE_FALSE(timestamp_is_closer(1001, 500, 1000, TimeDirection::backwards));
            }
        }
    }

    GIVEN("no local answer")
    {
        WHEN("a remote answer is judged")
        {
            THEN("any answer on the right side of the timestamp wins")
            {
                REQUIRE(timestamp_is_closer(5000, std::nullopt, 1000, TimeDirection::forwards));
                REQUIRE_FALSE(timestamp_is_closer(999, std::nullopt, 1000, TimeDirection::forwards));
                REQUIRE(timestamp_is_closer(5, std::nullopt, 1000, TimeDirection::backwards));
                REQUIRE_FALSE(timestamp_is_closer(1001, std::nullopt, 1000, TimeDirection::backwards));
            }
        }
    }
}
