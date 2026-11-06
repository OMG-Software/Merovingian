// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The state a federation /state or /state_ids and a client /context answer with is the state this
// server RECORDED for the event (its ADR-0064 state groups), never a walk of the event graph
// (F-25, F-26, ADR-0363). Every store below is filled through the same bookkeeping ingestion runs
// (`compute_state_before`, `compute_state_after`, `record_event_state`), so the recorded state is
// what a real room would hold.

#include "../support/ingested_state_fixture.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/event_query.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace fed = merovingian::federation;
namespace hs = merovingian::homeserver;

constexpr auto room_id = std::string_view{"!room:example.org"};
constexpr auto origin = std::string_view{"example.org"};
constexpr auto sender = std::string_view{"@creator:example.org"};
constexpr auto max_depth = std::uint64_t{9'007'199'254'740'991U};

// One event to put in the room. `state_key` set makes it a state event. `status` is the receipt-order
// status ingestion would have given it ("accepted", "soft_failed", "rejected").
struct NewEvent final
{
    std::string id{};
    std::string type{};
    std::optional<std::string> state_key{};
    std::vector<std::string> prev{};
    std::uint64_t depth{1U};
    std::string status{"accepted"};
    std::string content{"{}"};
};

[[nodiscard]] auto event_json(NewEvent const& event) -> std::string
{
    auto json = std::string{R"({"type":")"} + event.type + R"(","sender":")" + std::string{sender} + R"(","content":)" +
                event.content;
    if (event.state_key.has_value())
    {
        json += R"(,"state_key":")" + *event.state_key + R"(")";
    }
    return json + "}";
}

[[nodiscard]] auto make_event(NewEvent const& event) -> db::PersistentEvent
{
    auto stored = db::PersistentEvent{};
    stored.event_id = event.id;
    stored.room_id = std::string{room_id};
    stored.sender_user_id = std::string{sender};
    stored.json = event_json(event);
    stored.depth = event.depth;
    stored.stream_ordering = event.depth;
    stored.prev_event_ids = event.prev;
    stored.status = event.status;
    return stored;
}

// Stores `event` and records its state the way ingestion does (tests/support/ingested_state_fixture.hpp).
auto ingest(db::PersistentStore& store, NewEvent const& event) -> void
{
    auto const stored = make_event(event);
    store.events.push_back(stored);
    merovingian::tests::record_ingested_state(store, stored);
}

// A room with its create event and the creator's join, which is also what lets `origin` read it.
// create <- join, depths 1 and 2.
[[nodiscard]] auto room_with_creator() -> db::PersistentStore
{
    auto store = db::PersistentStore{};
    ingest(store, {"$create", "m.room.create", "", {}, 1U, "accepted", R"({"room_version":"11"})"});
    ingest(store,
           {"$join", "m.room.member", std::string{sender}, {"$create"}, 2U, "accepted", R"({"membership":"join"})"});
    store.state.push_back({std::string{room_id}, "m.room.create", "", "$create"});
    store.state.push_back({std::string{room_id}, "m.room.member", std::string{sender}, "$join"});
    return store;
}

[[nodiscard]] auto name_event(std::string id, std::vector<std::string> prev, std::uint64_t depth,
                              std::string status = "accepted") -> NewEvent
{
    auto const content = R"({"name":")" + id + R"("})";
    return {std::move(id), "m.room.name", "", std::move(prev), depth, std::move(status), content};
}

[[nodiscard]] auto message_event(std::string id, std::vector<std::string> prev, std::uint64_t depth) -> NewEvent
{
    return {std::move(id), "m.room.message", std::nullopt, std::move(prev), depth, "accepted", "{}"};
}

[[nodiscard]] auto quoted(std::string_view id) -> std::string
{
    return "\"" + std::string{id} + "\"";
}

[[nodiscard]] auto names(std::string const& body, std::string_view id) -> bool
{
    return body.find(quoted(id)) != std::string::npos;
}

[[nodiscard]] auto state_ids_body(db::PersistentStore const& store, std::string_view at) -> std::optional<std::string>
{
    auto const result = fed::build_state_ids_response(store, room_id, at, origin);
    if (result.status != fed::RoomReadStatus::ok)
    {
        return std::nullopt;
    }
    return result.body;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string_view id) -> bool
{
    return std::ranges::find(ids, id) != ids.end();
}

} // namespace

// Spec: SS API v1.19 GET /state_ids/{roomId}, GET /state/{roomId}: the state is "prior to considering
// any state changes induced by the requested event". SS API "Rejection": state is calculated "as normal,
// except not updating with the rejected event where it is a state event".
SCENARIO("A rejected state event never appears in the state at a later event, whatever depth its sender chose",
         "[federation][events][state][state-at-event][security]")
{
    GIVEN("a room where a remote member sent a forged m.room.name with the largest depth, which was rejected, "
          "and then a message that cites it")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_true", {"$join"}, 3U));
        ingest(store, name_event("$name_forged", {"$name_true"}, max_depth, "rejected"));
        ingest(store, message_event("$after_forged", {"$name_forged"}, 4U));

        WHEN("the state IDs at the message are requested")
        {
            auto const body = state_ids_body(store, "$after_forged");

            THEN("the true name is the room's name and the forged event is not named")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_true"));
                REQUIRE_FALSE(names(*body, "$name_forged"));
            }
        }

        WHEN("the state at the message is requested in full")
        {
            auto const result = fed::build_state_response(store, room_id, "$after_forged", origin);

            THEN("the true name is carried and the forged one is not")
            {
                REQUIRE(result.status == fed::RoomReadStatus::ok);
                REQUIRE(result.body.find(R"("name":"$name_true")") != std::string::npos);
                REQUIRE(result.body.find("$name_forged") == std::string::npos);
            }
        }

        WHEN("the state at the message is resolved for a client's /context")
        {
            auto const ids = fed::resolve_state_event_ids_at(store, room_id, "$after_forged");

            THEN("it holds the true name and not the forged event")
            {
                REQUIRE(contains(ids, "$name_true"));
                REQUIRE_FALSE(contains(ids, "$name_forged"));
            }
        }

        WHEN("the state is requested at the rejected event itself")
        {
            auto const body = state_ids_body(store, "$name_forged");

            THEN("it is the state before it, which names the true name")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_true"));
                REQUIRE_FALSE(names(*body, "$name_forged"));
            }
        }
    }

    GIVEN("a rejected event with the largest depth on a branch that a later event merges with another branch")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_true", {"$join"}, 3U));
        ingest(store, name_event("$name_forged", {"$name_true"}, max_depth, "rejected"));
        ingest(store, {"$topic", "m.room.topic", "", {"$name_true"}, 4U, "accepted", R"({"topic":"t"})"});
        ingest(store, message_event("$merge", {"$name_forged", "$topic"}, 5U));

        WHEN("the state IDs at the merging event are requested")
        {
            auto const body = state_ids_body(store, "$merge");

            THEN("the state holds both branches' accepted state and never the rejected event")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_true"));
                REQUIRE(names(*body, "$topic"));
                REQUIRE_FALSE(names(*body, "$name_forged"));
            }
        }
    }
}

// Spec: SS API "Soft failure": a soft-failed event "participate[s] in state resolution as normal", so a
// later event built on it sees the state it set; an event built on its sibling does not.
SCENARIO("A soft-failed state event is in the state of the events built on it and nowhere else",
         "[federation][events][state][state-at-event]")
{
    GIVEN("a soft-failed rename and one event built on it and one built on the rename it followed")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_v1", {"$join"}, 3U));
        ingest(store, name_event("$name_soft", {"$name_v1"}, 4U, "soft_failed"));
        ingest(store, message_event("$on_soft", {"$name_soft"}, 5U));
        ingest(store, message_event("$on_v1", {"$name_v1"}, 5U));

        WHEN("the state IDs at each message are requested")
        {
            auto const on_soft = state_ids_body(store, "$on_soft");
            auto const on_v1 = state_ids_body(store, "$on_v1");

            THEN("the event built on the soft-failed one has its name; the other keeps the earlier name")
            {
                REQUIRE(on_soft.has_value());
                REQUIRE(on_v1.has_value());
                REQUIRE(names(*on_soft, "$name_soft"));
                REQUIRE_FALSE(names(*on_soft, "$name_v1"));
                REQUIRE(names(*on_v1, "$name_v1"));
                REQUIRE_FALSE(names(*on_v1, "$name_soft"));
            }
        }
    }
}

// Spec: SS API GET /state_ids/{roomId}: "prior to considering any state changes induced by the
// requested event". CS API GET /context: "The state of the room at the last event returned".
SCENARIO("The state before a state event excludes its own change, the state at it includes it",
         "[federation][events][state][state-at-event]")
{
    GIVEN("a room whose name is set twice")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_v1", {"$join"}, 3U));
        ingest(store, name_event("$name_v2", {"$name_v1"}, 4U));

        WHEN("the state IDs at the second rename are requested")
        {
            auto const body = state_ids_body(store, "$name_v2");

            THEN("they hold the first name, not the rename itself")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_v1"));
                REQUIRE_FALSE(names(*body, "$name_v2"));
                REQUIRE(names(*body, "$create"));
                REQUIRE(names(*body, "$join"));
            }
        }

        WHEN("the state at the second rename is resolved for a client")
        {
            auto const ids = fed::resolve_state_event_ids_at(store, room_id, "$name_v2");

            THEN("it holds the rename itself in place of the first name")
            {
                REQUIRE(contains(ids, "$name_v2"));
                REQUIRE_FALSE(contains(ids, "$name_v1"));
                REQUIRE(contains(ids, "$join"));
            }
        }
    }
}

// Spec: SS API GET /state_ids/{roomId}: "The fully resolved state for the room".
SCENARIO("The state before an event with several prev_events is the resolution of their states",
         "[federation][events][state][state-at-event]")
{
    GIVEN("two branches that each set different state, and events that merge them")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_branch", {"$join"}, 3U));
        ingest(store, {"$topic_branch", "m.room.topic", "", {"$join"}, 3U, "accepted", R"({"topic":"t"})"});
        ingest(store, message_event("$merge_message", {"$name_branch", "$topic_branch"}, 4U));
        ingest(store, {
                          "$merge_aliases",
                          "m.room.canonical_alias",
                          "",
                          {"$name_branch", "$topic_branch"},
                          4U,
                          "accepted",
                          "{}"
        });

        WHEN("the state IDs at the merging message are requested")
        {
            auto const body = state_ids_body(store, "$merge_message");

            THEN("they hold the state of both branches")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_branch"));
                REQUIRE(names(*body, "$topic_branch"));
                REQUIRE(names(*body, "$join"));
            }
        }

        WHEN("the state IDs at the merging state event are requested")
        {
            auto const body = state_ids_body(store, "$merge_aliases");

            THEN("they hold the state of both branches and not the merging event")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$name_branch"));
                REQUIRE(names(*body, "$topic_branch"));
                REQUIRE_FALSE(names(*body, "$merge_aliases"));
            }
        }
    }
}

// Spec: SS API GET /state_ids/{roomId}, 404: "the server doesn't know about the state at that event to
// return anything useful".
SCENARIO("An event whose state this server never recorded is answered 404 and never walked",
         "[federation][events][state][state-at-event][security]")
{
    // An outlier has no recorded state; serving state for it, or for a child, would hand out a guess dressed as a fact.
    GIVEN("a room holding an outlier whose prev_event this server lacks, and a message that cites the outlier")
    {
        auto store = room_with_creator();
        auto outlier = name_event("$outlier_name", {"$not_held"}, max_depth);
        outlier.status = "outlier";
        store.events.push_back(make_event(outlier));
        store.events.push_back(make_event(message_event("$after_outlier", {"$outlier_name"}, 4U)));

        WHEN("the state is requested at the outlier or at the message after it")
        {
            auto const at_outlier = fed::build_state_ids_response(store, room_id, "$outlier_name", origin);
            auto const after_outlier = fed::build_state_ids_response(store, room_id, "$after_outlier", origin);
            auto const full = fed::build_state_response(store, room_id, "$after_outlier", origin);

            THEN("each is not found, with nothing taken from the outlier")
            {
                REQUIRE(at_outlier.status == fed::RoomReadStatus::not_found);
                REQUIRE(after_outlier.status == fed::RoomReadStatus::not_found);
                REQUIRE(full.status == fed::RoomReadStatus::not_found);
                REQUIRE(fed::resolve_state_event_ids_at(store, room_id, "$after_outlier").empty());
            }
        }
    }

    // Missing recorded state is never rebuilt by walking the event graph: the answer fails closed.
    GIVEN("a room where a state group on the chain of a prev_event is missing")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_v1", {"$join"}, 3U));
        ingest(store, message_event("$on_v1", {"$name_v1"}, 4U));
        auto const group = db::find_event_state_group(store, "$name_v1");
        REQUIRE(group.has_value());
        REQUIRE(store.state_groups.erase_if([&](db::PersistentStateGroup const& row) {
            return row.state_group_id == *group;
        }) == 1U);

        WHEN("the state is requested at the event built on it")
        {
            auto const result = fed::build_state_ids_response(store, room_id, "$on_v1", origin);

            THEN("it is not found rather than rebuilt from the graph")
            {
                REQUIRE(result.status == fed::RoomReadStatus::not_found);
            }
        }
    }

    // The group of a state event includes the event itself, so the prev_event's intact group is not an acceptable
    // substitute.
    GIVEN("a state event whose own recorded group is missing, though the group of its prev_event is intact")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_v1", {"$join"}, 3U));
        ingest(store, name_event("$name_v2", {"$name_v1"}, 4U));
        auto const before_erasing = state_ids_body(store, "$name_v2");
        REQUIRE(before_erasing.has_value());
        REQUIRE(names(*before_erasing, "$name_v1"));
        auto const group = db::find_event_state_group(store, "$name_v2");
        REQUIRE(group.has_value());
        REQUIRE(store.state_groups.erase_if([&](db::PersistentStateGroup const& row) {
            return row.state_group_id == *group;
        }) == 1U);

        WHEN("the state before it is requested")
        {
            auto const result = fed::build_state_ids_response(store, room_id, "$name_v2", origin);

            THEN("it is not found rather than answered from the fork it cites")
            {
                REQUIRE(result.status == fed::RoomReadStatus::not_found);
            }
        }
    }

    // A recorded state with a hole (a missing event) or a rejected event must not be served as the room's state.
    GIVEN("a recorded state that names an event the store lacks, or a rejected one")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$name_forged", {"$join"}, 3U, "rejected"));
        auto const ghost_group = db::create_or_reuse_state_group(store, room_id, "sg:ghost", std::nullopt,
                                                                 {
                                                                     {"", "m.room.name", "", "$ghost"}
        });
        auto const rejected_group = db::create_or_reuse_state_group(store, room_id, "sg:rejected", std::nullopt,
                                                                    {
                                                                        {"", "m.room.name", "", "$name_forged"}
        });
        REQUIRE(ghost_group.has_value());
        REQUIRE(rejected_group.has_value());
        // The two bad groups are attached to messages, whose state before them is their own recorded group.
        // Two messages whose recorded state is the bad group (a message's state before it is its own).
        store.events.push_back(make_event(message_event("$on_ghost", {"$join"}, 5U)));
        REQUIRE(db::set_event_state_group(store, "$on_ghost", *ghost_group));
        store.events.push_back(make_event(message_event("$on_rejected", {"$join"}, 5U)));
        REQUIRE(db::set_event_state_group(store, "$on_rejected", *rejected_group));

        WHEN("the state is requested at an event with that recorded state")
        {
            auto const ghost = fed::build_state_ids_response(store, room_id, "$on_ghost", origin);
            auto const rejected = fed::build_state_ids_response(store, room_id, "$on_rejected", origin);

            THEN("it is not found: a state with a hole or a rejected event is not served")
            {
                REQUIRE(ghost.status == fed::RoomReadStatus::not_found);
                REQUIRE(rejected.status == fed::RoomReadStatus::not_found);
            }
        }
    }
}

// A room joined over federation holds the remote history as outliers with no recorded state; its own
// state starts at the join event's synthetic group (ADR-0064).
SCENARIO("A room joined over federation answers state from the join onwards and never from the outliers",
         "[federation][events][state][state-at-event]")
{
    GIVEN("a joined room whose pre-join history is outliers with an inflated depth, and a message after the join")
    {
        auto store = db::PersistentStore{};
        auto create = NewEvent{"$r_create", "m.room.create", "", {}, 1U, "outlier", R"({"room_version":"11"})"};
        auto name = name_event("$r_name", {"$r_create"}, 2U, "outlier");
        auto forged = name_event("$r_forged", {"$r_name"}, max_depth, "outlier");
        store.events.push_back(make_event(create));
        store.events.push_back(make_event(name));
        store.events.push_back(make_event(forged));
        auto const join = NewEvent{"$join", "m.room.member", std::string{sender},       {"$r_forged"},
                                   3U,      "accepted",      R"({"membership":"join"})"};
        store.events.push_back(make_event(join));
        // The join's recorded state is the one the send_join response gave: create and name, then the join.
        auto const state_after = std::vector<db::PersistentStateGroupStateEntry>{
            {"", "m.room.create", "",                  "$r_create"},
            {"", "m.room.name",   "",                  "$r_name"  },
            {"", "m.room.member", std::string{sender}, "$join"    },
        };
        REQUIRE(hs::record_event_state_with_parent(store, room_id, "$join", {"$r_forged"}, std::nullopt, state_after)
                    .has_value());
        ingest(store, message_event("$after_join", {"$join"}, 4U));
        store.state.push_back({std::string{room_id}, "m.room.create", "", "$r_create"});
        store.state.push_back({std::string{room_id}, "m.room.member", std::string{sender}, "$join"});

        WHEN("the state IDs at the message after the join are requested")
        {
            auto const body = state_ids_body(store, "$after_join");

            THEN("they are the state recorded at the join")
            {
                REQUIRE(body.has_value());
                REQUIRE(names(*body, "$r_create"));
                REQUIRE(names(*body, "$r_name"));
                REQUIRE(names(*body, "$join"));
                REQUIRE_FALSE(names(*body, "$r_forged"));
            }
        }

        WHEN("the state at that message is resolved for a client")
        {
            auto const ids = fed::resolve_state_event_ids_at(store, room_id, "$after_join");

            THEN("it is the same state")
            {
                REQUIRE(contains(ids, "$r_name"));
                REQUIRE(contains(ids, "$join"));
                REQUIRE_FALSE(contains(ids, "$r_forged"));
            }
        }

        WHEN("the state is requested at the join itself, whose prev_events this server does not hold")
        {
            auto const result = fed::build_state_ids_response(store, room_id, "$join", origin);

            THEN("it is not found")
            {
                REQUIRE(result.status == fed::RoomReadStatus::not_found);
            }
        }
    }
}

// F-26: the cost of a request is the state groups on at most two chains and the state returned, not the room's
// history. The count is what `state_before_event` reports: the stored events whose JSON it parsed.
SCENARIO("The state at an event costs the same however long the room's history is",
         "[federation][events][state][state-at-event][security]")
{
    GIVEN("two rooms with the same state, one with 10 messages after it and one with 3000")
    {
        auto const build = [](std::size_t messages) {
            auto store = room_with_creator();
            ingest(store, name_event("$name", {"$join"}, 3U));
            auto previous = std::string{"$name"};
            for (auto i = std::size_t{0U}; i < messages; ++i)
            {
                auto id = "$m" + std::to_string(i);
                ingest(store, message_event(id, {previous}, 4U + i));
                previous = std::move(id);
            }
            return std::pair{std::move(store), previous};
        };
        auto const [short_room, short_tip] = build(10U);
        auto const [long_room, long_tip] = build(3000U);

        WHEN("the state before the newest message is read in each")
        {
            auto const short_state = fed::state_before_event(short_room, room_id, short_tip);
            auto const long_state = fed::state_before_event(long_room, room_id, long_tip);

            THEN("each parses one event, resolves nothing, and returns the same state")
            {
                REQUIRE(short_state.known);
                REQUIRE(long_state.known);
                REQUIRE(short_state.events_parsed == 1U);
                REQUIRE(long_state.events_parsed == short_state.events_parsed);
                REQUIRE_FALSE(short_state.resolved);
                REQUIRE_FALSE(long_state.resolved);
                REQUIRE(long_state.event_ids.size() == short_state.event_ids.size());
            }
        }
    }

    GIVEN("a state event whose prev_events are two branches")
    {
        auto store = room_with_creator();
        ingest(store, name_event("$a", {"$join"}, 3U));
        ingest(store, {"$b", "m.room.topic", "", {"$join"}, 3U, "accepted", R"({"topic":"t"})"});
        ingest(store, {
                          "$merge", "m.room.canonical_alias", "", {"$a", "$b"},
                             4U, "accepted", "{}"
        });

        WHEN("the state before it is read")
        {
            auto const merged = fed::state_before_event(store, room_id, "$merge");

            THEN("it is resolved, and says so")
            {
                REQUIRE(merged.known);
                REQUIRE(merged.resolved);
            }
        }
    }
}
