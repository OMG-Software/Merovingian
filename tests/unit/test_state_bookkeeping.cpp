// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for ADR-0064 phase B1: state-before/state-after computation (and ADR-0694: the state before is
// resolved and stored once per set of prev groups),
// delta-state-group recording, and current-state-as-cache-of-resolution,
// against an in-memory PersistentStore (PersistentStoreBackend::memory —
// commit_persistent_transaction is a trivial success for this backend).
//
// These tests exercise merovingian::homeserver::compute_state_before /
// compute_state_after / record_event_state / recompute_current_state
// directly — the same functions src/homeserver/LocalHttpRouter.cpp's
// ingest_pdu_event wires into the inbound PDU path. See
// docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md and
// tests/integration/test_pdu_ingestion_state_groups_flow.cpp for the end-to-end proof
// through ingest_pdu_event itself.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU" (state resolution determines "current state", not
// arrival order).

#include "merovingian/config/Config.hpp"
#include "merovingian/config/FederationStateResolutionConfig.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/StateEventReference.hpp"
#include "merovingian/events/StateResolutionRequest.hpp"
#include "merovingian/events/StateResolution.hpp"
#include "merovingian/homeserver/CurrentStateRecomputeStatus.hpp"
#include "merovingian/homeserver/EventBookkeeping.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStateGroupStateEntry;
using merovingian::database::PersistentStore;
using merovingian::homeserver::compute_state_after;
using merovingian::homeserver::compute_state_before;
using merovingian::homeserver::CurrentStateRecomputeStatus;
using merovingian::homeserver::recompute_current_state;
using merovingian::homeserver::record_event_state;

auto const room_id = std::string{"!room:example.org"};

// Builds a flat state-event JSON body: type/state_key/sender/event_id/
// origin_server_ts/auth_events/content. Mirrors the shape
// tests/unit/test_state_resolution_auth_diff.cpp's make_ref() uses (a
// pattern already proven to satisfy resolve_state_v2's internal auth
// checks), since homeserver::make_store_event_lookup parses events in
// exactly this shape.
[[nodiscard]] auto make_event_json(std::string const& event_type, std::string const& state_key,
                                   std::string const& event_id, std::string const& sender, std::int64_t ts,
                                   std::vector<std::string> const& auth_ids, std::string const& content_json)
    -> std::string
{
    auto auth = std::string{"["};
    for (auto const& id : auth_ids)
    {
        if (auth.size() > 1U)
        {
            auth += ",";
        }
        auth += "\"" + id + "\"";
    }
    auth += "]";
    return std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key + "\",\"sender\":\"" + sender +
           "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
           ",\"auth_events\":" + auth + ",\"content\":" + content_json + "}";
}

// Stores an event and (unless `prev` is empty) records its state via
// record_event_state, chaining off `prev`'s own state. Fails the calling
// test (via REQUIRE) if state-before cannot be determined or the state
// group write fails — every call site in these scenarios expects success
// except where a scenario explicitly tests the failure path.
auto ingest_test_event(PersistentStore& store, std::string const& event_id, std::string const& event_type,
                       std::optional<std::string> const& state_key, std::string const& sender, std::int64_t ts,
                       std::vector<std::string> const& auth_ids, std::string const& content_json,
                       std::vector<std::string> const& prev, std::uint64_t depth,
                       merovingian::rooms::RoomVersionPolicy const& policy, std::uint64_t stream_ordering = 0U) -> void
{
    auto event = PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = sender;
    event.json = make_event_json(event_type, state_key.value_or(""), event_id, sender, ts, auth_ids, content_json);
    event.depth = depth;
    event.stream_ordering = stream_ordering;
    event.prev_event_ids = prev;
    store.events.push_back(event);

    auto const state_before = compute_state_before(store, room_id, policy, prev);
    REQUIRE(state_before.ok);
    auto const state_after = compute_state_after(state_before.state, event_id, event_type, state_key);
    auto const group = record_event_state(store, room_id, event_id, prev, state_after);
    REQUIRE(group.has_value());
}

[[nodiscard]] auto topic_winner(PersistentStore const& store) -> std::string
{
    for (auto const& entry : store.state)
    {
        if (entry.room_id == room_id && entry.event_type == "m.room.topic" && entry.state_key.empty())
        {
            return entry.event_id;
        }
    }
    return {};
}

auto const pl_content = std::string{
    R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":0,"users_default":0,"users":{"@alice:example.org":100}})"};

// Builds a linear genesis (create -> power_levels -> join_rules ->
// alice_join) ending in a single forward extremity, using the module under
// test at every step (not seeded around it) so genesis itself exercises
// record_event_state for a non-forking chain.
auto seed_genesis(PersistentStore& store, merovingian::rooms::RoomVersionPolicy const& policy) -> void
{
    ingest_test_event(store, "$create", "m.room.create", std::string{}, "@alice:example.org", 1, {},
                      R"({"creator":"@alice:example.org","room_version":"10"})", {}, 0U, policy);
    ingest_test_event(store, "$pl0", "m.room.power_levels", std::string{}, "@alice:example.org", 10, {"$create"},
                      pl_content, {"$create"}, 1U, policy);
    ingest_test_event(store, "$join_rules", "m.room.join_rules", std::string{}, "@alice:example.org", 20,
                      {"$create", "$pl0"}, R"({"join_rule":"public"})", {"$pl0"}, 2U, policy);
    ingest_test_event(store, "$alice_join", "m.room.member", std::string{"@alice:example.org"}, "@alice:example.org",
                      30, {"$create"}, R"({"membership":"join"})", {"$join_rules"}, 3U, policy);
}

} // namespace

SCENARIO("Delivery-order independence: two concurrent state forks resolve identically regardless of arrival order",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("two independent stores seeded with the same room history")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store_ab = PersistentStore{};
        seed_genesis(store_ab, *policy);
        auto store_ba = PersistentStore{};
        seed_genesis(store_ba, *policy);

        WHEN("two conflicting m.room.topic events on the same parent are ingested in opposite orders")
        {
            ingest_test_event(store_ab, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                              {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
            ingest_test_event(store_ab, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200,
                              {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);

            ingest_test_event(store_ba, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200,
                              {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
            ingest_test_event(store_ba, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                              {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);

            THEN("both are recorded as forward extremities (a genuine fork, not last-writer-wins)")
            {
                auto ext_ab = merovingian::database::find_forward_extremities(store_ab, room_id);
                auto ext_ba = merovingian::database::find_forward_extremities(store_ba, room_id);
                std::ranges::sort(ext_ab);
                std::ranges::sort(ext_ba);
                REQUIRE(ext_ab == std::vector<std::string>{"$topic_a", "$topic_b"});
                REQUIRE(ext_ba == std::vector<std::string>{"$topic_a", "$topic_b"});
            }

            AND_WHEN("current state is recomputed (the resolution over the forward extremities) in each store")
            {
                REQUIRE(recompute_current_state(store_ab, room_id, *policy));
                REQUIRE(recompute_current_state(store_ba, room_id, *policy));

                THEN("the resolved m.room.topic winner is identical in both, independent of arrival order")
                {
                    auto const winner_ab = topic_winner(store_ab);
                    auto const winner_ba = topic_winner(store_ba);
                    REQUIRE_FALSE(winner_ab.empty());
                    REQUIRE(winner_ab == winner_ba);

                    // Cross-check against resolve_state_v2 called directly
                    // (not through the module under test) on the same two
                    // forks, so this does not merely prove ingestion is
                    // self-consistent — it proves it agrees with the spec's
                    // algorithm's own answer.
                    auto const group_a = merovingian::database::find_event_state_group(store_ab, "$topic_a");
                    auto const group_b = merovingian::database::find_event_state_group(store_ab, "$topic_b");
                    REQUIRE(group_a.has_value());
                    REQUIRE(group_b.has_value());
                    auto const full_a = merovingian::database::read_state_group_full_state(store_ab, *group_a);
                    auto const full_b = merovingian::database::read_state_group_full_state(store_ab, *group_b);
                    REQUIRE(full_a.has_value());
                    REQUIRE(full_b.has_value());
                    auto const lookup = merovingian::homeserver::make_store_event_lookup(store_ab);
                    auto refs_a = std::vector<merovingian::events::StateEventReference>{};
                    auto refs_b = std::vector<merovingian::events::StateEventReference>{};
                    for (auto const& e : *full_a)
                    {
                        auto ref = lookup(e.event_id);
                        REQUIRE(ref.has_value());
                        refs_a.push_back(*ref);
                    }
                    for (auto const& e : *full_b)
                    {
                        auto ref = lookup(e.event_id);
                        REQUIRE(ref.has_value());
                        refs_b.push_back(*ref);
                    }
                    auto oracle_request = merovingian::events::StateResolutionRequest{};
                    oracle_request.room_version = std::string{policy->id};
                    oracle_request.state_groups = {
                        {"a", refs_a},
                        {"b", refs_b}
                    };
                    oracle_request.event_lookup = lookup;
                    auto const oracle = merovingian::events::resolve_state_v2(oracle_request, *policy);
                    REQUIRE(oracle.resolved);
                    auto const oracle_topic = std::ranges::find_if(
                        oracle.resolved_state, [](merovingian::events::StateEventReference const& r) {
                            return r.key.event_type == "m.room.topic" && r.key.state_key.empty();
                        });
                    REQUIRE(oracle_topic != oracle.resolved_state.end());
                    REQUIRE(oracle_topic->event_id == winner_ab);
                }
            }
        }
    }
}

SCENARIO("A merge event's state before it is the resolution of both fork tips' after-states",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a room forked into two conflicting m.room.topic tips")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
        ingest_test_event(store, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);

        REQUIRE(recompute_current_state(store, room_id, *policy));
        auto const winner_before_merge = topic_winner(store);
        REQUIRE_FALSE(winner_before_merge.empty());

        WHEN("a message event with both tips as prev_events is ingested")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$topic_a", "$topic_b"});

            THEN("its state before is the resolution of both tips, matching the room's current-state resolution")
            {
                REQUIRE(state_before.ok);
                auto const it = std::ranges::find_if(state_before.state, [](PersistentStateGroupStateEntry const& e) {
                    return e.event_type == "m.room.topic" && e.state_key.empty();
                });
                REQUIRE(it != state_before.state.end());
                REQUIRE(it->event_id == winner_before_merge);
            }

            AND_WHEN("the merge event is recorded and current state recomputed")
            {
                ingest_test_event(store, "$merge", "m.room.message", std::nullopt, "@alice:example.org", 300, {},
                                  R"({"body":"merged"})", {"$topic_a", "$topic_b"}, 5U, *policy);

                THEN("the merge collapses both forward extremities into one")
                {
                    auto const extremities = merovingian::database::find_forward_extremities(store, room_id);
                    REQUIRE(extremities.size() == 1U);
                    REQUIRE(extremities.front() == "$merge");
                }

                THEN("current state after the merge still reflects the resolved topic winner")
                {
                    REQUIRE(recompute_current_state(store, room_id, *policy));
                    REQUIRE(topic_winner(store) == winner_before_merge);
                }
            }
        }
    }
}

SCENARIO("Configured state-resolution budgets constrain fork resolution without partial cache updates",
         "[pdu_ingestion][state_groups][limits]")
{
    GIVEN("a fork whose state groups exceed a custom per-group event budget")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
        ingest_test_event(store, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);

        REQUIRE(recompute_current_state(store, room_id, *policy));
        auto const cached_topic = topic_winner(store);
        auto const cached_state = store.state;
        auto config = merovingian::config::FederationStateResolutionConfig{};
        config.max_events_per_state_group = 3U;
        auto const limits = merovingian::homeserver::state_resolution_limits(config);

        WHEN("state-before and cached current-state resolution use the configured policy")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$topic_a", "$topic_b"}, limits);
            auto const recomputed = recompute_current_state(store, room_id, *policy, limits);

            THEN("over-cap resolution fails closed, says it was refused, and leaves cached state untouched")
            {
                REQUIRE(limits.max_state_groups == config.max_state_groups);
                REQUIRE(limits.max_events_per_state_group == 3U);
                REQUIRE(limits.max_conflicted_state_keys == config.max_conflicted_state_keys);
                REQUIRE(limits.max_mainline_auth_chain_depth == config.max_mainline_auth_chain_depth);
                REQUIRE(limits.max_auth_chain_walk_events == config.max_auth_chain_walk_events);
                REQUIRE(limits.max_total_state_events == config.max_total_state_events);
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(recomputed.status == CurrentStateRecomputeStatus::refused);
                REQUIRE_FALSE(recomputed);
                REQUIRE_FALSE(recomputed.reason.empty());
                REQUIRE(topic_winner(store) == cached_topic);
                REQUIRE(std::ranges::equal(store.state, cached_state, [](auto const& current, auto const& previous) {
                    return current.room_id == previous.room_id && current.event_type == previous.event_type &&
                           current.state_key == previous.state_key && current.event_id == previous.event_id;
                }));
            }
        }
    }
}

SCENARIO("Every stored event has an after-state group whose full state is correct", "[pdu_ingestion][state_groups]")
{
    GIVEN("a room with a fork")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);

        THEN("$alice_join's after-state has exactly create+power_levels+join_rules+member")
        {
            auto const group = merovingian::database::find_event_state_group(store, "$alice_join");
            REQUIRE(group.has_value());
            auto const full = merovingian::database::read_state_group_full_state(store, *group);
            REQUIRE(full.has_value());
            REQUIRE(full->size() == 4U);
        }

        THEN("$topic_a's after-state adds m.room.topic on top of $alice_join's four entries")
        {
            auto const group = merovingian::database::find_event_state_group(store, "$topic_a");
            REQUIRE(group.has_value());
            auto const full = merovingian::database::read_state_group_full_state(store, *group);
            REQUIRE(full.has_value());
            REQUIRE(full->size() == 5U);
            auto const it = std::ranges::find_if(*full, [](PersistentStateGroupStateEntry const& e) {
                return e.event_type == "m.room.topic";
            });
            REQUIRE(it != full->end());
            REQUIRE(it->event_id == "$topic_a");
        }
    }
}

SCENARIO("A PDU whose prev_event has no recorded state group is not stored and does not corrupt state",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a room whose genesis is recorded")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store = PersistentStore{};
        seed_genesis(store, *policy);

        WHEN("computing state before an event whose prev_event was never recorded")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$never_seen"});

            THEN("it fails closed rather than substituting current state")
            {
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(state_before.state.empty());
            }
        }

        WHEN("one of several prev_events lacks a state group")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$alice_join", "$never_seen"});

            THEN("it still fails closed even though the other prev_event resolves fine")
            {
                REQUIRE_FALSE(state_before.ok);
            }
        }
    }
}

// Spec: server-server-api.md, "PDUs": prev_events are "the most recent events in the room". An
// event of another room says nothing about this room's state, even when its state group is present.
SCENARIO("compute_state_before refuses a prev_event or a state group of another room",
         "[pdu_ingestion][state_groups][security][f01]")
{
    GIVEN("a room whose genesis is recorded and an event of another room with state of its own")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto store = PersistentStore{};
        seed_genesis(store, *policy);

        auto const other_room = std::string{"!other:example.org"};
        auto foreign = PersistentEvent{};
        foreign.event_id = "$foreign_tip";
        foreign.room_id = other_room;
        foreign.sender_user_id = "@mallory:example.org";
        foreign.json = make_event_json("m.room.topic", "", "$foreign_tip", "@mallory:example.org", 40, {}, "{}");
        store.events.push_back(foreign);
        auto const foreign_group =
            merovingian::database::create_or_reuse_state_group(store, other_room, "foreign-group", std::nullopt,
                                                               {
                                                                   {"", "m.room.topic", "", "$foreign_tip"}
        });
        REQUIRE(foreign_group.has_value());
        REQUIRE(merovingian::database::set_event_state_group(store, "$foreign_tip", *foreign_group));

        WHEN("it is the only prev_event")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$foreign_tip"});

            THEN("nothing is computed, and the reason names the other room")
            {
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(state_before.state.empty());
                REQUIRE(state_before.reason.find("another room") != std::string::npos);
            }
        }

        WHEN("it is one of two prev_events and the other is of this room")
        {
            auto const state_before = compute_state_before(store, room_id, *policy, {"$alice_join", "$foreign_tip"});

            THEN("the merge is refused as a whole")
            {
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(state_before.reason.find("another room") != std::string::npos);
            }
        }

        WHEN("an event of this room is mapped to a state group of the other room")
        {
            auto local = PersistentEvent{};
            local.event_id = "$mismapped";
            local.room_id = room_id;
            local.sender_user_id = "@alice:example.org";
            local.json = make_event_json("m.room.topic", "", "$mismapped", "@alice:example.org", 50, {}, "{}");
            store.events.push_back(local);
            REQUIRE(merovingian::database::set_event_state_group(store, "$mismapped", *foreign_group));

            auto const state_before = compute_state_before(store, room_id, *policy, {"$mismapped"});

            THEN("the group is not read as this room's state")
            {
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(state_before.state.empty());
                REQUIRE(state_before.reason.find("another room") != std::string::npos);
            }
        }
    }
}

namespace
{

// A fork of the genesis tip into two m.room.topic events, both recorded.
auto seed_topic_fork(PersistentStore& store, merovingian::rooms::RoomVersionPolicy const& policy) -> void
{
    seed_genesis(store, policy);
    ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100, {"$create", "$pl0"},
                      "{}", {"$alice_join"}, 4U, policy);
    ingest_test_event(store, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200, {"$create", "$pl0"},
                      "{}", {"$alice_join"}, 4U, policy);
}

// An m.room.message composed on `prev_event_ids`, as persist_composed_event
// hands one to store_local_event.
[[nodiscard]] auto local_message(std::string const& event_id, std::vector<std::string> const& prev_event_ids)
    -> PersistentEvent
{
    auto event = PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = "@alice:example.org";
    event.json = std::string{R"({"type":"m.room.message","sender":"@alice:example.org","content":{}})"};
    event.depth = 5U;
    event.prev_event_ids = prev_event_ids;
    return event;
}

[[nodiscard]] auto event_is_stored(PersistentStore const& store, std::string const& event_id) -> bool
{
    return store.events.find(event_id) != store.events.end();
}

} // namespace

SCENARIO("compute_state_before says why it fails closed", "[pdu_ingestion][state_groups][limits]")
{
    GIVEN("a room forked into two recorded m.room.topic tips")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_topic_fork(store, *policy);

        WHEN("a prev_event's state group is gone from the store")
        {
            auto const group = merovingian::database::find_event_state_group(store, "$topic_a");
            REQUIRE(group.has_value());
            std::ignore = store.state_groups.erase_if([&group](auto const& g) {
                return g.state_group_id == *group;
            });
            auto const alone = compute_state_before(store, room_id, *policy, {"$topic_a"});
            auto const both = compute_state_before(store, room_id, *policy, {"$topic_a", "$topic_b"});

            THEN("it fails closed with a reason, alone or beside another prev_event")
            {
                REQUIRE_FALSE(alone.ok);
                REQUIRE_FALSE(alone.reason.empty());
                REQUIRE_FALSE(both.ok);
                REQUIRE_FALSE(both.reason.empty());
            }
        }

        WHEN("a prev_event's state names an event the store does not hold")
        {
            store.events.push_back(local_message("$names_a_ghost", {"$alice_join"}));
            auto const join_group = merovingian::database::find_event_state_group(store, "$alice_join");
            REQUIRE(join_group.has_value());
            auto state_after = merovingian::database::read_state_group_full_state(store, *join_group);
            REQUIRE(state_after.has_value());
            state_after->push_back({{}, "m.room.name", "", "$ghost_name"});
            REQUIRE(record_event_state(store, room_id, "$names_a_ghost", {"$alice_join"}, *state_after).has_value());
            auto const result = compute_state_before(store, room_id, *policy, {"$topic_a", "$names_a_ghost"});

            THEN("it fails closed with a reason rather than resolve a partial state")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.reason.empty());
            }
        }

        WHEN("the states exceed the per-group state-resolution budget")
        {
            auto config = merovingian::config::FederationStateResolutionConfig{};
            config.max_events_per_state_group = 3U;
            auto const result = compute_state_before(store, room_id, *policy, {"$topic_a", "$topic_b"},
                                                     merovingian::homeserver::state_resolution_limits(config));

            THEN("it fails closed with a reason")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.reason.empty());
            }
        }

        WHEN("the resolution itself is refused by its conflicted-key budget")
        {
            auto config = merovingian::config::FederationStateResolutionConfig{};
            config.max_conflicted_state_keys = 0U;
            auto const result = compute_state_before(store, room_id, *policy, {"$topic_a", "$topic_b"},
                                                     merovingian::homeserver::state_resolution_limits(config));

            THEN("it fails closed with a reason")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

SCENARIO("basis_for_new_event builds on the newest forward extremity whose state reads alone",
         "[pdu_ingestion][state_groups][leave]")
{
    GIVEN("a room whose recorded tip sits beside a newer extremity with no recorded state")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
        auto orphan = local_message("$orphan", {"$topic_a"});
        orphan.stream_ordering = 1000U;
        store.events.push_back(orphan);
        REQUIRE(merovingian::database::update_forward_extremities(store, room_id, "$orphan", {}, true));

        WHEN("the basis of a new local event is chosen")
        {
            auto const basis = merovingian::homeserver::basis_for_new_event(store, room_id, *policy);

            THEN("it skips the newer extremity, cites the recorded tip, and retires the other")
            {
                REQUIRE(basis.ok);
                REQUIRE(basis.prev_event_ids == std::vector<std::string>{"$topic_a"});
                REQUIRE(basis.retired_extremities == std::vector<std::string>{"$orphan"});
                REQUIRE_FALSE(basis.state_before.empty());
            }
        }
    }

    GIVEN("a room whose only forward extremities have no recorded state")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        REQUIRE(merovingian::database::update_forward_extremities(store, room_id, "$ghost_a", {}, true));
        REQUIRE(merovingian::database::update_forward_extremities(store, room_id, "$ghost_b", {}, true));

        WHEN("the basis of a new local event is chosen")
        {
            auto const basis = merovingian::homeserver::basis_for_new_event(store, room_id, *policy);

            THEN("there is none, and it says why")
            {
                REQUIRE_FALSE(basis.ok);
                REQUIRE_FALSE(basis.reason.empty());
                REQUIRE(basis.retired_extremities.empty());
            }
        }
    }
}

SCENARIO("store_local_event refuses a local event it cannot place, and leaves the room's tips alone",
         "[pdu_ingestion][state_groups][leave]")
{
    GIVEN("a room with a recorded genesis and the basis of a new local event")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        auto const basis = merovingian::homeserver::basis_for_new_event(store, room_id, *policy);
        REQUIRE(basis.ok);
        auto const tips_before = merovingian::database::find_forward_extremities(store, room_id);

        WHEN("the event cites prev_events other than the ones its basis resolved")
        {
            auto const stored = merovingian::homeserver::store_local_event(
                store, *policy, local_message("$mismatched", {"$pl0"}), std::nullopt, basis);

            THEN("it is refused and not stored")
            {
                REQUIRE_FALSE(stored);
                REQUIRE_FALSE(event_is_stored(store, "$mismatched"));
                REQUIRE(merovingian::database::find_forward_extremities(store, room_id) == tips_before);
            }
        }

        WHEN("the event's ID is already stored")
        {
            auto const stored = merovingian::homeserver::store_local_event(
                store, *policy, local_message("$join_rules", basis.prev_event_ids), std::nullopt, basis);

            THEN("it is refused and the room's tips are unchanged")
            {
                REQUIRE_FALSE(stored);
                REQUIRE(merovingian::database::find_forward_extremities(store, room_id) == tips_before);
            }
        }

        // ADR-0228: the event, its after-state group, its mapping to that
        // group, the forward-extremity change and current state commit in one
        // transaction, so a write refused at any of them leaves none of them.
        auto const state_rows_before = store.state.size();
        auto const state_transitions_before = store.state_transitions.size();
        auto const nothing_left_of = [&store, &tips_before, state_rows_before,
                                      state_transitions_before](std::string const& event_id) {
            REQUIRE_FALSE(event_is_stored(store, event_id));
            REQUIRE_FALSE(merovingian::database::find_event_state_group(store, event_id).has_value());
            REQUIRE_FALSE(merovingian::database::find_state_group(store, "sg:" + event_id).has_value());
            REQUIRE(merovingian::database::find_forward_extremities(store, room_id) == tips_before);
            REQUIRE(store.state.size() == state_rows_before);
            REQUIRE(store.state_transitions.size() == state_transitions_before);
        };

        WHEN("the write mapping it to its after-state group is refused")
        {
            store.force_failure_statement_names.insert("upsert_event_state_group");
            auto const stored = merovingian::homeserver::store_local_event(
                store, *policy, local_message("$no_group", basis.prev_event_ids), std::nullopt, basis);

            THEN("it is refused, and nothing of it is left: no event, no group, no new tip")
            {
                REQUIRE_FALSE(stored);
                nothing_left_of("$no_group");
            }
        }

        WHEN("the write moving the room's forward extremities is refused")
        {
            store.force_failure_statement_names.insert("insert_forward_extremity");
            auto const stored = merovingian::homeserver::store_local_event(
                store, *policy, local_message("$no_tip", basis.prev_event_ids), std::nullopt, basis);

            THEN("it is refused, and nothing of it is left")
            {
                REQUIRE_FALSE(stored);
                nothing_left_of("$no_tip");
            }
        }

        WHEN("current state cannot be written after it")
        {
            // The fixture never recomputed current state, so recording the
            // event's after-state must write every entry.
            store.force_failure_statement_names.insert("insert_state");
            store.force_failure_statement_names.insert("upsert_state");
            auto const stored = merovingian::homeserver::store_local_event(
                store, *policy, local_message("$no_current_state", basis.prev_event_ids), std::nullopt, basis);

            THEN("it is refused, and nothing of it is left")
            {
                REQUIRE_FALSE(stored);
                nothing_left_of("$no_current_state");
            }
        }
    }
}

// F-40 (ADR-0373): the state before a fallback event is the room's current state, not one fork's.
// Spec: server-server-api.md, "Soft failure": current state is the state resolved across the
// forward extremities; a failure to resolve them must not give a banned user the old state back.
SCENARIO("A local event built on the fallback extremity keeps the ban that fork predates",
         "[pdu_ingestion][state_groups][fallback][f40]")
{
    GIVEN("a room with a ban tip and a newer fork that predates the ban, whose tips cannot be resolved")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$bob_join", "m.room.member", std::string{"@bob:example.org"}, "@bob:example.org", 40,
                          {"$create", "$join_rules"}, R"({"membership":"join"})", {"$alice_join"}, 4U, *policy, 10U);
        ingest_test_event(store, "$ban", "m.room.member", std::string{"@bob:example.org"}, "@alice:example.org", 50,
                          {"$create", "$pl0", "$alice_join", "$bob_join"}, R"({"membership":"ban"})", {"$bob_join"}, 5U,
                          *policy, 20U);
        ingest_test_event(store, "$fork", "m.room.topic", std::string{}, "@bob:example.org", 60,
                          {"$create", "$pl0", "$bob_join"}, "{}", {"$bob_join"}, 5U, *policy, 30U);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        auto const bob_member = [&store]() {
            return merovingian::database::find_current_state_event_id(store, room_id, "m.room.member",
                                                                      "@bob:example.org");
        };
        REQUIRE(bob_member() == std::optional<std::string>{"$ban"});

        auto config = merovingian::config::FederationStateResolutionConfig{};
        config.max_conflicted_state_keys = 0U;
        auto const limits = merovingian::homeserver::state_resolution_limits(config);
        REQUIRE_FALSE(compute_state_before(store, room_id, *policy, {"$ban", "$fork"}, limits).ok);

        WHEN("the basis of a new local event is chosen")
        {
            auto const basis = merovingian::homeserver::basis_for_new_event(store, room_id, *policy, limits);

            THEN("it cites the newest tip, retires the ban tip, and its state before still holds the ban")
            {
                REQUIRE(basis.ok);
                REQUIRE(basis.prev_event_ids == std::vector<std::string>{"$fork"});
                REQUIRE(basis.retired_extremities == std::vector<std::string>{"$ban"});
                auto const held = std::ranges::find_if(basis.state_before, [](auto const& entry) {
                    return entry.event_type == "m.room.member" && entry.state_key == "@bob:example.org";
                });
                REQUIRE(held != basis.state_before.end());
                REQUIRE(held->event_id == "$ban");
            }
        }

        WHEN("a local event is stored on that basis, and the room's current state is then recomputed")
        {
            auto const basis = merovingian::homeserver::basis_for_new_event(store, room_id, *policy, limits);
            REQUIRE(basis.ok);
            REQUIRE(merovingian::homeserver::store_local_event(store, *policy, local_message("$local", {"$fork"}),
                                                               std::nullopt, basis, limits));
            auto const recomputed = recompute_current_state(store, room_id, *policy, limits);

            THEN("the banned user is still banned in current state")
            {
                REQUIRE(recomputed);
                REQUIRE(bob_member() == std::optional<std::string>{"$ban"});
            }

            THEN("the local event's own state group records the ban, so a later single-tip recompute keeps it")
            {
                auto const group = merovingian::database::find_event_state_group(store, "$local");
                REQUIRE(group.has_value());
                auto const full_state = merovingian::database::read_state_group_full_state(store, *group);
                REQUIRE(full_state.has_value());
                auto const held = std::ranges::find_if(*full_state, [](auto const& entry) {
                    return entry.event_type == "m.room.member" && entry.state_key == "@bob:example.org";
                });
                REQUIRE(held != full_state->end());
                REQUIRE(held->event_id == "$ban");
                REQUIRE(merovingian::database::find_forward_extremities(store, room_id) ==
                        std::vector<std::string>{"$local"});
            }
        }
    }
}

// F-49 (ADR-0375): a refusal is a status, not a success.
SCENARIO("A refused recomputation of current state is reported and writes nothing",
         "[pdu_ingestion][state_groups][f49]")
{
    GIVEN("a room whose forward extremities include one with no recorded state")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        REQUIRE(merovingian::database::update_forward_extremities(store, room_id, "$ghost", {}, true));
        auto const rows_before = store.state.size();
        auto const transitions_before = store.state_transitions.size();

        WHEN("current state is recomputed")
        {
            auto const recomputed = recompute_current_state(store, room_id, *policy);

            THEN("it is refused with a reason, and no current_state row is written")
            {
                REQUIRE(recomputed.status == CurrentStateRecomputeStatus::refused);
                REQUIRE_FALSE(recomputed);
                REQUIRE(recomputed.reason.find("$ghost") != std::string::npos);
                REQUIRE(store.state.size() == rows_before);
                REQUIRE(store.state_transitions.size() == transitions_before);
            }
        }
    }

    GIVEN("a room with no forward extremity")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};

        WHEN("current state is recomputed")
        {
            auto const recomputed = recompute_current_state(store, room_id, *policy);

            THEN("there was nothing to resolve, which is not a refusal")
            {
                REQUIRE(recomputed.status == CurrentStateRecomputeStatus::resolved);
            }
        }
    }

    GIVEN("a local event stored beside a fork whose state cannot be resolved with it")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$topic_a", "m.room.topic", std::string{}, "@alice:example.org", 100,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
        ingest_test_event(store, "$topic_b", "m.room.topic", std::string{}, "@alice:example.org", 200,
                          {"$create", "$pl0"}, "{}", {"$alice_join"}, 4U, *policy);
        auto config = merovingian::config::FederationStateResolutionConfig{};
        config.max_conflicted_state_keys = 0U;
        auto const limits = merovingian::homeserver::state_resolution_limits(config);
        auto const before = compute_state_before(store, room_id, *policy, {"$topic_a"});
        REQUIRE(before.ok);
        auto bookkeeping = merovingian::homeserver::EventBookkeeping{};
        bookkeeping.state_after = before.state;
        bookkeeping.parent_state_group_id = merovingian::database::find_event_state_group(store, "$topic_a");
        bookkeeping.replaced_extremities = {"$topic_a"};

        WHEN("the event is stored")
        {
            auto const stored = merovingian::homeserver::store_event_with_bookkeeping(
                store, *policy, local_message("$beside", {"$topic_a"}), std::nullopt, std::nullopt, bookkeeping,
                limits);

            THEN("it is stored, and the result says the extremities could not be resolved")
            {
                REQUIRE(stored.ok);
                REQUIRE(stored.resolution_refused);
                REQUIRE_FALSE(stored.resolution_refusal.empty());
                REQUIRE(event_is_stored(store, "$beside"));
            }
        }
    }
}

// F-49 (ADR-0374): tips are bounded for events that add no state.
SCENARIO("forward_extremities_stay_bounded refuses only an event that would add a tip past the limit",
         "[pdu_ingestion][state_groups][f49]")
{
    GIVEN("a room holding as many forward extremities as the limit allows")
    {
        auto store = PersistentStore{};
        auto config = merovingian::config::FederationStateResolutionConfig{};
        config.max_state_groups = 3U;
        auto const limits = merovingian::homeserver::state_resolution_limits(config);
        for (auto const* tip : {"$t1", "$t2", "$t3"})
        {
            REQUIRE(merovingian::database::update_forward_extremities(store, room_id, tip, {}, true));
        }

        THEN("an event citing a tip replaces it and is allowed")
        {
            REQUIRE(merovingian::homeserver::forward_extremities_stay_bounded(store, room_id, {"$t2"}, limits));
            REQUIRE(merovingian::homeserver::forward_extremities_stay_bounded(store, room_id, {"$old", "$t1"}, limits));
        }

        THEN("an event citing only older events would add a tip, and is refused")
        {
            REQUIRE_FALSE(merovingian::homeserver::forward_extremities_stay_bounded(store, room_id, {"$old"}, limits));
        }

        THEN("another room's tips do not count")
        {
            REQUIRE(merovingian::homeserver::forward_extremities_stay_bounded(store, "!other:example.org", {"$old"},
                                                                              limits));
        }
    }

    GIVEN("a room holding fewer forward extremities than the limit")
    {
        auto store = PersistentStore{};
        auto config = merovingian::config::FederationStateResolutionConfig{};
        config.max_state_groups = 3U;
        auto const limits = merovingian::homeserver::state_resolution_limits(config);
        REQUIRE(merovingian::database::update_forward_extremities(store, room_id, "$t1", {}, true));

        THEN("an event citing only older events is allowed")
        {
            REQUIRE(merovingian::homeserver::forward_extremities_stay_bounded(store, room_id, {"$old"}, limits));
        }
    }
}

// ADR-0615. Spec: docs/matrix-v1.19-spec/server-server-api.md, "Room State Resolution": current state is the resolved
// state, so a key the resolution does not hold is not in it.
namespace
{

using merovingian::database::find_current_state_event_id;
using merovingian::database::for_each_room_state_row;

auto const carol = std::string{"@carol:example.org"};
auto const bob = std::string{"@bob:example.org"};
auto const demoting_pl_content = std::string{
    R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,"users":{"@alice:example.org":100}})"};

[[nodiscard]] auto room_row_count(PersistentStore const& store, std::string const& room) -> std::size_t
{
    auto rows = std::size_t{0U};
    for_each_room_state_row(store, room, [&rows](merovingian::database::PersistentStateEvent const&) {
        ++rows;
    });
    return rows;
}

[[nodiscard]] auto row_membership(PersistentStore const& store, std::string const& user) -> std::string
{
    auto const row = std::ranges::find_if(store.memberships, [&user](auto const& candidate) {
        return candidate.room_id == room_id && candidate.user_id == user;
    });
    return row == store.memberships.end() ? std::string{} : row->membership;
}

// Genesis, bob joined, then bob's m.room.name as the only tip: the name is current state. A demotion of bob on another
// fork then outranks it.
auto seed_name_set_on_a_fork(PersistentStore& store, merovingian::rooms::RoomVersionPolicy const& policy) -> void
{
    seed_genesis(store, policy);
    ingest_test_event(store, "$bob_join", "m.room.member", bob, bob, 40, {"$create", "$pl0", "$join_rules"},
                      R"({"membership":"join"})", {"$alice_join"}, 4U, policy);
    ingest_test_event(store, "$name", "m.room.name", std::string{}, bob, 50, {"$create", "$pl0", "$bob_join"},
                      R"({"name":"from the losing fork"})", {"$bob_join"}, 5U, policy);
    REQUIRE(recompute_current_state(store, room_id, policy));
    REQUIRE(find_current_state_event_id(store, room_id, "m.room.name", "") == "$name");
}

auto add_demotion_fork(PersistentStore& store, merovingian::rooms::RoomVersionPolicy const& policy) -> void
{
    ingest_test_event(store, "$pl1", "m.room.power_levels", std::string{}, "@alice:example.org", 60,
                      {"$create", "$pl0", "$alice_join"}, demoting_pl_content, {"$bob_join"}, 5U, policy);
}

} // namespace

SCENARIO("A key only a losing fork set leaves current state", "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("a room name set by a user another fork demotes")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_name_set_on_a_fork(store, *policy);
        auto const rows_before = room_row_count(store, room_id);

        WHEN("current state is recomputed over both forks")
        {
            add_demotion_fork(store, *policy);
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the name is gone and the demotion is current")
            {
                CHECK_FALSE(find_current_state_event_id(store, room_id, "m.room.name", "").has_value());
                CHECK(find_current_state_event_id(store, room_id, "m.room.power_levels", "") == "$pl1");
                CHECK(room_row_count(store, room_id) == rows_before - 1U);
                CHECK(std::ranges::none_of(store.state, [](auto const& row) {
                    return row.event_type == "m.room.name";
                }));
            }
        }
    }
}

SCENARIO("A member key only a losing fork set leaves current state and its membership row follows",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("carol joined a public room on one fork, her row saying join")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$carol_join", "m.room.member", carol, carol, 40, {"$create", "$pl0", "$join_rules"},
                          R"({"membership":"join"})", {"$alice_join"}, 4U, *policy, 7U);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        REQUIRE(find_current_state_event_id(store, room_id, "m.room.member", carol) == "$carol_join");
        store.memberships.push_back({room_id, carol, "join", 7U});
        merovingian::database::rebuild_membership_index(store);

        WHEN("another fork makes the room invite-only and current state is recomputed")
        {
            ingest_test_event(store, "$invite_only", "m.room.join_rules", std::string{}, "@alice:example.org", 50,
                              {"$create", "$pl0", "$alice_join"}, R"({"join_rule":"invite"})", {"$alice_join"}, 4U,
                              *policy, 8U);
            auto const recomputed = recompute_current_state(store, room_id, *policy);
            REQUIRE(recomputed);

            THEN("her key is gone and her row says leave")
            {
                CHECK_FALSE(find_current_state_event_id(store, room_id, "m.room.member", carol).has_value());
                CHECK(row_membership(store, carol) == "leave");
            }
        }
    }
}

SCENARIO("A membership row follows a member key the resolution changes",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("carol's join on one fork, her row saying join, and a ban of her on another")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$carol_join", "m.room.member", carol, carol, 40, {"$create", "$pl0", "$join_rules"},
                          R"({"membership":"join"})", {"$alice_join"}, 4U, *policy, 7U);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        store.memberships.push_back({room_id, carol, "join", 7U});
        merovingian::database::rebuild_membership_index(store);

        WHEN("the ban arrives and current state is recomputed")
        {
            ingest_test_event(store, "$carol_ban", "m.room.member", carol, "@alice:example.org", 50,
                              {"$create", "$pl0", "$alice_join"}, R"({"membership":"ban"})", {"$alice_join"}, 4U,
                              *policy, 8U);
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the ban is current and her row says ban")
            {
                CHECK(find_current_state_event_id(store, room_id, "m.room.member", carol) == "$carol_ban");
                CHECK(row_membership(store, carol) == "ban");
            }
        }
    }
}

SCENARIO("A membership row written by an event that lost its resolution follows the key back",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("carol's join, and a ban by a user with no standing that wrote its own key and row on receipt")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$carol_join", "m.room.member", carol, carol, 40, {"$create", "$pl0", "$join_rules"},
                          R"({"membership":"join"})", {"$alice_join"}, 4U, *policy, 7U);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        ingest_test_event(store, "$carol_ban", "m.room.member", carol, bob, 50, {"$create", "$pl0"},
                          R"({"membership":"ban"})", {"$alice_join"}, 4U, *policy, 8U);
        REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.member", carol, "$carol_ban"}));
        store.memberships.push_back({room_id, carol, "ban", 8U});
        merovingian::database::rebuild_membership_index(store);

        WHEN("current state is recomputed")
        {
            REQUIRE(recompute_current_state(store, room_id, *policy, {}, 8U));

            THEN("the join is current and her row says join")
            {
                CHECK(find_current_state_event_id(store, room_id, "m.room.member", carol) == "$carol_join");
                CHECK(row_membership(store, carol) == "join");
            }
        }
    }
}

SCENARIO("A row written outside the room's graph survives a resolution that does not hold it",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("a room whose current state also holds an outlier invite with no state group")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        REQUIRE(recompute_current_state(store, room_id, *policy));
        auto invite = PersistentEvent{};
        invite.event_id = "$outlier_invite";
        invite.room_id = room_id;
        invite.sender_user_id = "@alice:example.org";
        invite.json = make_event_json("m.room.member", carol, "$outlier_invite", "@alice:example.org", 45, {"$create"},
                                      R"({"membership":"invite"})");
        invite.status = "outlier";
        store.events.push_back(invite);
        REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.member", carol, "$outlier_invite"}));
        store.memberships.push_back({room_id, carol, "invite", 9U});
        merovingian::database::rebuild_membership_index(store);

        WHEN("current state is recomputed")
        {
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the invite and its row stay")
            {
                CHECK(find_current_state_event_id(store, room_id, "m.room.member", carol) == "$outlier_invite");
                CHECK(row_membership(store, carol) == "invite");
            }
        }
    }
}

SCENARIO("A snapshot event a tip's state names leaves current state when the resolution drops it",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("a room name known only as an event with no state group of its own, held in one tip's state")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$bob_join", "m.room.member", bob, bob, 40, {"$create", "$pl0", "$join_rules"},
                          R"({"membership":"join"})", {"$alice_join"}, 4U, *policy);
        auto name = PersistentEvent{};
        name.event_id = "$snapshot_name";
        name.room_id = room_id;
        name.sender_user_id = bob;
        name.json = make_event_json("m.room.name", "", "$snapshot_name", bob, 45, {"$create", "$pl0", "$bob_join"},
                                    R"({"name":"from a snapshot"})");
        name.status = "outlier";
        store.events.push_back(name);

        auto tip = PersistentEvent{};
        tip.event_id = "$tip";
        tip.room_id = room_id;
        tip.sender_user_id = bob;
        tip.json = make_event_json("m.room.topic", "", "$tip", bob, 46, {"$create", "$pl0", "$bob_join"}, "{}");
        tip.prev_event_ids = {"$bob_join"};
        store.events.push_back(tip);
        auto const before = compute_state_before(store, room_id, *policy, {"$bob_join"});
        REQUIRE(before.ok);
        auto after = compute_state_after(before.state, "$tip", "m.room.topic", std::string{});
        after.push_back({{}, "m.room.name", "", "$snapshot_name"});
        REQUIRE(record_event_state(store, room_id, "$tip", {"$bob_join"}, after).has_value());
        REQUIRE(recompute_current_state(store, room_id, *policy));
        REQUIRE(find_current_state_event_id(store, room_id, "m.room.name", "") == "$snapshot_name");

        WHEN("a demotion on another fork outranks it")
        {
            add_demotion_fork(store, *policy);
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the name is gone")
            {
                CHECK_FALSE(find_current_state_event_id(store, room_id, "m.room.name", "").has_value());
            }
        }
    }
}

SCENARIO("A room with no tips keeps the rows it holds", "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("a room with a current-state row and no forward extremities")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        auto event = PersistentEvent{};
        event.event_id = "$held";
        event.room_id = room_id;
        event.sender_user_id = "@alice:example.org";
        event.json = make_event_json("m.room.name", "", "$held", "@alice:example.org", 1, {}, "{}");
        store.events.push_back(event);
        REQUIRE(merovingian::database::store_state(store, {room_id, "m.room.name", "", "$held"}));

        WHEN("current state is recomputed")
        {
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the row stays: nothing was resolved")
            {
                CHECK(find_current_state_event_id(store, room_id, "m.room.name", "") == "$held");
            }
        }
    }
}

SCENARIO("The state indexes stay right when a removal moves another room's row",
         "[pdu_ingestion][state_groups][gate-m][state_retraction]")
{
    GIVEN("a room whose name will be dropped, and another room's row stored last")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_name_set_on_a_fork(store, *policy);
        auto const other_room = std::string{"!other:example.org"};
        auto other = PersistentEvent{};
        other.event_id = "$other";
        other.room_id = other_room;
        other.sender_user_id = "@alice:example.org";
        other.json = make_event_json("m.room.topic", "", "$other", "@alice:example.org", 1, {}, "{}");
        store.events.push_back(other);
        REQUIRE(merovingian::database::store_state(store, {other_room, "m.room.topic", "", "$other"}));
        merovingian::database::rebuild_state_index(store);

        WHEN("current state is recomputed over both forks")
        {
            add_demotion_fork(store, *policy);
            REQUIRE(recompute_current_state(store, room_id, *policy));

            THEN("the indexes are still trusted and every lookup agrees with the rows")
            {
                CHECK(store.state_indexed_rows == store.state.size());
                CHECK_FALSE(find_current_state_event_id(store, room_id, "m.room.name", "").has_value());
                CHECK(find_current_state_event_id(store, other_room, "m.room.topic", "") == "$other");
                CHECK(room_row_count(store, other_room) == 1U);
                for (auto const& row : store.state)
                {
                    CHECK(find_current_state_event_id(store, row.room_id, row.event_type, row.state_key) ==
                          row.event_id);
                }
                auto seen = std::size_t{0U};
                for_each_room_state_row(store, room_id, [&seen](auto const& row) {
                    CHECK(row.room_id == room_id);
                    ++seen;
                });
                CHECK(seen == store.state.size() - 1U);
            }
        }
    }
}

namespace
{

// Records `event_id` as compute_state_before and record_event_state do on receipt, passing the state before to the
// overload that keeps it as a group (ADR-0694). Returns the state before.
auto receive_event(PersistentStore& store, std::string const& event_id, std::string const& event_type,
                   std::optional<std::string> const& state_key, std::string const& sender, std::int64_t ts,
                   std::vector<std::string> const& auth_ids, std::string const& content_json,
                   std::vector<std::string> const& prev, std::uint64_t depth,
                   merovingian::rooms::RoomVersionPolicy const& policy, bool rejected)
    -> std::vector<PersistentStateGroupStateEntry>
{
    auto event = PersistentEvent{};
    event.event_id = event_id;
    event.room_id = room_id;
    event.sender_user_id = sender;
    event.json = make_event_json(event_type, state_key.value_or(""), event_id, sender, ts, auth_ids, content_json);
    event.depth = depth;
    event.prev_event_ids = prev;
    store.events.push_back(event);

    auto const state_before = compute_state_before(store, room_id, policy, prev);
    REQUIRE(state_before.ok);
    auto const state_after =
        rejected ? state_before.state : compute_state_after(state_before.state, event_id, event_type, state_key);
    REQUIRE(record_event_state(store, room_id, event_id, prev, state_before, state_after, false).has_value());
    return state_before.state;
}

[[nodiscard]] auto names_key(std::vector<PersistentStateGroupStateEntry> const& state, std::string const& event_type,
                             std::string const& event_id) -> bool
{
    return std::ranges::any_of(state, [&](PersistentStateGroupStateEntry const& entry) {
        return entry.event_type == event_type && entry.event_id == event_id;
    });
}

// The same (type, state_key) -> event_id map, whatever order the entries come in.
[[nodiscard]] auto same_state(std::vector<PersistentStateGroupStateEntry> left,
                              std::vector<PersistentStateGroupStateEntry> right) -> bool
{
    auto const by_key = [](PersistentStateGroupStateEntry const& entry) {
        return std::tie(entry.event_type, entry.state_key, entry.event_id);
    };
    std::ranges::sort(left, {}, by_key);
    std::ranges::sort(right, {}, by_key);
    return std::ranges::equal(left, right, {}, by_key, by_key);
}

constexpr auto filler_keys = std::size_t{200U};
constexpr auto messages = std::size_t{20U};

} // namespace

SCENARIO("Events naming the same prev_events resolve and store their state before once",
         "[pdu_ingestion][state_groups][state_before_reuse]")
{
    GIVEN("a room with many state keys, forked so that resolving the forks drops a key one fork holds")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);
        auto store = PersistentStore{};
        seed_genesis(store, *policy);
        ingest_test_event(store, "$bob_join", "m.room.member", std::string{"@bob:example.org"}, "@bob:example.org", 40,
                          {"$create", "$pl0", "$join_rules"}, R"({"membership":"join"})", {"$alice_join"}, 4U, *policy);
        auto last = std::string{"$bob_join"};
        for (std::size_t index = 0U; index < filler_keys; ++index)
        {
            auto const id = "$fill_" + std::to_string(index);
            ingest_test_event(store, id, "x.fill", std::to_string(index), "@alice:example.org",
                              100 + static_cast<std::int64_t>(index), {"$create", "$pl0", "$alice_join"}, R"({"v":1})",
                              {last}, 5U + index, *policy);
            last = id;
        }
        auto const depth = 5U + filler_keys;
        // Fork X: Bob (power 0, state_default 0) sets x.k. Fork Y: Alice raises state_default to 100, so resolving
        // the two applies Y's power levels first and then refuses Bob's key.
        ingest_test_event(store, "$x", "x.k", std::string{}, "@bob:example.org", 5000, {"$create", "$pl0", "$bob_join"},
                          R"({"v":"x"})", {last}, depth, *policy);
        ingest_test_event(
            store, "$pl1", "m.room.power_levels", std::string{}, "@alice:example.org", 5001,
            {"$create", "$pl0", "$alice_join"},
            R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":100,"users_default":0,"users":{"@alice:example.org":100}})",
            {last}, depth, *policy);

        WHEN("Bob sends many messages naming both forks, in either order, rejected or not")
        {
            auto const rows_before = store.state_group_state.size();
            auto first = receive_event(store, "$msg_0", "m.room.message", std::nullopt, "@bob:example.org", 6000,
                                       {"$create", "$pl1", "$bob_join"}, R"({"body":"0"})", {"$x", "$pl1"}, depth + 1U,
                                       *policy, false);
            auto const parsed_after_first = store.state_events_parsed.value();
            auto const rows_after_first = store.state_group_state.size();
            auto every_state_before_is_the_resolution = true;
            for (std::size_t index = 1U; index < messages; ++index)
            {
                auto const prev = index % 2U == 0U ? std::vector<std::string>{"$x", "$pl1"}
                                                   : std::vector<std::string>{"$pl1", "$x", "$pl1"};
                auto const before = receive_event(
                    store, "$msg_" + std::to_string(index), "m.room.message", std::nullopt, "@bob:example.org",
                    6000 + static_cast<std::int64_t>(index), {"$create", "$pl1", "$bob_join"}, R"({"body":"n"})", prev,
                    depth + 1U, *policy, index % 3U == 0U);
                every_state_before_is_the_resolution =
                    every_state_before_is_the_resolution && same_state(before, first);
            }

            THEN("each state before is the spec resolution, and only the first event resolved or stored anything")
            {
                REQUIRE_FALSE(names_key(first, "x.k", "$x"));
                REQUIRE(names_key(first, "m.room.power_levels", "$pl1"));
                REQUIRE(first.size() == filler_keys + 5U);
                REQUIRE(every_state_before_is_the_resolution);
                // The resolution equals fork Y's state, so its group is reused: no snapshot of the room.
                REQUIRE(rows_after_first == rows_before);
                REQUIRE(store.state_group_state.size() == rows_before);
                REQUIRE(store.state_events_parsed.value() == parsed_after_first);
                REQUIRE(store.state_before_memo.size() == 1U);
            }
        }

        WHEN("Alice sends a state event naming both forks after a message did")
        {
            std::ignore = receive_event(store, "$msg", "m.room.message", std::nullopt, "@bob:example.org", 6000,
                                        {"$create", "$pl1", "$bob_join"}, R"({"body":"m"})", {"$x", "$pl1"}, depth + 1U,
                                        *policy, false);
            auto const rows_before = store.state_group_state.size();
            std::ignore = receive_event(store, "$topic", "m.room.topic", std::string{}, "@alice:example.org", 6001,
                                        {"$create", "$pl1", "$alice_join"}, R"({"topic":"t"})", {"$pl1", "$x"},
                                        depth + 1U, *policy, false);

            THEN("its after-state adds the one row it sets")
            {
                REQUIRE(store.state_group_state.size() == rows_before + 1U);
            }
        }

        WHEN("an event the forks name changes, and the room is forgotten")
        {
            std::ignore = receive_event(store, "$msg_a", "m.room.message", std::nullopt, "@bob:example.org", 6000,
                                        {"$create", "$pl1", "$bob_join"}, R"({"body":"a"})", {"$x", "$pl1"}, depth + 1U,
                                        *policy, false);
            store.state_before_memo.forget_room(room_id);
            auto const parsed_before = store.state_events_parsed.value();
            auto const before = receive_event(store, "$msg_b", "m.room.message", std::nullopt, "@bob:example.org", 6001,
                                              {"$create", "$pl1", "$bob_join"}, R"({"body":"b"})", {"$x", "$pl1"},
                                              depth + 1U, *policy, false);

            THEN("the next event resolves again, to the same state")
            {
                REQUIRE(store.state_events_parsed.value() > parsed_before);
                REQUIRE_FALSE(names_key(before, "x.k", "$x"));
                REQUIRE(names_key(before, "m.room.power_levels", "$pl1"));
            }
        }
    }
}

SCENARIO("The state-before memo holds at most its cap of entries, the oldest dropped first",
         "[state_groups][state_before_reuse]")
{
    GIVEN("a memo filled to its cap")
    {
        auto memo = merovingian::database::StateBeforeMemo{};
        auto const cap = merovingian::database::StateBeforeMemo::max_entries;
        for (std::size_t index = 0U; index < cap; ++index)
        {
            memo.remember(room_id, "10", {"sg:a", "sg:" + std::to_string(index)}, "sb:" + std::to_string(index));
        }

        WHEN("it is read at the cap")
        {
            THEN("every entry is served")
            {
                REQUIRE(memo.size() == cap);
                REQUIRE(memo.find(room_id, "10", {"sg:a", "sg:0"}) != nullptr);
                REQUIRE(*memo.find(room_id, "10", {"sg:a", "sg:" + std::to_string(cap - 1U)}) ==
                        "sb:" + std::to_string(cap - 1U));
                REQUIRE(memo.find(room_id, "11", {"sg:a", "sg:0"}) == nullptr);
            }
        }

        WHEN("one more entry is remembered")
        {
            memo.remember(room_id, "10", {"sg:a", "sg:over"}, "sb:over");

            THEN("the oldest is dropped and the newest kept")
            {
                REQUIRE(memo.size() == cap);
                REQUIRE(memo.find(room_id, "10", {"sg:a", "sg:0"}) == nullptr);
                REQUIRE(memo.find(room_id, "10", {"sg:a", "sg:1"}) != nullptr);
                REQUIRE(*memo.find(room_id, "10", {"sg:a", "sg:over"}) == "sb:over");
            }
        }

        WHEN("the room is forgotten")
        {
            memo.forget_room(room_id);

            THEN("nothing is left")
            {
                REQUIRE(memo.size() == 0U);
            }
        }
    }
}
