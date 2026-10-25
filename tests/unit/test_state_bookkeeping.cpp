// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for ADR-0064 phase B1: state-before/state-after computation,
// delta-state-group recording, and current-state-as-cache-of-resolution,
// against an in-memory PersistentStore (PersistentStoreBackend::memory —
// commit_persistent_transaction is a trivial success for this backend).
//
// These tests exercise merovingian::homeserver::compute_state_before /
// compute_state_after / record_event_state / recompute_current_state
// directly — the same functions src/homeserver/local_http_router.cpp's
// ingest_pdu_event wires into the inbound PDU path. See
// docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md and
// tests/unit/test_pdu_ingestion_state_groups.cpp for the end-to-end proof
// through ingest_pdu_event itself.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU" (state resolution determines "current state", not
// arrival order).

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace
{

using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStateGroupStateEntry;
using merovingian::database::PersistentStore;
using merovingian::homeserver::compute_state_after;
using merovingian::homeserver::compute_state_before;
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
                       merovingian::rooms::RoomVersionPolicy const& policy) -> void
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

            THEN("over-cap resolution fails closed and leaves cached state untouched")
            {
                REQUIRE(limits.max_state_groups == config.max_state_groups);
                REQUIRE(limits.max_events_per_state_group == 3U);
                REQUIRE(limits.max_conflicted_state_keys == config.max_conflicted_state_keys);
                REQUIRE(limits.max_mainline_auth_chain_depth == config.max_mainline_auth_chain_depth);
                REQUIRE(limits.max_auth_chain_walk_events == config.max_auth_chain_walk_events);
                REQUIRE(limits.max_total_state_events == config.max_total_state_events);
                REQUIRE_FALSE(state_before.ok);
                REQUIRE(recomputed);
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
            std::erase_if(store.state_groups, [&group](auto const& g) {
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
        auto const nothing_left_of = [&store, &tips_before](std::string const& event_id) {
            REQUIRE_FALSE(event_is_stored(store, event_id));
            REQUIRE_FALSE(merovingian::database::find_event_state_group(store, event_id).has_value());
            REQUIRE(merovingian::database::find_forward_extremities(store, room_id) == tips_before);
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
