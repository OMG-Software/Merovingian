// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for ADR-0064 phase A: delta state groups, forward-extremity
// bookkeeping, and event status, all against an in-memory PersistentStore
// (PersistentStoreBackend::memory — commit_persistent_transaction is a
// trivial success for this backend, so these tests exercise the in-memory
// bookkeeping directly without a real database connection). See
// docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md.

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

namespace
{

using merovingian::database::create_or_reuse_state_group;
using merovingian::database::find_event_status;
using merovingian::database::find_forward_extremities;
using merovingian::database::find_state_group;
using merovingian::database::PersistentEvent;
using merovingian::database::PersistentStateGroup;
using merovingian::database::PersistentStateGroupStateEntry;
using merovingian::database::PersistentStore;
using merovingian::database::read_state_group_full_state;
using merovingian::database::set_event_status;
using merovingian::database::store_event;
using merovingian::database::update_forward_extremities;

[[nodiscard]] auto entry(std::string event_type, std::string state_key, std::string event_id)
    -> PersistentStateGroupStateEntry
{
    return {"", std::move(event_type), std::move(state_key), std::move(event_id)};
}

// PersistentStateGroupStateEntry is a plain aggregate with no operator==, so
// state maps are compared field-by-field after sorting by (event_type,
// state_key, event_id) rather than relying on vector equality.
[[nodiscard]] auto state_key_tuple(PersistentStateGroupStateEntry const& state_entry)
    -> std::tuple<std::string, std::string, std::string>
{
    return {state_entry.event_type, state_entry.state_key, state_entry.event_id};
}

[[nodiscard]] auto state_maps_equal(std::vector<PersistentStateGroupStateEntry> lhs,
                                    std::vector<PersistentStateGroupStateEntry> rhs) -> bool
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }
    std::ranges::sort(lhs, {}, state_key_tuple);
    std::ranges::sort(rhs, {}, state_key_tuple);
    return std::ranges::equal(lhs, rhs, {}, state_key_tuple, state_key_tuple);
}

[[nodiscard]] auto contains_entry(std::vector<PersistentStateGroupStateEntry> const& entries,
                                  PersistentStateGroupStateEntry const& needle) -> bool
{
    return std::ranges::any_of(entries, [&needle](PersistentStateGroupStateEntry const& candidate) {
        return candidate.event_type == needle.event_type && candidate.state_key == needle.state_key &&
               candidate.event_id == needle.event_id;
    });
}

[[nodiscard]] auto minimal_event(std::string event_id, std::string room_id, std::uint64_t stream_ordering)
    -> PersistentEvent
{
    auto event = PersistentEvent{};
    event.event_id = std::move(event_id);
    event.room_id = std::move(room_id);
    event.sender_user_id = "@alice:example.org";
    event.json = "{}";
    event.depth = 1U;
    event.stream_ordering = stream_ordering;
    return event;
}

} // namespace

SCENARIO("A delta state group round trips through a snapshot and its deltas", "[state_groups][database]")
{
    GIVEN("a snapshot state group holding two state events")
    {
        auto store = PersistentStore{};
        auto const snapshot_state = std::vector<PersistentStateGroupStateEntry>{
            entry("m.room.create", "", "$create"),
            entry("m.room.member", "@alice:example.org", "$alice_join"),
        };
        auto const snapshot_id =
            create_or_reuse_state_group(store, "!room:example.org", "g0", std::nullopt, snapshot_state);
        REQUIRE(snapshot_id.has_value());

        WHEN("a delta group adds a new member on top of the snapshot")
        {
            auto const delta_state = std::vector<PersistentStateGroupStateEntry>{
                entry("m.room.create", "", "$create"),
                entry("m.room.member", "@alice:example.org", "$alice_join"),
                entry("m.room.member", "@bob:example.org", "$bob_join"),
            };
            auto const delta_id =
                create_or_reuse_state_group(store, "!room:example.org", "g1", snapshot_id, delta_state);

            THEN("the delta group's own rows are only the changed entry, and it is one hop deeper than its parent")
            {
                REQUIRE(delta_id.has_value());
                REQUIRE(*delta_id == "g1");
                auto const group = find_state_group(store, "g1");
                REQUIRE(group.has_value());
                REQUIRE(group->parent_state_group_id == snapshot_id);
                REQUIRE(group->delta_depth == 1U);

                auto own_rows = std::size_t{0U};
                for (auto const& row : store.state_group_state)
                {
                    if (row.state_group_id == "g1")
                    {
                        ++own_rows;
                    }
                }
                REQUIRE(own_rows == 1U);
            }

            AND_THEN("reading the delta group's full state returns the snapshot plus the new member")
            {
                auto const full_state = read_state_group_full_state(store, *delta_id);
                REQUIRE(full_state.has_value());
                REQUIRE(state_maps_equal(*full_state, delta_state));
            }

            AND_THEN("a second delta changing bob's membership still resolves the full chain correctly")
            {
                auto const grandchild_state = std::vector<PersistentStateGroupStateEntry>{
                    entry("m.room.create", "", "$create"),
                    entry("m.room.member", "@alice:example.org", "$alice_join"),
                    entry("m.room.member", "@bob:example.org", "$bob_leave"),
                };
                auto const grandchild_id =
                    create_or_reuse_state_group(store, "!room:example.org", "g2", delta_id, grandchild_state);
                REQUIRE(grandchild_id.has_value());

                auto const full_state = read_state_group_full_state(store, *grandchild_id);
                REQUIRE(full_state.has_value());
                REQUIRE(state_maps_equal(*full_state, grandchild_state));
                REQUIRE_FALSE(contains_entry(*full_state, entry("m.room.member", "@bob:example.org", "$bob_join")));
            }
        }
    }
}

SCENARIO("A new state group is written as a full snapshot once the delta chain would exceed the depth cap",
         "[state_groups][database]")
{
    GIVEN("a snapshot and a chain of deltas reaching exactly the maximum depth")
    {
        auto store = PersistentStore{};
        auto state = std::vector<PersistentStateGroupStateEntry>{entry("m.room.create", "", "$create")};
        auto current_id = create_or_reuse_state_group(store, "!room:example.org", "seed", std::nullopt, state);
        REQUIRE(current_id.has_value());

        for (auto depth = std::size_t{1U}; depth <= merovingian::events::max_state_group_delta_depth; ++depth)
        {
            state.push_back(entry("m.custom.counter", "", "$counter-" + std::to_string(depth)));
            auto const id =
                create_or_reuse_state_group(store, "!room:example.org", "g" + std::to_string(depth), current_id, state);
            REQUIRE(id.has_value());
            current_id = id;
        }
        auto const deepest = find_state_group(store, *current_id);
        REQUIRE(deepest.has_value());
        REQUIRE(deepest->delta_depth == merovingian::events::max_state_group_delta_depth);

        WHEN("one more state change would push the chain past the cap")
        {
            state.push_back(entry("m.custom.counter", "", "$counter-over"));
            auto const new_id =
                create_or_reuse_state_group(store, "!room:example.org", "g-overflow", current_id, state);

            THEN("a fresh full snapshot is written instead of a further delta")
            {
                REQUIRE(new_id.has_value());
                auto const group = find_state_group(store, *new_id);
                REQUIRE(group.has_value());
                REQUIRE_FALSE(group->parent_state_group_id.has_value());
                REQUIRE(group->delta_depth == 0U);

                auto own_rows = std::size_t{0U};
                for (auto const& row : store.state_group_state)
                {
                    if (row.state_group_id == *new_id)
                    {
                        ++own_rows;
                    }
                }
                REQUIRE(own_rows == state.size());
            }
        }
    }
}

SCENARIO("Creating a state group with the parent's own unchanged state reuses the parent group",
         "[state_groups][database]")
{
    GIVEN("an existing snapshot group")
    {
        auto store = PersistentStore{};
        auto const state = std::vector<PersistentStateGroupStateEntry>{
            entry("m.room.create", "", "$create"),
            entry("m.room.member", "@alice:example.org", "$alice_join"),
        };
        auto const snapshot_id = create_or_reuse_state_group(store, "!room:example.org", "g0", std::nullopt, state);
        REQUIRE(snapshot_id.has_value());
        auto const groups_before = store.state_groups.size();

        WHEN("a group is requested with the exact same resulting state")
        {
            auto const reused_id = create_or_reuse_state_group(store, "!room:example.org", "g1", snapshot_id, state);

            THEN("the parent's own id is returned and no new group is created")
            {
                REQUIRE(reused_id.has_value());
                REQUIRE(*reused_id == *snapshot_id);
                REQUIRE(store.state_groups.size() == groups_before);
            }
        }
    }
}

SCENARIO("A resulting state missing a key the parent has forces a full snapshot instead of a delta",
         "[state_groups][database]")
{
    GIVEN("a snapshot group with two state events")
    {
        auto store = PersistentStore{};
        auto const snapshot_state = std::vector<PersistentStateGroupStateEntry>{
            entry("m.room.create", "", "$create"),
            entry("m.room.member", "@alice:example.org", "$alice_join"),
        };
        auto const snapshot_id =
            create_or_reuse_state_group(store, "!room:example.org", "g0", std::nullopt, snapshot_state);
        REQUIRE(snapshot_id.has_value());

        WHEN("a new group is requested whose state lacks a key the parent has")
        {
            auto const truncated_state =
                std::vector<PersistentStateGroupStateEntry>{entry("m.room.create", "", "$create")};
            auto const new_id =
                create_or_reuse_state_group(store, "!room:example.org", "g1", snapshot_id, truncated_state);

            THEN("it is written as a full snapshot, not a delta")
            {
                REQUIRE(new_id.has_value());
                auto const group = find_state_group(store, *new_id);
                REQUIRE(group.has_value());
                REQUIRE_FALSE(group->parent_state_group_id.has_value());
                REQUIRE(group->delta_depth == 0U);

                auto const full_state = read_state_group_full_state(store, *new_id);
                REQUIRE(full_state.has_value());
                REQUIRE(state_maps_equal(*full_state, truncated_state));
            }
        }
    }
}

SCENARIO("A missing parent state group fails closed", "[state_groups][database]")
{
    GIVEN("an empty store")
    {
        auto store = PersistentStore{};

        WHEN("a state group is created with a parent id that does not exist")
        {
            auto const state = std::vector<PersistentStateGroupStateEntry>{entry("m.room.create", "", "$create")};
            auto const result = create_or_reuse_state_group(store, "!room:example.org", "g1",
                                                            std::optional<std::string>{"missing-parent"}, state);

            THEN("creation fails rather than silently writing an unanchored group")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }

        WHEN("the full state of a state group that was never created is read")
        {
            auto const full_state = read_state_group_full_state(store, "does-not-exist");

            THEN("the read fails closed instead of returning an empty map")
            {
                REQUIRE_FALSE(full_state.has_value());
            }
        }
    }
}

SCENARIO("A cyclic parent chain fails closed", "[state_groups][database]")
{
    GIVEN("two state groups whose parent links point at each other")
    {
        auto store = PersistentStore{};
        store.state_groups.push_back(
            PersistentStateGroup{"a", "!room:example.org", std::optional<std::string>{"b"}, 1U});
        store.state_groups.push_back(
            PersistentStateGroup{"b", "!room:example.org", std::optional<std::string>{"a"}, 1U});

        WHEN("the full state of either group is read")
        {
            auto const full_state_a = read_state_group_full_state(store, "a");
            auto const full_state_b = read_state_group_full_state(store, "b");

            THEN("both fail closed instead of looping forever or returning partial state")
            {
                REQUIRE_FALSE(full_state_a.has_value());
                REQUIRE_FALSE(full_state_b.has_value());
            }
        }

        WHEN("a new group is created with the cyclic group as its parent")
        {
            auto const state = std::vector<PersistentStateGroupStateEntry>{entry("m.room.create", "", "$create")};
            auto const result =
                create_or_reuse_state_group(store, "!room:example.org", "c", std::optional<std::string>{"a"}, state);

            THEN("creation fails closed")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

SCENARIO("A delta chain longer than the depth cap fails closed", "[state_groups][database]")
{
    GIVEN("a synthetic chain one hop longer than the maximum allowed depth")
    {
        auto store = PersistentStore{};
        // Snapshot at the root, then max_state_group_delta_depth + 1 deltas on
        // top of it — one hop more than read_state_group_full_state's bound
        // (max_state_group_delta_depth + 1 groups total) permits.
        store.state_groups.push_back(PersistentStateGroup{"root", "!room:example.org", std::nullopt, 0U});
        auto parent = std::string{"root"};
        for (auto depth = std::size_t{1U}; depth <= merovingian::events::max_state_group_delta_depth + 1U; ++depth)
        {
            auto const id = "chain-" + std::to_string(depth);
            store.state_groups.push_back(PersistentStateGroup{
                id, "!room:example.org", std::optional<std::string>{parent}, static_cast<std::uint32_t>(depth)});
            parent = id;
        }

        WHEN("the deepest group's full state is read")
        {
            auto const full_state = read_state_group_full_state(store, parent);

            THEN("the walk fails closed instead of returning a partial map")
            {
                REQUIRE_FALSE(full_state.has_value());
            }
        }
    }
}

SCENARIO("Forward extremities track a room's DAG leaves", "[state_groups][database]")
{
    GIVEN("an empty room")
    {
        auto store = PersistentStore{};
        auto const room_id = std::string{"!room:example.org"};

        WHEN("a linear chain of accepted events is stored")
        {
            REQUIRE(update_forward_extremities(store, room_id, "$e1", {}, true));
            REQUIRE(update_forward_extremities(store, room_id, "$e2", {"$e1"}, true));

            THEN("only the newest event is a forward extremity")
            {
                auto const extremities = find_forward_extremities(store, room_id);
                REQUIRE(extremities.size() == 1U);
                REQUIRE(extremities.front() == "$e2");
            }

            AND_WHEN("the DAG forks into two children of the same event")
            {
                REQUIRE(update_forward_extremities(store, room_id, "$e3a", {"$e2"}, true));
                REQUIRE(update_forward_extremities(store, room_id, "$e3b", {"$e2"}, true));

                THEN("both children become forward extremities")
                {
                    auto extremities = find_forward_extremities(store, room_id);
                    std::ranges::sort(extremities);
                    REQUIRE(extremities == std::vector<std::string>{"$e3a", "$e3b"});
                }

                AND_WHEN("a merge event references both forks")
                {
                    REQUIRE(update_forward_extremities(store, room_id, "$e4", {"$e3a", "$e3b"}, true));

                    THEN("the merge collapses both extremities into one")
                    {
                        auto const extremities = find_forward_extremities(store, room_id);
                        REQUIRE(extremities.size() == 1U);
                        REQUIRE(extremities.front() == "$e4");
                    }

                    AND_WHEN("a soft-failed event referencing the merge is stored")
                    {
                        auto const before = find_forward_extremities(store, room_id);
                        REQUIRE(update_forward_extremities(store, room_id, "$e5-soft-failed", {"$e4"}, false));

                        THEN("the extremity set is unchanged")
                        {
                            auto const after = find_forward_extremities(store, room_id);
                            REQUIRE(after == before);
                        }
                    }

                    AND_WHEN("a rejected event referencing the merge is stored")
                    {
                        auto const before = find_forward_extremities(store, room_id);
                        REQUIRE(update_forward_extremities(store, room_id, "$e5-rejected", {"$e4"}, false));

                        THEN("the extremity set is unchanged")
                        {
                            auto const after = find_forward_extremities(store, room_id);
                            REQUIRE(after == before);
                        }
                    }
                }
            }
        }
    }
}

SCENARIO("Event status is stored and can be updated", "[state_groups][database]")
{
    GIVEN("a freshly stored event")
    {
        auto store = PersistentStore{};
        REQUIRE(store_event(store, minimal_event("$e1", "!room:example.org", 1U)));

        THEN("its status defaults to accepted")
        {
            auto const status = find_event_status(store, "$e1");
            REQUIRE(status.has_value());
            REQUIRE(*status == "accepted");
        }

        WHEN("the status is set to soft_failed")
        {
            REQUIRE(set_event_status(store, "$e1", "soft_failed"));

            THEN("the update round trips")
            {
                auto const status = find_event_status(store, "$e1");
                REQUIRE(status.has_value());
                REQUIRE(*status == "soft_failed");
            }
        }

        WHEN("an unrecognised status is set")
        {
            auto const result = set_event_status(store, "$e1", "not-a-real-status");

            THEN("the call fails and the stored status is unchanged")
            {
                REQUIRE_FALSE(result);
                auto const status = find_event_status(store, "$e1");
                REQUIRE(status.has_value());
                REQUIRE(*status == "accepted");
            }
        }

        WHEN("the status of an unknown event is requested or set")
        {
            THEN("both fail closed")
            {
                REQUIRE_FALSE(find_event_status(store, "$does-not-exist").has_value());
                REQUIRE_FALSE(set_event_status(store, "$does-not-exist", "accepted"));
            }
        }
    }
}
