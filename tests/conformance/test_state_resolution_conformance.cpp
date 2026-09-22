// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX STATE RESOLUTION CONFORMANCE TESTS                       |
// |                                                                         |
// |  Spec: Matrix v1.19 — State Resolution                                  |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                 |
// |          #room-state-resolution                                          |
// |  v2 algorithm:                                                           |
// |    ../../docs/matrix-v1.19-spec/server-server-api.md                     |
// |          #state-resolution-algorithm-for-room-versions-2-through-10     |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |                                                                         |
// |  The state resolution algorithm is safety-critical: getting it wrong    |
// |  lets forged membership events or power-level elevations persist.       |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

namespace
{

using merovingian::events::StateEventReference;
using merovingian::events::StateGroup;
using merovingian::events::StateKey;
using merovingian::events::StateResolutionRequest;

// Helper: build a StateEventReference from raw JSON.
[[nodiscard]] auto make_event_ref(std::string const& event_type, std::string const& state_key,
                                  std::string const& event_id, std::string const& sender, std::int64_t ts,
                                  std::uint64_t depth, std::string const& json) -> StateEventReference
{
    auto ref = StateEventReference{};
    ref.key = {event_type, state_key};
    ref.event_id = event_id;
    ref.sender = sender;
    ref.origin_server_ts = ts;
    ref.depth = depth;
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    if (parsed.error == merovingian::canonicaljson::ParseError::none)
    {
        ref.event_json = std::move(parsed.value);
    }
    return ref;
}

// Build a minimal state event for test purposes (no content — suitable for v1 tests
// and any scenario that does NOT need SDSS auth checking).
[[nodiscard]] auto make_state_event(std::string event_type, std::string state_key, std::string event_id,
                                    std::string sender, std::int64_t ts, std::uint64_t depth) -> StateEventReference
{
    auto const json = std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key +
                      "\",\"sender\":\"" + sender + "\",\"event_id\":\"" + event_id +
                      "\",\"origin_server_ts\":" + std::to_string(ts) + ",\"content\":{}}";
    return make_event_ref(event_type, state_key, event_id, sender, ts, depth, json);
}

// Build an m.room.create event with creator in content.
// Auth checks (v6+) require content.creator to exist (auth rule Step 3).
[[nodiscard]] auto make_create_event(std::string const& creator, std::string const& event_id, std::int64_t ts)
    -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\""} + creator +
                      "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"creator\":\"" + creator + "\",\"room_version\":\"10\"}}";
    return make_event_ref("m.room.create", "", event_id, creator, ts, 0, json);
}

// Build an m.room.member join event for a user.
[[nodiscard]] auto make_member_event(std::string user_id, std::string event_id, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + user_id + "\",\"sender\":\"" +
                      user_id + "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"membership\":\"join\"}}";
    return make_event_ref("m.room.member", user_id, event_id, user_id, ts, depth, json);
}

// Build an m.room.member leave event for a user (self-leave: sender == state_key).
[[nodiscard]] auto make_member_leave_event(std::string user_id, std::string event_id, std::int64_t ts,
                                           std::uint64_t depth) -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + user_id + "\",\"sender\":\"" +
                      user_id + "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"membership\":\"leave\"}}";
    return make_event_ref("m.room.member", user_id, event_id, user_id, ts, depth, json);
}

// Build an m.room.join_rules event with join_rule "public" — lets a self-join
// succeed without a preceding invite (spec auth rule Step 5).
[[nodiscard]] auto make_public_join_rules_event(std::string const& sender, std::string const& event_id, std::int64_t ts,
                                                std::uint64_t depth) -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.join_rules\",\"state_key\":\"\",\"sender\":\""} + sender +
                      "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"join_rule\":\"public\"}}";
    return make_event_ref("m.room.join_rules", "", event_id, sender, ts, depth, json);
}

// Build an m.room.power_levels event granting a specific user level 100.
[[nodiscard]] auto make_power_levels_event(std::string const& sender, std::string const& event_id, std::int64_t ts,
                                           std::uint64_t depth) -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\""} + sender +
                      "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"ban\":50,\"events_default\":0,\"invite\":0,\"kick\":50,\"redact\":50,"
                      "\"state_default\":50,\"users\":{\"" +
                      sender + "\":100},\"users_default\":0}}";
    return make_event_ref("m.room.power_levels", "", event_id, sender, ts, depth, json);
}

// Returns true if `event_id` appears in `result.resolved_state`.
[[nodiscard]] auto result_contains_event(merovingian::events::StateResolutionResult const& result,
                                         std::string const& event_id) -> bool
{
    return std::any_of(result.resolved_state.begin(), result.resolved_state.end(), [&](StateEventReference const& r) {
        return r.event_id == event_id;
    });
}

// Returns the event in resolved_state for (type, state_key), or nullptr.
[[nodiscard]] auto result_event_for(merovingian::events::StateResolutionResult const& result,
                                    std::string const& event_type, std::string const& state_key)
    -> StateEventReference const*
{
    for (auto const& r : result.resolved_state)
    {
        if (r.key.event_type == event_type && r.key.state_key == state_key)
        {
            return &r;
        }
    }
    return nullptr;
}

} // namespace

// Spec: Matrix v1.19 — State Resolution
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution
//
// When a single state group is provided (no fork), the resolved state is that
// group's state — there is nothing to conflict on. This is the common case
// for append-only room history.
SCENARIO("State resolution v1: single state group is returned unchanged", "[state-resolution][conformance][v1]")
{
    GIVEN("a single state group with two events")
    {
        auto const join_ev =
            make_state_event("m.room.member", "@alice:example.org", "$join:example.org", "@alice:example.org", 1000, 1);
        auto const pl_ev =
            make_state_event("m.room.power_levels", "", "$pl:example.org", "@alice:example.org", 1000, 2);

        auto group = StateGroup{};
        group.group_id = "group_a";
        group.state = {join_ev, pl_ev};

        auto request = StateResolutionRequest{};
        request.room_version = "1";
        request.state_groups = {group};

        WHEN("resolve_state is called")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("resolution succeeds")
            {
                // Spec MUST: a single state group has no conflicts, so resolution succeeds.
                REQUIRE(result.resolved);
            }

            THEN("both events appear in the resolved state")
            {
                // Spec MUST: non-conflicted state is included as-is in the result.
                REQUIRE(result_contains_event(result, "$join:example.org"));
                REQUIRE(result_contains_event(result, "$pl:example.org"));
            }

            THEN("exactly two events are in the resolved state")
            {
                // Spec MUST: no duplicate (type, state_key) pairs in resolved state.
                REQUIRE(result.resolved_state.size() == 2U);
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution
//
// When two state groups agree on every (type, state_key) pair, the resolved
// state is identical to both groups — there is no conflict to resolve.
SCENARIO("State resolution v1: identical state groups produce no conflict", "[state-resolution][conformance][v1]")
{
    GIVEN("two state groups with the same events")
    {
        auto const ev =
            make_state_event("m.room.member", "@alice:example.org", "$join:example.org", "@alice:example.org", 1000, 1);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {ev};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {ev};

        auto request = StateResolutionRequest{};
        request.room_version = "1";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state is called")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("resolution succeeds")
            {
                REQUIRE(result.resolved);
            }

            THEN("exactly one event appears in the resolved state")
            {
                // Spec MUST: duplicate (type, state_key) from non-conflicting groups
                // is deduplicated to a single entry in the output.
                REQUIRE(result.resolved_state.size() == 1U);
                REQUIRE(result_contains_event(result, "$join:example.org"));
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution
//
// When two forks have different events for the same (type, state_key), the
// event with the greater depth wins. On a depth tie the lexicographically
// smaller event ID wins (v1 algorithm).
SCENARIO("State resolution v1: conflicting events — greater depth wins", "[state-resolution][conformance][v1]")
{
    GIVEN("two state groups with conflicting m.room.member events")
    {
        // event_a has a lower depth — it should LOSE the conflict.
        auto const event_a = make_state_event("m.room.member", "@alice:example.org", "$ev_aaa:example.org",
                                              "@alice:example.org", 1000, 1);
        // event_b has a higher depth — it should WIN the conflict.
        auto const event_b = make_state_event("m.room.member", "@alice:example.org", "$ev_bbb:example.org",
                                              "@alice:example.org", 2000, 5);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {event_a};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {event_b};

        auto request = StateResolutionRequest{};
        request.room_version = "1";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state is called")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("resolution succeeds")
            {
                REQUIRE(result.resolved);
            }

            THEN("exactly one m.room.member event is in the resolved state")
            {
                // Spec MUST: conflicting (type, state_key) resolves to one winner.
                auto const* winner = result_event_for(result, "m.room.member", "@alice:example.org");
                REQUIRE(winner != nullptr);
            }

            THEN("the higher-depth event wins")
            {
                // Spec MUST (v1 algorithm): the event with greater depth wins
                // the conflict. event_b has depth 5 vs depth 1.
                auto const* winner = result_event_for(result, "m.room.member", "@alice:example.org");
                REQUIRE(winner != nullptr);
                REQUIRE(winner->event_id == "$ev_bbb:example.org");
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#room-state-resolution
//
// On equal depth, the lexicographically smaller event ID wins (v1 tiebreak).
// The spec says: "If two events are at the same depth the event with the
// smallest event ID (lexicographically) is used."
SCENARIO("State resolution v1: depth tie broken by lexicographically smaller event ID",
         "[state-resolution][conformance][v1]")
{
    GIVEN("two state groups with conflicting events at equal depth")
    {
        auto const event_aaa =
            make_state_event("m.room.join_rules", "", "$aaa:example.org", "@alice:example.org", 1000, 3);
        auto const event_zzz =
            make_state_event("m.room.join_rules", "", "$zzz:example.org", "@alice:example.org", 2000, 3);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {event_aaa};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {event_zzz};

        auto request = StateResolutionRequest{};
        request.room_version = "1";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state is called")
        {
            auto const result = merovingian::events::resolve_state(request);

            THEN("resolution succeeds")
            {
                REQUIRE(result.resolved);
            }

            THEN("the lexicographically smaller event ID wins the tiebreak")
            {
                // Spec MUST (v1 tiebreak): '$aaa' < '$zzz' lexicographically.
                auto const* winner = result_event_for(result, "m.room.join_rules", "");
                REQUIRE(winner != nullptr);
                REQUIRE(winner->event_id == "$aaa:example.org");
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md
//       #state-resolution-algorithm-for-room-versions-2-through-10
//
// resolve_state_v2 requires a room version policy. For a single state group
// the resolved state is that group's complete state.
SCENARIO("State resolution v2 (SDSS): single state group is returned unchanged", "[state-resolution][conformance][v2]")
{
    GIVEN("a single state group and the v10 room version policy")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create_ev =
            make_state_event("m.room.create", "", "$create:example.org", "@alice:example.org", 1000, 0);
        auto const join_ev =
            make_state_event("m.room.member", "@alice:example.org", "$join:example.org", "@alice:example.org", 1001, 1);

        auto group = StateGroup{};
        group.group_id = "group_a";
        group.state = {create_ev, join_ev};

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution succeeds")
            {
                // Spec MUST: single group has no conflict — resolution always succeeds.
                REQUIRE(result.resolved);
            }

            THEN("both events appear in the resolved state")
            {
                // Spec MUST: non-conflicted state passes through as-is.
                REQUIRE(result_contains_event(result, "$create:example.org"));
                REQUIRE(result_contains_event(result, "$join:example.org"));
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md
//       #state-resolution-algorithm-for-room-versions-2-through-10
//
// Non-conflicted state (events that agree across all forks) is taken
// into the resolved state WITHOUT applying resolution rules.
SCENARIO("State resolution v2 (SDSS): non-conflicted state passes through unchanged",
         "[state-resolution][conformance][v2]")
{
    GIVEN("two state groups that agree on some state and conflict on one event")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        // Both groups agree on create, power_levels, and alice's membership.
        // Auth check (v6+ Step 3) requires content.creator in the create event.
        // Auth check for join_rules requires alice to be joined with power >= 50.
        auto const create_ev = make_create_event("@alice:example.org", "$create:example.org", 1000);
        auto const power_ev = make_power_levels_event("@alice:example.org", "$power:example.org", 1001, 1);
        auto const alice_mbr = make_member_event("@alice:example.org", "$alice_member:example.org", 1002, 2);
        // The groups disagree on join_rules.
        auto const join_a =
            make_state_event("m.room.join_rules", "", "$join_rules_a:example.org", "@alice:example.org", 1003, 3);
        auto const join_b =
            make_state_event("m.room.join_rules", "", "$join_rules_b:example.org", "@alice:example.org", 1004, 3);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {create_ev, power_ev, alice_mbr, join_a};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {create_ev, power_ev, alice_mbr, join_b};

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution succeeds")
            {
                REQUIRE(result.resolved);
            }

            THEN("the non-conflicted create event appears in the resolved state")
            {
                // Spec MUST: non-conflicted state is taken as-is into the resolved set.
                REQUIRE(result_contains_event(result, "$create:example.org"));
            }

            THEN("exactly one join_rules event is in the resolved state")
            {
                // Spec MUST: conflicting (type, state_key) resolves to one winner.
                auto const* winner = result_event_for(result, "m.room.join_rules", "");
                REQUIRE(winner != nullptr);
                // The resolved winner must be one of the two candidates.
                auto const& wid = winner->event_id;
                REQUIRE((wid == "$join_rules_a:example.org" || wid == "$join_rules_b:example.org"));
            }
        }
    }
}

// Spec: Matrix v1.19 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md
//       #state-resolution-algorithm-for-room-versions-2-through-10
//
// The resolved state must not contain duplicate (event_type, state_key) pairs.
// This is a fundamental invariant of state resolution: every (type, key) pair
// maps to exactly one event in the resolved state.
SCENARIO("State resolution result never contains duplicate (type, state_key) pairs",
         "[state-resolution][conformance][v1][v2]")
{
    GIVEN("two state groups with three conflicting (type, state_key) pairs")
    {
        auto const ev_a1 =
            make_state_event("m.room.member", "@alice:example.org", "$alice_a:example.org", "@alice:example.org", 1, 1);
        auto const ev_a2 =
            make_state_event("m.room.member", "@alice:example.org", "$alice_b:example.org", "@alice:example.org", 2, 2);
        auto const ev_b1 =
            make_state_event("m.room.member", "@bob:example.org", "$bob_a:example.org", "@bob:example.org", 1, 1);
        auto const ev_b2 =
            make_state_event("m.room.member", "@bob:example.org", "$bob_b:example.org", "@bob:example.org", 2, 2);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {ev_a1, ev_b1};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {ev_a2, ev_b2};

        WHEN("resolve_state (v1) is called")
        {
            auto request = StateResolutionRequest{};
            request.room_version = "1";
            request.state_groups = {group_a, group_b};

            auto const result = merovingian::events::resolve_state(request);
            REQUIRE(result.resolved);

            THEN("resolved state has exactly one entry per (type, state_key)")
            {
                // Spec MUST: no duplicate (type, state_key) in output.
                // Check alice's membership.
                std::size_t alice_count{0};
                std::size_t bob_count{0};
                for (auto const& r : result.resolved_state)
                {
                    if (r.key.event_type == "m.room.member" && r.key.state_key == "@alice:example.org")
                        ++alice_count;
                    if (r.key.event_type == "m.room.member" && r.key.state_key == "@bob:example.org")
                        ++bob_count;
                }
                REQUIRE(alice_count == 1U);
                REQUIRE(bob_count == 1U);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: State resolution v2 — conflicting events resolved by depth
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md
//         #state-resolution-algorithm-for-room-versions-2-through-10
//
// When two state groups conflict on the same (type, state_key) pair, the v2
// algorithm processes auth events first (by reverse topological power sort)
// then non-auth events (by mainline ordering). In the absence of a power-level
// differential, events at greater depth take precedence.
// ---------------------------------------------------------------------------

SCENARIO("State resolution v2: conflicting membership events are resolved to a single winner",
         "[conformance][state-resolution][v2]")
{
    GIVEN("two state groups with a shared create event and conflicting membership events")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        // Shared create event anchors both groups.
        auto const create = make_create_event("@alice:example.org", "$create:example.org", 500);

        // Shared public join_rules: without it a non-creator self-join defaults
        // to invite-only (auth rule Step 5) and would be denied regardless of
        // this scenario's join/leave conflict, defeating the point of the test.
        auto const join_rules = make_public_join_rules_event("@alice:example.org", "$join_rules:example.org", 600, 0);

        // Group A: @charlie has membership=join (depth=10).
        auto const join_event = make_member_event("@charlie:example.org", "$charlie_join:example.org", 1000, 10);

        // Group B: @charlie has membership=leave (depth=5).
        auto const leave_event = make_member_leave_event("@charlie:example.org", "$charlie_leave:example.org", 2000, 5);

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(create);
        group_a.state.push_back(join_rules);
        group_a.state.push_back(join_event);

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(create);
        group_b.state.push_back(join_rules);
        group_b.state.push_back(leave_event);

        request.state_groups.push_back(std::move(group_a));
        request.state_groups.push_back(std::move(group_b));

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the result is resolved")
            {
                // Spec MUST: v2 must always produce a resolved state, never leave it unresolved.
                REQUIRE(result.resolved);
            }

            THEN("the resolved state contains exactly one entry for the member key")
            {
                // Spec MUST: no two events in the resolved state may share the same
                // (type, state_key) pair. The conflict is resolved to exactly one winner.
                auto charlie_count = std::size_t{0};
                for (auto const& ref : result.resolved_state)
                {
                    if (ref.key.event_type == "m.room.member" && ref.key.state_key == "@charlie:example.org")
                    {
                        ++charlie_count;
                    }
                }
                REQUIRE(charlie_count == 1U);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: State resolution v2 — unconflicted state passes through unchanged,
// conflicted state goes through the resolution algorithm.
// ---------------------------------------------------------------------------

SCENARIO("State resolution v2: unconflicted state survives and conflicted state is resolved",
         "[conformance][state-resolution][v2]")
{
    GIVEN("two state groups sharing a create event but conflicting on a membership")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        // Shared unconflicted event: both groups have the same create.
        auto const create = make_state_event("m.room.create", "", "$create:example.org", "@alice:example.org", 500, 0);

        // Shared public join_rules: without it a non-creator self-join defaults
        // to invite-only (auth rule Step 5) and would be denied regardless of
        // this scenario's join/leave conflict, defeating the point of the test.
        auto const join_rules = make_public_join_rules_event("@alice:example.org", "$join_rules:example.org", 600, 0);

        // Conflicting: Group A has @bob=join (depth 8), Group B has @bob=leave (depth 3).
        auto const bob_join = make_member_event("@bob:example.org", "$bob_join:example.org", 1000, 8);
        auto const bob_leave = make_member_leave_event("@bob:example.org", "$bob_leave:example.org", 2000, 3);

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(create);
        group_a.state.push_back(join_rules);
        group_a.state.push_back(bob_join);

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(create);
        group_b.state.push_back(join_rules);
        group_b.state.push_back(bob_leave);

        request.state_groups.push_back(std::move(group_a));
        request.state_groups.push_back(std::move(group_b));

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the result is resolved with exactly three state entries")
            {
                REQUIRE(result.resolved);
                // Expect: the create event + the shared join_rules event + the winning bob membership.
                REQUIRE(result.resolved_state.size() == 3U);
            }

            THEN("the create event appears in the resolved state (unconflicted)")
            {
                auto const found_create =
                    std::ranges::any_of(result.resolved_state, [](merovingian::events::StateEventReference const& r) {
                        return r.key.event_type == "m.room.create" && r.key.state_key == "";
                    });
                REQUIRE(found_create);
            }

            THEN("exactly one winner is chosen for @bob's membership (no duplicates)")
            {
                // Spec MUST: the v2 algorithm must choose exactly one winner for each
                // conflicted (type, state_key) pair. Both join and leave are candidates;
                // the specific winner is determined by the auth-chain power sort and
                // mainline ordering — we assert the invariant (one winner), not a
                // specific outcome, as it depends on the full auth DAG.
                auto bob_count = std::size_t{0};
                for (auto const& ref : result.resolved_state)
                {
                    if (ref.key.event_type == "m.room.member" && ref.key.state_key == "@bob:example.org")
                    {
                        ++bob_count;
                    }
                }
                REQUIRE(bob_count == 1U);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: partition_conflicted_state correctly separates conflicted from
// unconflicted state across multiple state groups.
// ---------------------------------------------------------------------------

SCENARIO("partition_conflicted_state separates shared state from conflicting state",
         "[conformance][state-resolution][v2]")
{
    GIVEN("two state groups with one event identical in both and one that differs")
    {
        // Shared: exact same event reference in both groups (unconflicted).
        auto const shared_create =
            make_state_event("m.room.create", "", "$create:example.org", "@alice:example.org", 500, 0);

        // Conflicting: same key, different event_id in each group.
        auto const alice_join = make_state_event("m.room.member", "@alice:example.org", "$alice_join:example.org",
                                                 "@alice:example.org", 600, 1);
        auto const alice_leave = make_state_event("m.room.member", "@alice:example.org", "$alice_leave:example.org",
                                                  "@alice:example.org", 700, 2);

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(shared_create);
        group_a.state.push_back(alice_join);

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(shared_create);
        group_b.state.push_back(alice_leave);

        auto const groups = std::vector<merovingian::events::StateGroup>{group_a, group_b};

        WHEN("partition_conflicted_state is called")
        {
            auto const [unconflicted, conflicted] = merovingian::events::partition_conflicted_state(groups);

            THEN("the create event is unconflicted (same event_id in both groups)")
            {
                // Spec: an event appearing in all groups with the same value is unconflicted.
                auto const create_key = merovingian::events::StateKey{"m.room.create", ""};
                REQUIRE(unconflicted.count(create_key) == 1U);
                REQUIRE(unconflicted.at(create_key).event_id == "$create:example.org");
            }

            THEN("the member event is conflicted (different event_id in each group)")
            {
                // Spec: events with differing values across groups must go through resolution.
                auto const member_key = merovingian::events::StateKey{"m.room.member", "@alice:example.org"};
                REQUIRE(conflicted.count(member_key) == 1U);
            }
        }
    }
}

namespace
{

// Build a state event whose JSON carries event_id and an auth_events array of
// event-id strings — the v3+ PDU shape consumed by the mainline walk.
[[nodiscard]] auto make_event_with_auth(std::string const& event_type, std::string const& state_key,
                                        std::string const& event_id, std::string const& sender, std::int64_t ts,
                                        std::vector<std::string> const& auth_ids, std::string const& content_json)
    -> StateEventReference
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
    auto const json = std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key +
                      "\",\"sender\":\"" + sender + "\",\"event_id\":\"" + event_id +
                      "\",\"origin_server_ts\":" + std::to_string(ts) + ",\"auth_events\":" + auth +
                      ",\"content\":" + content_json + "}";
    return make_event_ref(event_type, state_key, event_id, sender, ts, 1, json);
}

auto const power_levels_content =
    std::string{"{\"ban\":50,\"events_default\":0,\"invite\":0,\"kick\":50,\"redact\":50,"
                "\"state_default\":50,\"users\":{\"@alice:example.org\":100},\"users_default\":0}"};

} // namespace

// Spec: Matrix v1.19 — Room v2 state resolution, Mainline ordering
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md (Definitions — Mainline ordering)
//
// The mainline of the resolved power-levels event P0 is [P0, P1, …, Pn] where
// P(i+1) is the m.room.power_levels event in Pi's auth_events, walked
// transitively. An event's mainline position is found by walking its own
// power-levels ancestry until a mainline event is reached; an event with no
// mainline ancestor gets position ∞ (a sentinel greater than any index).
// Ordering is smallest-to-largest where x < y when the mainline position of x
// is GREATER than that of y, then by origin_server_ts, then event_id.
SCENARIO("Mainline ordering walks power-levels ancestry transitively with an infinity sentinel",
         "[conformance][state-resolution][v2][mainline]")
{
    GIVEN("a two-hop power-levels mainline and events anchored at different depths")
    {
        // Mainline: $pl2 (head, resolved) -> $pl1. $plx is a power event NOT on
        // the mainline whose own auth chain reaches $pl1.
        auto const create = make_event_with_auth("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                                 "{\"creator\":\"@alice:example.org\",\"room_version\":\"10\"}");
        auto const pl1 = make_event_with_auth("m.room.power_levels", "", "$pl1", "@alice:example.org", 100, {"$create"},
                                              power_levels_content);
        auto const pl2 = make_event_with_auth("m.room.power_levels", "", "$pl2", "@alice:example.org", 200,
                                              {"$pl1", "$create"}, power_levels_content);
        auto const plx = make_event_with_auth("m.room.power_levels", "", "$plx", "@alice:example.org", 150, {"$pl1"},
                                              power_levels_content);

        // topic_c has no power-levels ancestor at all -> position ∞ (sorted first).
        auto const topic_c =
            make_event_with_auth("m.room.topic", "", "$topic_c", "@alice:example.org", 50, {"$create"}, "{}");
        // topic_e reaches the mainline only transitively via the non-mainline $plx -> position 1.
        auto const topic_e =
            make_event_with_auth("m.room.topic", "", "$topic_e", "@alice:example.org", 10, {"$plx"}, "{}");
        // topic_a is anchored directly at $pl1 -> position 1.
        auto const topic_a =
            make_event_with_auth("m.room.topic", "", "$topic_a", "@alice:example.org", 20, {"$pl1"}, "{}");
        // topic_b is anchored at the head $pl2 -> position 0 (sorted last).
        auto const topic_b =
            make_event_with_auth("m.room.topic", "", "$topic_b", "@alice:example.org", 5, {"$pl2"}, "{}");

        auto context_group = merovingian::events::StateGroup{};
        context_group.group_id = "context";
        context_group.state = {create, pl1, pl2, plx, topic_a, topic_b, topic_c, topic_e};

        auto const groups = std::vector<merovingian::events::StateGroup>{context_group};
        auto const events_by_id = merovingian::events::build_event_json_index(groups);

        auto resolved = merovingian::events::StateMap{};
        resolved[merovingian::events::StateKey{"m.room.power_levels", ""}] = pl2;

        WHEN("the events are ordered by the mainline ordering based on the resolved power levels")
        {
            auto events = std::vector<StateEventReference>{topic_b, topic_e, topic_a, topic_c};
            merovingian::events::mainline_order(events, resolved, events_by_id);

            THEN("events sort by descending mainline position, ties broken by origin_server_ts")
            {
                REQUIRE(events.size() == 4U);
                // Spec MUST: no mainline ancestor -> position ∞ -> smallest (first).
                REQUIRE(events[0].event_id == "$topic_c");
                // Spec MUST: position found by walking power-levels ancestry transitively.
                REQUIRE(events[1].event_id == "$topic_e");
                // Spec MUST: same position (1) -> smaller origin_server_ts first.
                REQUIRE(events[2].event_id == "$topic_a");
                // Spec MUST: position 0 (anchored at the head) sorts last.
                REQUIRE(events[3].event_id == "$topic_b");
            }
        }
    }
}

// Spec: Matrix v1.19 — Room v2 state resolution, Algorithm steps 1-4
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md (Definitions — Algorithm)
//
// Step 1/2: power events from the conflicted set are sorted by reverse
// topological power ordering and auth-checked FIRST against the unconflicted
// state. Step 3/4: only the REMAINING (non-power) events are then ordered by
// the mainline ordering based on the power level in the partially resolved
// state, and auth-checked. A timestamp-only ordering of the non-power events
// violates step 3.
SCENARIO("State resolution v2 orders non-power events by mainline of the partially resolved power levels",
         "[conformance][state-resolution][v2][mainline]")
{
    GIVEN("a fork conflicting over both power levels and the room topic")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_event_with_auth("m.room.create", "", "$create", "@alice:example.org", 100, {},
                                                 "{\"creator\":\"@alice:example.org\",\"room_version\":\"10\"}");
        auto const alice_join =
            make_event_with_auth("m.room.member", "@alice:example.org", "$alice_join", "@alice:example.org", 200,
                                 {"$create"}, "{\"membership\":\"join\"}");

        // Conflicted power levels: $pl2 descends from $pl1 (same sender power),
        // so reverse-topo ordering applies $pl1 then $pl2 -> $pl2 wins.
        auto const pl1 = make_event_with_auth("m.room.power_levels", "", "$pl1", "@alice:example.org", 300, {"$create"},
                                              power_levels_content);
        auto const pl2 = make_event_with_auth("m.room.power_levels", "", "$pl2", "@alice:example.org", 400,
                                              {"$pl1", "$create"}, power_levels_content);

        // Conflicted topic: $topic_a is NEWER by timestamp but anchored at the
        // older mainline event $pl1 (position 1); $topic_b is older by
        // timestamp but anchored at the resolved head $pl2 (position 0).
        auto const topic_a =
            make_event_with_auth("m.room.topic", "", "$topic_a", "@alice:example.org", 900, {"$pl1"}, "{}");
        auto const topic_b =
            make_event_with_auth("m.room.topic", "", "$topic_b", "@alice:example.org", 400, {"$pl2"}, "{}");

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, alice_join, pl1, topic_a};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, alice_join, pl2, topic_b};

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the descendant power-levels event wins the power conflict")
            {
                REQUIRE(result.resolved);
                auto const* pl_winner = result_event_for(result, "m.room.power_levels", "");
                REQUIRE(pl_winner != nullptr);
                REQUIRE(pl_winner->event_id == "$pl2");
            }

            THEN("the topic anchored at the resolved power levels head wins despite its older timestamp")
            {
                // Spec MUST: step 3 orders remaining events by mainline position
                // (position 0 sorts last, so it is applied last and wins), NOT by
                // origin_server_ts alone.
                REQUIRE(result.resolved);
                auto const* topic_winner = result_event_for(result, "m.room.topic", "");
                REQUIRE(topic_winner != nullptr);
                REQUIRE(topic_winner->event_id == "$topic_b");
            }
        }
    }
}

// Spec: Matrix v1.19 — Room v2 state resolution, Definitions — Power events
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md (Definitions — Power events)
//
// A power event is a state event with type m.room.power_levels or
// m.room.join_rules, or an m.room.member event with membership leave or ban
// where the sender does not match the state_key.
SCENARIO("Power events are classified per the spec definition", "[conformance][state-resolution][v2]")
{
    GIVEN("state events of each class")
    {
        auto const pl =
            make_event_with_auth("m.room.power_levels", "", "$pl", "@alice:example.org", 1, {}, power_levels_content);
        auto const join_rules = make_event_with_auth("m.room.join_rules", "", "$jr", "@alice:example.org", 1, {},
                                                     "{\"join_rule\":\"public\"}");
        auto const kick = make_event_with_auth("m.room.member", "@bob:example.org", "$kick", "@alice:example.org", 1,
                                               {}, "{\"membership\":\"leave\"}");
        auto const self_leave = make_event_with_auth("m.room.member", "@bob:example.org", "$leave", "@bob:example.org",
                                                     1, {}, "{\"membership\":\"leave\"}");
        auto const ban = make_event_with_auth("m.room.member", "@bob:example.org", "$ban", "@alice:example.org", 1, {},
                                              "{\"membership\":\"ban\"}");
        auto const join = make_event_with_auth("m.room.member", "@bob:example.org", "$join", "@bob:example.org", 1, {},
                                               "{\"membership\":\"join\"}");
        auto const topic = make_event_with_auth("m.room.topic", "", "$topic", "@alice:example.org", 1, {}, "{}");

        WHEN("each event is classified")
        {
            THEN("power_levels, join_rules, kicks and bans are power events; the rest are not")
            {
                // Spec MUST: m.room.power_levels and m.room.join_rules are power events.
                REQUIRE(merovingian::events::is_power_event(pl));
                REQUIRE(merovingian::events::is_power_event(join_rules));
                // Spec MUST: leave/ban with sender != state_key are power events.
                REQUIRE(merovingian::events::is_power_event(kick));
                REQUIRE(merovingian::events::is_power_event(ban));
                // Spec MUST: a self-leave (sender == state_key) is NOT a power event.
                REQUIRE_FALSE(merovingian::events::is_power_event(self_leave));
                REQUIRE_FALSE(merovingian::events::is_power_event(join));
                REQUIRE_FALSE(merovingian::events::is_power_event(topic));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Restricted-join auth events, and string-encoded power levels in the reverse
// topological power ordering.
// ---------------------------------------------------------------------------

namespace
{

// Build an m.room.join_rules event with an arbitrary join rule.
[[nodiscard]] auto make_join_rules_event(std::string const& join_rule, std::string const& sender,
                                         std::string const& event_id, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.join_rules\",\"state_key\":\"\",\"sender\":\""} + sender +
                      "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"join_rule\":\"" + join_rule + "\"}}";
    return make_event_ref("m.room.join_rules", "", event_id, sender, ts, depth, json);
}

// Build an m.room.power_levels event whose content.users body is supplied
// verbatim, so a test can encode a level as a JSON string ("100") rather than
// an integer (100). `invite` is spelled out because the restricted-join rule
// compares the authorising user's level against it.
[[nodiscard]] auto make_power_levels_with_users(std::string const& users_json, std::string const& sender,
                                                std::string const& event_id, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\""} + sender +
                      "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"ban\":50,\"events_default\":0,\"invite\":0,\"kick\":50,\"redact\":50,"
                      "\"state_default\":50,\"users\":" +
                      users_json + ",\"users_default\":0}}";
    return make_event_ref("m.room.power_levels", "", event_id, sender, ts, depth, json);
}

// Build an m.room.member join event carrying content.join_authorised_via_users_server,
// as a resident server issues for a join into a restricted room.
[[nodiscard]] auto make_restricted_join_event(std::string const& user_id, std::string const& authorising_user,
                                              std::string const& event_id, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + user_id + "\",\"sender\":\"" +
                      user_id + "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"membership\":\"join\",\"join_authorised_via_users_server\":\"" +
                      authorising_user + "\"}}";
    return make_event_ref("m.room.member", user_id, event_id, user_id, ts, depth, json);
}

} // namespace

// Spec: Matrix Server-Server API v1.19
// Section: Auth events selection; Authorization rules (restricted rooms)
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#auth-events-selection
//      ../../docs/matrix-v1.19-spec/rooms/v10.md#authorization-rules
//
// Spec MUST (auth events selection): "If membership is join,
// content.join_authorised_via_users_server is present, and the room version
// supports restricted rooms, then the m.room.member event with state_key
// matching content.join_authorised_via_users_server" is one of the event's auth
// events.
// Spec MUST (rule 4.3.5.2): reject if the user named by
// join_authorised_via_users_server "is not a user with sufficient permission to
// invite other users or is not a joined member of the room".
//
// State resolution re-runs the authorization rules against the state resolved so
// far, so it MUST offer the authorising user's membership to the rule. Omitting
// it fails every restricted join in the conflicted set, which locks authorized
// joiners out and diverges room state across servers.
SCENARIO("State resolution v2 authorizes a restricted join using the authorising user's membership",
         "[conformance][state-resolution][v2][restricted-join]")
{
    GIVEN("a restricted room whose conflicted set contains a join authorised by a joined, invite-capable user")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_create_event("@alice:example.org", "$create:example.org", 500);
        auto const join_rules =
            make_join_rules_event("restricted", "@alice:example.org", "$join_rules:example.org", 600, 1);
        auto const power_levels = make_power_levels_with_users(R"({"@alice:example.org":100,"@auth:example.org":100})",
                                                               "@alice:example.org", "$pl:example.org", 700, 2);
        // membership=join for the authorising user.
        auto const authoriser_member = make_member_event("@auth:example.org", "$auth_member:example.org", 800, 3);
        auto const bob_join =
            make_restricted_join_event("@bob:example.org", "@auth:example.org", "$bob_join:example.org", 900, 4);

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, join_rules, power_levels, authoriser_member, bob_join};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, join_rules, power_levels, authoriser_member};

        request.state_groups.push_back(std::move(group_a));
        request.state_groups.push_back(std::move(group_b));

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the restricted join survives resolution")
            {
                // Spec MUST: v2 always produces a resolved state.
                REQUIRE(result.resolved);
                // Spec MUST (rule 4.3.5.3): with a joined, invite-capable authorising
                // user the restricted join is allowed, so it must appear in the
                // resolved state. Do NOT weaken - dropping it locks authorized
                // joiners out of restricted rooms and diverges state across servers.
                REQUIRE(result_contains_event(result, "$bob_join:example.org"));
                auto const* member = result_event_for(result, "m.room.member", "@bob:example.org");
                REQUIRE(member != nullptr);
                REQUIRE(member->event_id == "$bob_join:example.org");
            }
        }
    }

    GIVEN("the same restricted room where the authorising user is not a member")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_create_event("@alice:example.org", "$create:example.org", 500);
        auto const join_rules =
            make_join_rules_event("restricted", "@alice:example.org", "$join_rules:example.org", 600, 1);
        auto const power_levels = make_power_levels_with_users(R"({"@alice:example.org":100,"@auth:example.org":100})",
                                                               "@alice:example.org", "$pl:example.org", 700, 2);
        auto const bob_join =
            make_restricted_join_event("@bob:example.org", "@auth:example.org", "$bob_join:example.org", 900, 4);

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, join_rules, power_levels, bob_join};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, join_rules, power_levels};

        request.state_groups.push_back(std::move(group_a));
        request.state_groups.push_back(std::move(group_b));

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the restricted join is rejected")
            {
                REQUIRE(result.resolved);
                // Spec MUST (rule 4.3.5.2): reject when join_authorised_via_users_server
                // names a user who is not a joined member of the room.
                REQUIRE_FALSE(result_contains_event(result, "$bob_join:example.org"));
            }
        }
    }
}

// Spec: Matrix Room Versions v1.19
// Section: Values in m.room.power_levels events must be integers
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md
//      ../../docs/matrix-v1.19-spec/rooms/v9.md
//
// Spec MUST: room versions 1-9 accept a string representation of an integer in
// m.room.power_levels; room version 10 onwards MUST NOT. The reverse topological
// power ordering ranks conflicted power events by their sender's power level, so
// it has to read the level in the form the room's own version defines - reading a
// v9 string level as absent silently demotes the sender to users_default and lets
// a lower-power sender's event win.
SCENARIO("Reverse topological power ordering reads string power levels only where the room version allows",
         "[conformance][state-resolution][v2][power-levels]")
{
    GIVEN("two conflicted power-level events, the higher one encoding its level as a string")
    {
        auto const* v9 = merovingian::rooms::find_room_version_policy("9");
        auto const* v10 = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(v9 != nullptr);
        REQUIRE(v10 != nullptr);
        // Spec MUST: v10 is the version that introduced the integers-only rule.
        REQUIRE_FALSE(v9->power_levels_require_integers);
        REQUIRE(v10->power_levels_require_integers);

        // The power level is read from each candidate's own auth_events
        // power_levels ancestor (rooms/v10.md — Reverse topological power
        // ordering, rule 1), never from the candidate's own new content — so
        // the string-vs-integer distinction is exercised on the ANCESTOR
        // ($pl_prev): @bob holds an integer 0, @alice holds the string
        // "100". Both candidates merely cite $pl_prev; their own content is
        // irrelevant to the ordering.
        auto const pl_prev =
            make_event_with_auth("m.room.power_levels", "", "$pl_prev:example.org", "@alice:example.org", 1, {},
                                 R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,)"
                                 R"("users_default":0,"users":{"@bob:example.org":0,"@alice:example.org":"100"}})");
        auto const low = make_event_with_auth("m.room.power_levels", "", "$low:example.org", "@bob:example.org", 10,
                                              {"$pl_prev:example.org"}, power_levels_content);
        auto const high = make_event_with_auth("m.room.power_levels", "", "$high:example.org", "@alice:example.org", 50,
                                               {"$pl_prev:example.org"}, power_levels_content);
        auto const conflicted = std::vector<StateEventReference>{low, high};
        auto const known_index = merovingian::events::build_event_json_index({
            merovingian::events::StateGroup{"g", {pl_prev}}
        });

        WHEN("the events are sorted under a room version 9 policy")
        {
            auto const sorted = merovingian::events::reverse_topological_power_sort(
                conflicted, known_index, merovingian::events::EventLookupFn{}, *v9);

            THEN("the string-encoded level is honoured and its sender sorts first")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST: v9 accepts "100" as the power level 100, which outranks 0.
                // Do NOT weaken - reading it as absent lets a lower-power sender's event
                // win state resolution in every pre-v10 room.
                REQUIRE((*sorted)[0].event_id == "$high:example.org");
                REQUIRE((*sorted)[1].event_id == "$low:example.org");
            }
        }

        WHEN("the same events are sorted under a room version 10 policy")
        {
            auto const sorted = merovingian::events::reverse_topological_power_sort(
                conflicted, known_index, merovingian::events::EventLookupFn{}, *v10);

            THEN("the string-encoded level is ignored and the ordering falls back to origin_server_ts")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST: v10 rejects string power levels, so @alice falls back to
                // users_default (0). Both senders are then 0 and rule 2 orders by the
                // earlier origin_server_ts.
                REQUIRE((*sorted)[0].event_id == "$low:example.org");
                REQUIRE((*sorted)[1].event_id == "$high:example.org");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.19 — Room v2 state resolution, Definitions ("Reverse
// topological power ordering", rule 3) and Algorithm.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md
//
// "the senders have the same power level and the events have the same
// origin_server_ts, but x's event_id is less than y's event_id" — the final
// tie-break, distinct from the origin_server_ts tie-break already covered
// above.
// ---------------------------------------------------------------------------
SCENARIO("Reverse topological power ordering ties on equal power and equal origin_server_ts are broken by event_id",
         "[conformance][state-resolution][v2][sort][state_res_v2]")
{
    GIVEN("two conflicted power events from the same sender at the identical origin_server_ts")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        // Neither event's own auth_events name a power_levels ancestor, so
        // both fall to the spec default of 0 (same as the mainline-sort
        // tie-break test above) — same origin_server_ts too, so only the
        // final event_id tie-break can distinguish them.
        auto const zzz = make_power_levels_event("@alice:example.org", "$zzz:example.org", 500, 1);
        auto const aaa = make_power_levels_event("@alice:example.org", "$aaa:example.org", 500, 1);

        auto const conflicted = std::vector<StateEventReference>{zzz, aaa};

        WHEN("the events are sorted by reverse topological power ordering")
        {
            auto const sorted = merovingian::events::reverse_topological_power_sort(
                conflicted, merovingian::events::EventJsonIndex{}, merovingian::events::EventLookupFn{}, *policy);

            THEN("the lexicographically smaller event_id sorts first")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST: rule 3 — equal power, equal ts -> smaller event_id first.
                REQUIRE((*sorted)[0].event_id == "$aaa:example.org");
                REQUIRE((*sorted)[1].event_id == "$zzz:example.org");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.19 — Room v2 state resolution, Algorithm step 1-2.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md
//
// A power-level self-demotion and a ban are both power events and are
// auth-checked in the SAME reverse-topological-power pass. When the
// demotion is ordered before the ban, the banner no longer has enough power
// by the time the ban is auth-checked against the partially resolved state,
// and the ban is correctly dropped — this is the "ban vs. concurrent
// power-level demotion" case.
// ---------------------------------------------------------------------------
SCENARIO("State resolution v2: a concurrent self-demotion can outrun a ban authored with the same prior power",
         "[conformance][state-resolution][v2][state_res_v2]")
{
    GIVEN("a fork where @alice demotes her own power while, concurrently, she also bans @bob")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_create_event("@alice:example.org", "$create:example.org", 100);
        auto const join_rules = make_public_join_rules_event("@alice:example.org", "$join_rules:example.org", 200, 0);
        auto const alice_join = make_member_event("@alice:example.org", "$alice_join:example.org", 300, 1);

        // Fork A: @alice bans @bob (a power event: sender != state_key, ban).
        auto const ban =
            make_event_with_auth("m.room.member", "@bob:example.org", "$ban:example.org", "@alice:example.org", 5000,
                                 {"$create:example.org"}, R"({"membership":"ban"})");

        // Fork B: @alice demotes her own power to 0, earlier than the ban's
        // origin_server_ts, so when both candidates are auth-checked in the
        // same reverse-topological-power pass, the demotion applies first.
        auto const demote = make_event_with_auth("m.room.power_levels", "", "$demote:example.org", "@alice:example.org",
                                                 1000, {"$create:example.org"},
                                                 R"({"ban":50,"events_default":0,"invite":0,"kick":50,)"
                                                 R"("redact":50,"state_default":50,"users":{},)"
                                                 R"("users_default":0})");

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, join_rules, alice_join, ban};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, join_rules, alice_join, demote};

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the ban does not survive — @alice had already demoted herself when it was auth-checked")
            {
                REQUIRE(result.resolved);
                // @bob's key has exactly one candidate ($ban) across both forks
                // (fork B never mentions @bob), so a rejected ban leaves no
                // winner for that key at all.
                REQUIRE(result_event_for(result, "m.room.member", "@bob:example.org") == nullptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.19 — Room v2 state resolution, Algorithm steps 1-4.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md
//
// A kick (power event, step 1-2) and a conflicting topic change (non-power,
// step 3-4) are independent conflicts in the same resolution. The kick must
// resolve correctly regardless of the unrelated topic conflict being
// resolved alongside it.
// ---------------------------------------------------------------------------
SCENARIO("State resolution v2: a kick survives alongside an unrelated conflicting topic change",
         "[conformance][state-resolution][v2][state_res_v2]")
{
    GIVEN("a fork that both kicks a member and changes the room topic")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_create_event("@alice:example.org", "$create:example.org", 100);
        auto const power_levels = make_power_levels_event("@alice:example.org", "$pl:example.org", 200, 1);
        // Invite-only, not public: a public join_rule would let @bob's
        // original join re-admit him unconditionally when it is re-checked
        // in step 4 (mainline ordering) against the already-kicked state,
        // which is correct behaviour, not something this scenario should
        // exercise — it would make ANY kick alongside a public room
        // unwinnable, regardless of algorithm correctness.
        auto const join_rules =
            make_join_rules_event("invite", "@alice:example.org", "$join_rules:example.org", 300, 0);
        auto const alice_join = make_member_event("@alice:example.org", "$alice_join:example.org", 400, 2);
        auto const bob_join = make_member_event("@bob:example.org", "$bob_join:example.org", 500, 2);

        // Fork A: @alice kicks @bob, and sets the topic to "a".
        auto const kick =
            make_event_with_auth("m.room.member", "@bob:example.org", "$kick:example.org", "@alice:example.org", 5000,
                                 {"$create:example.org", "$pl:example.org"}, R"({"membership":"leave"})");
        auto const topic_a = make_event_with_auth("m.room.topic", "", "$topic_a:example.org", "@alice:example.org", 600,
                                                  {"$create:example.org", "$pl:example.org"}, R"({"topic":"a"})");

        // Fork B: @bob stays joined, and the topic is set to "b".
        auto const topic_b = make_event_with_auth("m.room.topic", "", "$topic_b:example.org", "@alice:example.org", 700,
                                                  {"$create:example.org", "$pl:example.org"}, R"({"topic":"b"})");

        // @bob's (m.room.member, "@bob:example.org") key is the conflict:
        // fork A's current value is the kick, fork B's is the original join.
        // A group's flat state must carry exactly one event per key, so
        // $bob_join and $kick cannot both appear in group_a.
        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, power_levels, join_rules, alice_join, kick, topic_a};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, power_levels, join_rules, alice_join, bob_join, topic_b};

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("both the kick and the topic conflict resolve, independently of each other")
            {
                REQUIRE(result.resolved);
                auto const* member = result_event_for(result, "m.room.member", "@bob:example.org");
                REQUIRE(member != nullptr);
                // Spec MUST: @alice (power 100) kicking @bob (power 0) is
                // authorised, and the kick must survive alongside the
                // unrelated topic conflict, not be silently dropped by it.
                REQUIRE(member->event_id == "$kick:example.org");

                auto const* topic = result_event_for(result, "m.room.topic", "");
                REQUIRE(topic != nullptr);
                auto const& topic_winner = topic->event_id;
                REQUIRE((topic_winner == "$topic_a:example.org" || topic_winner == "$topic_b:example.org"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: Matrix v1.19 — Room v2 state resolution, Algorithm steps 1-4.
// URL: ../../docs/matrix-v1.19-spec/rooms/v10.md
//
// Join-rule evasion: a join is a non-power event (step 3-4), processed
// AFTER the conflicting join_rules change (a power event, step 1-2) has
// already been resolved. A user cannot "evade" a concurrent tightening of
// the join rule by joining on the fork that still has the old, looser rule —
// their join is authorised against the room's ALREADY-RESOLVED join_rules,
// not the value on their own fork.
// ---------------------------------------------------------------------------
SCENARIO("State resolution v2: a join cannot evade a concurrently tightened join rule",
         "[conformance][state-resolution][v2][state_res_v2]")
{
    GIVEN("a fork where the join rule is tightened to invite-only while, concurrently, a user tries to self-join")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const create = make_create_event("@alice:example.org", "$create:example.org", 100);
        auto const power_levels = make_power_levels_event("@alice:example.org", "$pl:example.org", 200, 1);
        auto const alice_join = make_member_event("@alice:example.org", "$alice_join:example.org", 300, 2);

        // Fork A: join_rule stays public, and @bob joins under it.
        auto const join_rules_public =
            make_join_rules_event("public", "@alice:example.org", "$join_rules_public:example.org", 400, 3);
        auto const bob_join = make_member_event("@bob:example.org", "$bob_join:example.org", 500, 4);

        // Fork B: the join rule is tightened to invite-only, at a LATER
        // origin_server_ts than the public rule, so it wins the reverse
        // topological power ordering (both candidates share the same sender
        // and power) and becomes the resolved join_rules before @bob's join
        // is ever auth-checked.
        auto const join_rules_invite =
            make_join_rules_event("invite", "@alice:example.org", "$join_rules_invite:example.org", 600, 3);

        auto group_a = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state = {create, power_levels, alice_join, join_rules_public, bob_join};

        auto group_b = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state = {create, power_levels, alice_join, join_rules_invite};

        auto request = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the tightened join rule wins, and @bob's join does not survive")
            {
                REQUIRE(result.resolved);
                auto const* join_rules_winner = result_event_for(result, "m.room.join_rules", "");
                REQUIRE(join_rules_winner != nullptr);
                REQUIRE(join_rules_winner->event_id == "$join_rules_invite:example.org");

                // Spec MUST: @bob's join is auth-checked against the
                // resolved (invite-only) join_rules, not the public rule on
                // his own fork — @bob was never invited, so the join is
                // denied and @bob's key has no winner at all (his was the
                // only candidate for that key).
                REQUIRE(result_event_for(result, "m.room.member", "@bob:example.org") == nullptr);
            }
        }
    }
}
