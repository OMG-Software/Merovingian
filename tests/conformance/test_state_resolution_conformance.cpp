// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX STATE RESOLUTION CONFORMANCE TESTS                       |
// |                                                                         |
// |  Spec: Matrix v1.18 — State Resolution                                  |
// |  URL:  ../../docs/matrix-v1.18-spec/server-server-api.md                 |
// |          #room-state-resolution                                          |
// |  v2 algorithm:                                                           |
// |    ../../docs/matrix-v1.18-spec/server-server-api.md                     |
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
                                   std::string const& event_id, std::string const& sender,
                                   std::int64_t ts, std::uint64_t depth,
                                   std::string const& json) -> StateEventReference
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
                                    std::string sender, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto const json =
        std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key + "\",\"sender\":\"" + sender +
        "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) + ",\"content\":{}}";
    return make_event_ref(event_type, state_key, event_id, sender, ts, depth, json);
}

// Build an m.room.create event with creator in content.
// Auth checks (v6+) require content.creator to exist (auth rule Step 3).
[[nodiscard]] auto make_create_event(std::string const& creator, std::string const& event_id,
                                      std::int64_t ts) -> StateEventReference
{
    auto const json =
        std::string{"{\"type\":\"m.room.create\",\"state_key\":\"\",\"sender\":\""} + creator +
        "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
        ",\"content\":{\"creator\":\"" + creator + "\",\"room_version\":\"10\"}}";
    return make_event_ref("m.room.create", "", event_id, creator, ts, 0, json);
}

// Build an m.room.member join event for a user.
[[nodiscard]] auto make_member_event(std::string user_id, std::string event_id, std::int64_t ts,
                                     std::uint64_t depth) -> StateEventReference
{
    auto const json = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + user_id +
                      "\",\"sender\":\"" + user_id +
                      "\",\"event_id\":\"" + event_id +
                      "\",\"origin_server_ts\":" + std::to_string(ts) +
                      ",\"content\":{\"membership\":\"join\"}}";
    return make_event_ref("m.room.member", user_id, event_id, user_id, ts, depth, json);
}

// Build an m.room.power_levels event granting a specific user level 100.
[[nodiscard]] auto make_power_levels_event(std::string const& sender, std::string const& event_id,
                                            std::int64_t ts, std::uint64_t depth) -> StateEventReference
{
    auto const json =
        std::string{"{\"type\":\"m.room.power_levels\",\"state_key\":\"\",\"sender\":\""} + sender +
        "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) +
        ",\"content\":{\"ban\":50,\"events_default\":0,\"invite\":0,\"kick\":50,\"redact\":50,"
        "\"state_default\":50,\"users\":{\"" + sender + "\":100},\"users_default\":0}}";
    return make_event_ref("m.room.power_levels", "", event_id, sender, ts, depth, json);
}

// Returns true if `event_id` appears in `result.resolved_state`.
[[nodiscard]] auto result_contains_event(merovingian::events::StateResolutionResult const& result,
                                         std::string const& event_id) -> bool
{
    return std::any_of(result.resolved_state.begin(), result.resolved_state.end(),
                       [&](StateEventReference const& r) { return r.event_id == event_id; });
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

// Spec: Matrix v1.18 — State Resolution
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution
//
// When a single state group is provided (no fork), the resolved state is that
// group's state — there is nothing to conflict on. This is the common case
// for append-only room history.
SCENARIO("State resolution v1: single state group is returned unchanged",
         "[state-resolution][conformance][v1]")
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

// Spec: Matrix v1.18 — State Resolution
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution
//
// When two state groups agree on every (type, state_key) pair, the resolved
// state is identical to both groups — there is no conflict to resolve.
SCENARIO("State resolution v1: identical state groups produce no conflict",
         "[state-resolution][conformance][v1]")
{
    GIVEN("two state groups with the same events")
    {
        auto const ev = make_state_event("m.room.member", "@alice:example.org", "$join:example.org",
                                         "@alice:example.org", 1000, 1);

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

// Spec: Matrix v1.18 — State Resolution
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution
//
// When two forks have different events for the same (type, state_key), the
// event with the greater depth wins. On a depth tie the lexicographically
// smaller event ID wins (v1 algorithm).
SCENARIO("State resolution v1: conflicting events — greater depth wins",
         "[state-resolution][conformance][v1]")
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

// Spec: Matrix v1.18 — State Resolution
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#room-state-resolution
//
// On equal depth, the lexicographically smaller event ID wins (v1 tiebreak).
// The spec says: "If two events are at the same depth the event with the
// smallest event ID (lexicographically) is used."
SCENARIO("State resolution v1: depth tie broken by lexicographically smaller event ID",
         "[state-resolution][conformance][v1]")
{
    GIVEN("two state groups with conflicting events at equal depth")
    {
        auto const event_aaa = make_state_event("m.room.join_rules", "", "$aaa:example.org",
                                                "@alice:example.org", 1000, 3);
        auto const event_zzz = make_state_event("m.room.join_rules", "", "$zzz:example.org",
                                                "@alice:example.org", 2000, 3);

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

// Spec: Matrix v1.18 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md
//       #state-resolution-algorithm-for-room-versions-2-through-10
//
// resolve_state_v2 requires a room version policy. For a single state group
// the resolved state is that group's complete state.
SCENARIO("State resolution v2 (SDSS): single state group is returned unchanged",
         "[state-resolution][conformance][v2]")
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

// Spec: Matrix v1.18 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md
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
        auto const create_ev  = make_create_event("@alice:example.org", "$create:example.org", 1000);
        auto const power_ev   = make_power_levels_event("@alice:example.org", "$power:example.org", 1001, 1);
        auto const alice_mbr  = make_member_event("@alice:example.org", "$alice_member:example.org", 1002, 2);
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

// Spec: Matrix v1.18 — State Resolution (v2 / SDSS)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md
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
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md
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

        // Group A: @charlie has membership=join (depth=10).
        auto const join_event = make_state_event(
            "m.room.member", "@charlie:example.org", "$charlie_join:example.org",
            "@charlie:example.org", 1000, 10);

        // Group B: @charlie has membership=leave (depth=5).
        auto const leave_event = make_state_event(
            "m.room.member", "@charlie:example.org", "$charlie_leave:example.org",
            "@charlie:example.org", 2000, 5);

        auto request         = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a     = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(create);
        group_a.state.push_back(join_event);

        auto group_b     = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(create);
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
                    if (ref.key.event_type == "m.room.member" &&
                        ref.key.state_key == "@charlie:example.org")
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
        auto const create = make_state_event(
            "m.room.create", "", "$create:example.org",
            "@alice:example.org", 500, 0);

        // Conflicting: Group A has @bob=join (depth 8), Group B has @bob=leave (depth 3).
        auto const bob_join = make_state_event(
            "m.room.member", "@bob:example.org", "$bob_join:example.org",
            "@bob:example.org", 1000, 8);
        auto const bob_leave = make_state_event(
            "m.room.member", "@bob:example.org", "$bob_leave:example.org",
            "@bob:example.org", 2000, 3);

        auto request         = merovingian::events::StateResolutionRequest{};
        request.room_version = "10";

        auto group_a     = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(create);
        group_a.state.push_back(bob_join);

        auto group_b     = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(create);
        group_b.state.push_back(bob_leave);

        request.state_groups.push_back(std::move(group_a));
        request.state_groups.push_back(std::move(group_b));

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the result is resolved with exactly two state entries")
            {
                REQUIRE(result.resolved);
                // Expect: the create event + the winning bob membership.
                REQUIRE(result.resolved_state.size() == 2U);
            }

            THEN("the create event appears in the resolved state (unconflicted)")
            {
                auto const found_create = std::ranges::any_of(
                    result.resolved_state,
                    [](merovingian::events::StateEventReference const& r)
                    {
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
                    if (ref.key.event_type == "m.room.member" &&
                        ref.key.state_key == "@bob:example.org")
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
        auto const shared_create = make_state_event(
            "m.room.create", "", "$create:example.org",
            "@alice:example.org", 500, 0);

        // Conflicting: same key, different event_id in each group.
        auto const alice_join = make_state_event(
            "m.room.member", "@alice:example.org", "$alice_join:example.org",
            "@alice:example.org", 600, 1);
        auto const alice_leave = make_state_event(
            "m.room.member", "@alice:example.org", "$alice_leave:example.org",
            "@alice:example.org", 700, 2);

        auto group_a     = merovingian::events::StateGroup{};
        group_a.group_id = "branch-a";
        group_a.state.push_back(shared_create);
        group_a.state.push_back(alice_join);

        auto group_b     = merovingian::events::StateGroup{};
        group_b.group_id = "branch-b";
        group_b.state.push_back(shared_create);
        group_b.state.push_back(alice_leave);

        auto const groups = std::vector<merovingian::events::StateGroup>{group_a, group_b};

        WHEN("partition_conflicted_state is called")
        {
            auto const [unconflicted, conflicted] =
                merovingian::events::partition_conflicted_state(groups);

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
                auto const member_key =
                    merovingian::events::StateKey{"m.room.member", "@alice:example.org"};
                REQUIRE(conflicted.count(member_key) == 1U);
            }
        }
    }
}
