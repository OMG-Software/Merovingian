// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX STATE RESOLUTION CONFORMANCE TESTS                       |
// |                                                                         |
// |  Spec: Matrix v1.18 — State Resolution                                  |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/                 |
// |          #room-state-resolution                                          |
// |  v2 algorithm:                                                           |
// |    https://spec.matrix.org/v1.18/server-server-api/                     |
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

// Build a minimal state event for test purposes.
[[nodiscard]] auto make_state_event(std::string event_type, std::string state_key, std::string event_id,
                                    std::string sender, std::int64_t ts, std::uint64_t depth)
    -> StateEventReference
{
    auto ref = StateEventReference{};
    ref.key = {event_type, state_key};
    ref.event_id = event_id;
    ref.sender = sender;
    ref.origin_server_ts = ts;
    ref.depth = depth;
    // Minimal event JSON so the resolution algorithm can read it if needed.
    auto const json =
        std::string{"{\"type\":\""} + event_type + "\",\"state_key\":\"" + state_key + "\",\"sender\":\"" + sender +
        "\",\"event_id\":\"" + event_id + "\",\"origin_server_ts\":" + std::to_string(ts) + "}";
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    if (parsed.error == merovingian::canonicaljson::ParseError::none)
    {
        ref.event_json = std::move(parsed.value);
    }
    return ref;
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
// URL: https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution
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
// URL: https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution
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
// URL: https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution
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
// URL: https://spec.matrix.org/v1.18/server-server-api/#room-state-resolution
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
// URL: https://spec.matrix.org/v1.18/server-server-api/
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
// URL: https://spec.matrix.org/v1.18/server-server-api/
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

        // Both groups agree on the create event.
        auto const create_ev =
            make_state_event("m.room.create", "", "$create:example.org", "@alice:example.org", 1000, 0);
        // The groups disagree on join_rules.
        auto const join_a =
            make_state_event("m.room.join_rules", "", "$join_rules_a:example.org", "@alice:example.org", 1001, 1);
        auto const join_b =
            make_state_event("m.room.join_rules", "", "$join_rules_b:example.org", "@alice:example.org", 1002, 1);

        auto group_a = StateGroup{};
        group_a.group_id = "group_a";
        group_a.state = {create_ev, join_a};

        auto group_b = StateGroup{};
        group_b.group_id = "group_b";
        group_b.state = {create_ev, join_b};

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
// URL: https://spec.matrix.org/v1.18/server-server-api/
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
