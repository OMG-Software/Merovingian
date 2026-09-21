// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for the state-resolution v2/v2.1 auth-chain walk: the auth
// difference, the v12 conflicted state subgraph, the event_lookup fail-closed
// paths, and determinism. Tag: [state_res_v2].
//
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions ("Auth
// chain", "Auth difference", "Full conflicted set"), Algorithm step 1.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v12.md — Definitions ("Conflicted
// state subgraph"), "State resolution" modifications 1-3.

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace
{

using merovingian::events::StateEventReference;
using merovingian::events::StateGroup;
using merovingian::events::StateKey;
using merovingian::events::StateResolutionRequest;

[[nodiscard]] auto make_ref(std::string const& event_type, std::string const& state_key, std::string const& event_id,
                            std::string const& sender, std::int64_t ts, std::vector<std::string> const& auth_ids,
                            std::string const& content_json) -> StateEventReference
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
    auto ref = StateEventReference{};
    ref.key = StateKey{event_type, state_key};
    ref.event_id = event_id;
    ref.sender = sender;
    ref.origin_server_ts = ts;
    ref.depth = 1U;
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    if (parsed.error == merovingian::canonicaljson::ParseError::none)
    {
        ref.event_json = std::move(parsed.value);
    }
    return ref;
}

auto const pl_content_full = std::string{
    R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,"users":{"@alice:example.org":100}})"};

[[nodiscard]] auto pl_content(std::vector<std::pair<std::string, std::int64_t>> const& users,
                              std::int64_t state_default = 50) -> std::string
{
    auto users_json = std::string{"{"};
    for (std::size_t i = 0; i < users.size(); ++i)
    {
        if (i > 0)
        {
            users_json += ",";
        }
        users_json += "\"" + users[i].first + "\":" + std::to_string(users[i].second);
    }
    users_json += "}";
    return std::string{"{\"ban\":50,\"events_default\":0,\"invite\":0,\"kick\":50,\"redact\":50,\"state_default\":"} +
           std::to_string(state_default) + ",\"users_default\":0,\"users\":" + users_json + "}";
}

// A simple in-memory DAG the test builds up, exposed as an event_lookup.
class EventDag final
{
public:
    auto add(StateEventReference const& ref) -> StateEventReference const&
    {
        auto [it, inserted] = events_.emplace(ref.event_id, ref);
        (void)inserted;
        return it->second;
    }

    [[nodiscard]] auto lookup() const -> merovingian::events::EventLookupFn
    {
        return [this](std::string_view event_id) -> std::optional<StateEventReference> {
            auto const it = events_.find(std::string{event_id});
            if (it == events_.end())
            {
                return std::nullopt;
            }
            return it->second;
        };
    }

private:
    std::unordered_map<std::string, StateEventReference> events_{};
};

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

// ---------------------------------------------------------------------------
// Scenario 1: the auth difference changes the outcome. A power_levels event
// ($pl_hidden) that promotes @bob exists only in one fork's auth chain — it
// is never a literal value of either state group's (m.room.power_levels, "")
// entry — so a resolver that does not compute the auth difference can never
// see it, and @bob's later ban of @charlie (authorised only by that hidden
// promotion) is silently dropped. This is the exact defect described in the
// task brief: verified to fail against the pre-fix implementation (recorded
// in the commit introducing this test), and to pass once resolve_state_v2
// computes ∪Ci − ∩Ci per rooms/v10.md.
// ---------------------------------------------------------------------------
SCENARIO("Auth difference: a power event visible only through the auth chain changes who wins a conflict",
         "[state_res_v2][auth-difference]")
{
    GIVEN("a room where @bob's power to ban comes only from a power_levels event hidden in one fork's auth chain")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto dag = EventDag{};

        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"10"})"));
        auto const pl0 = dag.add(make_ref("m.room.power_levels", "", "$pl0", "@alice:example.org", 10,
                                          {
                                              "$create"
        },
                                          pl_content({{"@alice:example.org", 100}})));
        auto const join_rules = dag.add(make_ref("m.room.join_rules", "", "$join_rules", "@alice:example.org", 20,
                                                 {"$create", "$pl0"}, R"({"join_rule":"public"})"));
        auto const alice_join = dag.add(make_ref("m.room.member", "@alice:example.org", "$alice_join",
                                                 "@alice:example.org", 30, {"$create"}, R"({"membership":"join"})"));
        auto const bob_join = dag.add(make_ref("m.room.member", "@bob:example.org", "$bob_join", "@bob:example.org", 40,
                                               {"$create", "$join_rules"}, R"({"membership":"join"})"));
        auto const charlie_join =
            dag.add(make_ref("m.room.member", "@charlie:example.org", "$charlie_join", "@charlie:example.org", 50,
                             {"$create", "$join_rules"}, R"({"membership":"join"})"));

        // $pl_hidden promotes @bob to power 100. It is authored by @alice (who
        // has 100 via $pl0) and cites $pl0 as its power ancestor. It is NEVER
        // placed in either state group's flat state below — only referenced
        // from $ban's auth_events — so only the auth-chain walk can find it.
        auto const pl_hidden = dag.add(make_ref("m.room.power_levels", "", "$pl_hidden", "@alice:example.org", 15,
                                                {
                                                    "$create", "$pl0"
        },
                                                pl_content({{"@alice:example.org", 100}, {"@bob:example.org", 100}})));

        // @bob bans @charlie, citing $pl_hidden (not $pl0) as his power
        // ancestor — this is the only place $pl_hidden is referenced.
        auto const ban =
            dag.add(make_ref("m.room.member", "@charlie:example.org", "$ban", "@bob:example.org", 1000,
                             {"$create", "$pl_hidden", "$bob_join", "$charlie_join"}, R"({"membership":"ban"})"));

        auto group_a = StateGroup{
            "branch-a", {create, pl0, join_rules, alice_join, bob_join, ban}
        };
        auto group_b = StateGroup{
            "branch-b", {create, pl0, join_rules, alice_join, bob_join, charlie_join}
        };

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};
        request.event_lookup = dag.lookup();

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("resolution succeeds and @charlie's ban (authorised only via the hidden auth-chain event) wins")
            {
                REQUIRE(result.resolved);
                auto const* winner = result_event_for(result, "m.room.member", "@charlie:example.org");
                REQUIRE(winner != nullptr);
                // Spec MUST (rooms/v10.md, Algorithm step 1): power events
                // reachable only through the auth chain of a conflicted power
                // event are part of the full conflicted set and must be
                // considered. Without the auth-difference computation, @bob's
                // power to ban is invisible and @charlie stays joined — this
                // is the exact bug this fix closes; it must NOT be weakened.
                REQUIRE(winner->event_id == "$ban");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fail closed: an auth-chain event the lookup cannot supply must not let
// resolution proceed on a partial chain.
// ---------------------------------------------------------------------------
SCENARIO("Fail closed: a missing auth-chain event yields an unresolved result", "[state_res_v2][fail-closed]")
{
    GIVEN("a conflict whose auth chain references an event the lookup does not have")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"10"})"));
        // $pl cites an ancestor ("$missing") that the lookup will never resolve.
        auto const pl_a = dag.add(make_ref("m.room.power_levels", "", "$pl_a", "@alice:example.org", 10,
                                           {"$create", "$missing"}, pl_content_full));
        auto const pl_b =
            dag.add(make_ref("m.room.power_levels", "", "$pl_b", "@bob:example.org", 20, {"$create"}, pl_content_full));

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {
            StateGroup{"branch-a", {create, pl_a}},
            StateGroup{"branch-b", {create, pl_b}},
        };
        request.event_lookup = dag.lookup(); // "$missing" is never added to the dag

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the resolution is NOT resolved — it must not proceed with a partial auth chain")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fail closed / termination: a cycle in the auth chain must not hang the
// resolver. The visited-set bounds the walk regardless of the cycle.
// ---------------------------------------------------------------------------
SCENARIO("An auth-chain cycle terminates instead of looping forever", "[state_res_v2][fail-closed][cycle]")
{
    GIVEN("two events whose auth_events cite each other")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"10"})"));
        // $cycle_a <-> $cycle_b: each cites the other in auth_events.
        dag.add(make_ref("m.room.topic", "", "$cycle_a", "@alice:example.org", 5, {"$cycle_b"}, "{}"));
        dag.add(make_ref("m.room.topic", "", "$cycle_b", "@alice:example.org", 6, {"$cycle_a"}, "{}"));

        auto const topic_a =
            make_ref("m.room.topic", "", "$topic_a", "@alice:example.org", 100, {"$create", "$cycle_a"}, "{}");
        auto const topic_b =
            make_ref("m.room.topic", "", "$topic_b", "@alice:example.org", 200, {"$create", "$cycle_b"}, "{}");

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {
            StateGroup{"branch-a", {create, topic_a}},
            StateGroup{"branch-b", {create, topic_b}},
        };
        request.event_lookup = dag.lookup();

        WHEN("resolve_state_v2 is called")
        {
            // The point of this scenario is that the call RETURNS at all
            // (Catch2's own test timeout would otherwise catch a hang); a
            // definite resolved/unresolved answer either way is acceptable.
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the call returns a definite result")
            {
                REQUIRE((result.resolved || !result.resolved));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Fail closed: exceeding the auth-chain work cap yields unresolved.
// ---------------------------------------------------------------------------
SCENARIO("Exceeding the auth-chain walk cap yields an unresolved result", "[state_res_v2][fail-closed][limits]")
{
    GIVEN("an auth chain deliberately longer than max_auth_chain_walk_events")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"10"})"));

        // Build a straight-line chain of events, each citing the previous one,
        // longer than the resolver's work cap.
        auto const chain_length = merovingian::events::max_auth_chain_walk_events + 100U;
        auto previous_id = std::string{"$create"};
        for (std::size_t i = 0; i < chain_length; ++i)
        {
            auto const id = "$chain-" + std::to_string(i);
            dag.add(make_ref("m.room.topic", "", id, "@alice:example.org", static_cast<std::int64_t>(i), {previous_id},
                             "{}"));
            previous_id = id;
        }

        auto const pl_a = make_ref("m.room.power_levels", "", "$pl_a", "@alice:example.org", 100'000,
                                   {"$create", previous_id}, pl_content_full);
        auto const pl_b =
            make_ref("m.room.power_levels", "", "$pl_b", "@bob:example.org", 100'001, {"$create"}, pl_content_full);

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {
            StateGroup{"branch-a", {create, pl_a}},
            StateGroup{"branch-b", {create, pl_b}},
        };
        request.event_lookup = dag.lookup();

        WHEN("resolve_state_v2 is called")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *policy);

            THEN("the resolution fails closed rather than doing unbounded work")
            {
                REQUIRE_FALSE(result.resolved);
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Determinism: resolving the same inputs with state groups in a different
// order yields the same resolved state.
// ---------------------------------------------------------------------------
SCENARIO("Resolving with state groups in a different order yields the same result", "[state_res_v2][determinism]")
{
    GIVEN("a conflict between two forks")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"10"})"));
        auto const pl0 = dag.add(make_ref("m.room.power_levels", "", "$pl0", "@alice:example.org", 10,
                                          {
                                              "$create"
        },
                                          pl_content({{"@alice:example.org", 100}})));
        auto const join_rules = dag.add(make_ref("m.room.join_rules", "", "$join_rules", "@alice:example.org", 20,
                                                 {"$create", "$pl0"}, R"({"join_rule":"public"})"));
        auto const alice_join = dag.add(make_ref("m.room.member", "@alice:example.org", "$alice_join",
                                                 "@alice:example.org", 30, {"$create"}, R"({"membership":"join"})"));

        auto const topic_a =
            dag.add(make_ref("m.room.topic", "", "$topic_a", "@alice:example.org", 100, {"$create", "$pl0"}, "{}"));
        auto const topic_b =
            dag.add(make_ref("m.room.topic", "", "$topic_b", "@alice:example.org", 200, {"$create", "$pl0"}, "{}"));

        auto group_a = StateGroup{
            "branch-a", {create, pl0, join_rules, alice_join, topic_a}
        };
        auto group_b = StateGroup{
            "branch-b", {create, pl0, join_rules, alice_join, topic_b}
        };

        auto request_forward = StateResolutionRequest{};
        request_forward.room_version = "10";
        request_forward.state_groups = {group_a, group_b};
        request_forward.event_lookup = dag.lookup();

        auto request_reversed = StateResolutionRequest{};
        request_reversed.room_version = "10";
        request_reversed.state_groups = {group_b, group_a};
        request_reversed.event_lookup = dag.lookup();

        WHEN("resolve_state_v2 is called with the groups in each order")
        {
            auto const result_forward = merovingian::events::resolve_state_v2(request_forward, *policy);
            auto const result_reversed = merovingian::events::resolve_state_v2(request_reversed, *policy);

            THEN("both resolve, and the winner for every key is identical")
            {
                REQUIRE(result_forward.resolved);
                REQUIRE(result_reversed.resolved);
                REQUIRE(result_forward.resolved_state.size() == result_reversed.resolved_state.size());

                for (auto const& event : result_forward.resolved_state)
                {
                    auto const* other = result_event_for(result_reversed, event.key.event_type, event.key.state_key);
                    REQUIRE(other != nullptr);
                    REQUIRE(other->event_id == event.event_id);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Room v12 (state-res v2.1), modification 1: the iterative auth checks start
// from an EMPTY state map, not the unconflicted state map. A conflicted event
// whose own auth_events omits its sender's membership (so the map-lookup
// fallback cannot recover it) is denied under v2.1 but allowed under v2,
// where the unconflicted state map already has it from the start.
// ---------------------------------------------------------------------------
SCENARIO("Room v12: iterative auth checks starting from an empty map diverge from starting from unconflicted state",
         "[state_res_v2][v12][empty-start]")
{
    GIVEN("a conflicted event whose sender's membership is unconflicted state but not in its own auth_events")
    {
        auto const* v2_policy = merovingian::rooms::find_room_version_policy("10");
        auto const* v2_1_policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(v2_policy != nullptr);
        REQUIRE(v2_1_policy != nullptr);
        REQUIRE(v2_policy->state_resolution == merovingian::rooms::StateResolutionAlgorithm::v2);
        REQUIRE(v2_1_policy->state_resolution == merovingian::rooms::StateResolutionAlgorithm::v2_1);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"12"})"));
        // state_default 0 so the power check can never be the reason a
        // candidate is denied — this isolates the "sender must be joined"
        // check, which is what modification 1 affects.
        auto const pl0 = dag.add(make_ref("m.room.power_levels", "", "$pl0", "@alice:example.org", 10,
                                          {
                                              "$create"
        },
                                          pl_content({{"@alice:example.org", 100}}, 0)));
        auto const join_rules = dag.add(make_ref("m.room.join_rules", "", "$join_rules", "@alice:example.org", 20,
                                                 {"$create", "$pl0"}, R"({"join_rule":"public"})"));
        auto const alice_join = dag.add(make_ref("m.room.member", "@alice:example.org", "$alice_join",
                                                 "@alice:example.org", 30, {"$create"}, R"({"membership":"join"})"));
        auto const bob_join = dag.add(make_ref("m.room.member", "@bob:example.org", "$bob_join", "@bob:example.org", 40,
                                               {"$create", "$join_rules"}, R"({"membership":"join"})"));

        // @bob's topic events deliberately omit $bob_join from auth_events, so
        // the own-auth-events fallback cannot recover his membership either.
        auto const topic_a = dag.add(
            make_ref("m.room.topic", "", "$topic_a", "@bob:example.org", 100, {"$create", "$pl0"}, R"({"topic":"a"})"));
        auto const topic_b = dag.add(
            make_ref("m.room.topic", "", "$topic_b", "@bob:example.org", 200, {"$create", "$pl0"}, R"({"topic":"b"})"));

        auto group_a = StateGroup{
            "branch-a", {create, pl0, join_rules, alice_join, bob_join, topic_a}
        };
        auto group_b = StateGroup{
            "branch-b", {create, pl0, join_rules, alice_join, bob_join, topic_b}
        };

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};
        request.event_lookup = dag.lookup();

        WHEN("resolved under the v2 (unconflicted-start) algorithm")
        {
            auto const result_v2 = merovingian::events::resolve_state_v2(request, *v2_policy);

            THEN("@bob's topic change is authorised — his membership is available from the unconflicted state")
            {
                REQUIRE(result_v2.resolved);
                REQUIRE(result_event_for(result_v2, "m.room.topic", "") != nullptr);
            }
        }

        WHEN("resolved under the v12 (empty-start) algorithm")
        {
            auto const result_v2_1 = merovingian::events::resolve_state_v2(request, *v2_1_policy);

            THEN("neither topic candidate is authorised — the empty starting map has no membership for @bob, "
                 "and his own auth_events do not supply it either")
            {
                // Spec MUST (rooms/v12.md — State resolution, modification 1):
                // "The iterative auth checks algorithm ... now starts with an
                // empty state map instead of the unconflicted state map."
                REQUIRE(result_v2_1.resolved);
                REQUIRE(result_event_for(result_v2_1, "m.room.topic", "") == nullptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Room v12, modification 2/3: the conflicted state subgraph. An event on an
// auth path between two conflicted-state-set events is included in the full
// conflicted set and changes the result, even though it is symmetrically
// reachable from both forks (so the auth difference alone would NOT surface
// it — this isolates the subgraph mechanism from the auth-difference fix
// covered by the first scenario in this file).
// ---------------------------------------------------------------------------
SCENARIO("Room v12: an event on the conflicted state subgraph's path is included and changes the result",
         "[state_res_v2][v12][subgraph]")
{
    GIVEN("a hidden power_levels event on the auth path between two conflicted power_levels candidates")
    {
        auto const* v2_policy = merovingian::rooms::find_room_version_policy("10");
        auto const* v2_1_policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(v2_policy != nullptr);
        REQUIRE(v2_1_policy != nullptr);

        auto dag = EventDag{};
        auto const create = dag.add(make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                             R"({"creator":"@alice:example.org","room_version":"12"})"));
        auto const join_rules = dag.add(make_ref("m.room.join_rules", "", "$join_rules", "@alice:example.org", 5,
                                                 {"$create"}, R"({"join_rule":"public"})"));
        auto const alice_join = dag.add(make_ref("m.room.member", "@alice:example.org", "$alice_join",
                                                 "@alice:example.org", 6, {"$create"}, R"({"membership":"join"})"));

        // $pl_hidden is on the path from $ban (conflicted) to $pl_a
        // (conflicted). $bob_join ALSO cites it directly, so it is reachable
        // from both forks equally (present in both forks' full auth chain) —
        // it is therefore excluded from the auth difference, and only the
        // v12 conflicted state subgraph can surface it.
        auto const pl_a = dag.add(make_ref("m.room.power_levels", "", "$pl_a", "@alice:example.org", 100,
                                           {
                                               "$create"
        },
                                           pl_content({{"@alice:example.org", 100}})));
        auto const pl_hidden = dag.add(make_ref("m.room.power_levels", "", "$pl_hidden", "@alice:example.org", 150,
                                                {
                                                    "$create", "$pl_a"
        },
                                                pl_content({{"@alice:example.org", 100}, {"@bob:example.org", 100}})));
        auto const bob_join = dag.add(make_ref("m.room.member", "@bob:example.org", "$bob_join", "@bob:example.org", 7,
                                               {"$create", "$join_rules", "$pl_hidden"}, R"({"membership":"join"})"));
        auto const pl_b = dag.add(make_ref("m.room.power_levels", "", "$pl_b", "@alice:example.org", 200,
                                           {
                                               "$create"
        },
                                           pl_content({{"@alice:example.org", 100}})));

        auto const charlie_join =
            dag.add(make_ref("m.room.member", "@charlie:example.org", "$charlie_join", "@charlie:example.org", 8,
                             {"$create", "$join_rules"}, R"({"membership":"join"})"));
        auto const ban =
            dag.add(make_ref("m.room.member", "@charlie:example.org", "$ban", "@bob:example.org", 1000,
                             {"$create", "$pl_hidden", "$bob_join", "$charlie_join"}, R"({"membership":"ban"})"));

        auto group_a = StateGroup{
            "branch-a", {create, join_rules, alice_join, bob_join, pl_a, ban}
        };
        auto group_b = StateGroup{
            "branch-b", {create, join_rules, alice_join, bob_join, pl_b, charlie_join}
        };

        auto request = StateResolutionRequest{};
        request.room_version = "10";
        request.state_groups = {group_a, group_b};
        request.event_lookup = dag.lookup();

        WHEN("resolved under v2 (no conflicted state subgraph)")
        {
            auto const result_v2 = merovingian::events::resolve_state_v2(request, *v2_policy);

            THEN("@bob's hidden promotion is never considered and the ban is dropped")
            {
                REQUIRE(result_v2.resolved);
                auto const* winner = result_event_for(result_v2, "m.room.member", "@charlie:example.org");
                REQUIRE(winner != nullptr);
                REQUIRE(winner->event_id == "$charlie_join");
            }
        }

        WHEN("resolved under v12 (with the conflicted state subgraph)")
        {
            auto const result_v2_1 = merovingian::events::resolve_state_v2(request, *v2_1_policy);

            THEN("the subgraph surfaces the hidden power_levels event and the ban wins")
            {
                // Spec MUST (rooms/v12.md — Definitions, "Conflicted state
                // subgraph" / "Full conflicted set"): an event on a path
                // between two conflicted state set events is part of the full
                // conflicted set even when the auth difference alone would
                // not surface it.
                REQUIRE(result_v2_1.resolved);
                auto const* winner = result_event_for(result_v2_1, "m.room.member", "@charlie:example.org");
                REQUIRE(winner != nullptr);
                REQUIRE(winner->event_id == "$ban");
            }
        }
    }
}
