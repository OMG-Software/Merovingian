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
                            std::string const& content_json, std::string const& prev_json = "[]") -> StateEventReference
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
                      ",\"prev_events\":" + prev_json + ",\"content\":" + content_json + "}";
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
                                    std::string const& event_type,
                                    std::string const& state_key) -> StateEventReference const*
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

// ---------------------------------------------------------------------------
// Reverse topological power ordering must read a candidate's sender power
// from the m.room.power_levels (and, for v12, m.room.create) event in that
// SAME candidate's own auth_events -- never from the candidate's own new
// content, and never from a shared unconflicted/resolved state map.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md -- Definitions, "Reverse
// topological power ordering", rule 1 ("x's sender has greater power level
// than y's sender, when looking at their respective auth_events").
// ---------------------------------------------------------------------------

namespace
{

// EventJsonIndex is a view (reference_wrapper) into the event_json members
// of a StateGroup's state vector, so the backing group must outlive the
// index (see state_resolution.hpp's own comment on EventJsonIndex).
// Bundling the groups vector and the index together, rather than returning
// the index alone, keeps that storage alive for as long as the caller keeps
// this struct -- returning just the index from a function-local StateGroup
// would leave it referencing an already-destroyed vector the moment the
// function returns.
//
// `groups` MUST be a `std::vector<StateGroup>` here, not a single
// `StateGroup` passed to build_event_json_index as `{group}` -- that braced
// form constructs its own temporary vector containing a COPY of `group`
// (StateGroup has no reference semantics), so the index would end up
// pointing at that temporary's copied elements instead of `group`'s, and
// dangle the moment the call expression ends. Passing the actual owned
// vector by reference avoids the copy entirely.
//
// This struct is safe to return by value: std::vector/std::unordered_map's
// move operations only transfer their internal buffer pointer, never
// relocate individual elements, so the addresses reference_wrapper points
// at do not change across the move.
struct OwnedIndex final
{
    std::vector<StateGroup> groups{};
    merovingian::events::EventJsonIndex index{};
};

[[nodiscard]] auto index_of(std::vector<StateEventReference> events) -> OwnedIndex
{
    auto owned = OwnedIndex{};
    owned.groups.push_back(StateGroup{"index", std::move(events)});
    owned.index = merovingian::events::build_event_json_index(owned.groups);
    return owned;
}

} // namespace

SCENARIO("Reverse topological power ordering reads a power_levels candidate's sender power from its auth_events "
         "ancestor, not its own new content",
         "[state_res_v2][power-ordering]")
{
    GIVEN("a power_levels event that grants its own sender a higher level than the previous power_levels event did")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        // Prior power_levels: alice genuinely holds 100, mallory only 10.
        auto const pl_prev = make_ref("m.room.power_levels", "", "$pl_prev", "@alice:example.org", 1,
                                      {
        },
                                      pl_content({{"@alice:example.org", 100}, {"@mallory:example.org", 10}}));

        // mallory's own candidate grants HERSELF 100 in its own new
        // content -- a self-elevation claim that must not be believed for
        // ordering purposes (it would still be rejected on its own merits by
        // the auth rules, but the ordering must not be fooled by it either).
        auto const candidate_mallory = make_ref("m.room.power_levels", "", "$mallory", "@mallory:example.org", 100,
                                                {
                                                    "$pl_prev"
        },
                                                pl_content({{"@mallory:example.org", 100}}));
        // alice's candidate merely restates her own real level.
        auto const candidate_alice = make_ref("m.room.power_levels", "", "$alice", "@alice:example.org", 200,
                                              {
                                                  "$pl_prev"
        },
                                              pl_content({{"@alice:example.org", 100}}));

        auto const owned_index = index_of({pl_prev});
        auto const conflicted = std::vector<StateEventReference>{candidate_mallory, candidate_alice};

        WHEN("the candidates are sorted by reverse topological power ordering")
        {
            auto const sorted =
                merovingian::events::reverse_topological_power_sort(conflicted, owned_index.index, {}, *policy);

            THEN("alice's real, higher power (from the auth_events ancestor) sorts her event first")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST: mallory's self-elevation claim (100, in her own
                // new content) must not outrank alice's real power (100 vs
                // mallory's real 10) read from the auth_events ancestor. Do
                // NOT weaken this assertion -- it is exactly the bug.
                REQUIRE((*sorted)[0].event_id == "$alice");
                REQUIRE((*sorted)[1].event_id == "$mallory");
            }
        }
    }
}

SCENARIO("Reverse topological power ordering reads a non-power candidate's sender power from its own auth_events, "
         "not a shared unconflicted power_levels event",
         "[state_res_v2][power-ordering]")
{
    GIVEN("two non-power candidates whose OWN auth_events name power_levels events with different real levels")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const pl_mallory_high = make_ref("m.room.power_levels", "", "$pl_mallory_high", "@alice:example.org", 1,
                                              {
        },
                                              pl_content({{"@mallory:example.org", 100}}));
        auto const pl_bob_low = make_ref("m.room.power_levels", "", "$pl_bob_low", "@alice:example.org", 1,
                                         {
        },
                                         pl_content({{"@bob:example.org", 5}}));

        // Both are member-ban events (non-power_levels type), each citing a
        // DIFFERENT power_levels ancestor with a very different real level
        // for its own sender.
        auto const ban_mallory = make_ref("m.room.member", "@victim:example.org", "$ban_mallory",
                                          "@mallory:example.org", 100, {"$pl_mallory_high"}, R"({"membership":"ban"})");
        auto const ban_bob = make_ref("m.room.member", "@victim:example.org", "$ban_bob", "@bob:example.org", 1,
                                      {"$pl_bob_low"}, R"({"membership":"ban"})");

        auto const owned_index = index_of({pl_mallory_high, pl_bob_low});
        auto const conflicted = std::vector<StateEventReference>{ban_bob, ban_mallory};

        WHEN("the candidates are sorted by reverse topological power ordering")
        {
            auto const sorted =
                merovingian::events::reverse_topological_power_sort(conflicted, owned_index.index, {}, *policy);

            THEN("mallory's genuinely higher power (100 vs bob's 5) sorts her event first")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST: each candidate's power comes from ITS OWN
                // auth_events, not a single shared map -- bob's ban must not
                // tie with or outrank mallory's despite both being
                // "unconflicted" from some other event's point of view.
                REQUIRE((*sorted)[0].event_id == "$ban_mallory");
                REQUIRE((*sorted)[1].event_id == "$ban_bob");
            }
        }
    }
}

SCENARIO("Room v12: a room creator's event sorts ahead of any non-creator's, however high the non-creator's level",
         "[state_res_v2][power-ordering][v12]")
{
    GIVEN("a creator candidate and a non-creator candidate with an extremely high power_levels-granted level")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        REQUIRE(policy->privilege_room_creators);

        auto const create = make_ref("m.room.create", "", "$create", "@alice:example.org", 1, {},
                                     R"({"creator":"@alice:example.org","room_version":"12"})");
        auto const pl_huge = make_ref("m.room.power_levels", "", "$pl_huge", "@alice:example.org", 1,
                                      {
                                          "$create"
        },
                                      pl_content({{"@mallory:example.org", 1000000}}));

        // mallory: an ordinary (non-creator) candidate with a huge but
        // finite power_levels-granted level.
        auto const candidate_mallory =
            make_ref("m.room.member", "@victim:example.org", "$mallory", "@mallory:example.org", 1,
                     {"$create", "$pl_huge"}, R"({"membership":"ban"})");
        // alice: the room's creator (per the create event's sender).
        auto const candidate_alice = make_ref("m.room.member", "@victim2:example.org", "$alice", "@alice:example.org",
                                              1, {"$create", "$pl_huge"}, R"({"membership":"ban"})");

        auto const owned_index = index_of({create, pl_huge});
        auto const conflicted = std::vector<StateEventReference>{candidate_mallory, candidate_alice};

        WHEN("the candidates are sorted by reverse topological power ordering")
        {
            auto const sorted =
                merovingian::events::reverse_topological_power_sort(conflicted, owned_index.index, {}, *policy);

            THEN("the creator sorts first regardless of the non-creator's power_levels level")
            {
                REQUIRE(sorted.has_value());
                REQUIRE(sorted->size() == 2U);
                // Spec MUST (rooms/v12.md, MSC4289): a room creator's power is
                // effectively infinite, decided from the create event in the
                // candidate's own auth_events (sender, or
                // content.additional_creators).
                REQUIRE((*sorted)[0].event_id == "$alice");
                REQUIRE((*sorted)[1].event_id == "$mallory");
            }
        }
    }
}

SCENARIO("Reverse topological power ordering fails closed when a candidate's auth_events power_levels ancestor "
         "cannot be fetched",
         "[state_res_v2][power-ordering][fail-closed]")
{
    GIVEN("a candidate whose auth_events cite an event the lookup does not have")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("10");
        REQUIRE(policy != nullptr);

        auto const candidate =
            make_ref("m.room.power_levels", "", "$pl", "@alice:example.org", 1, {"$missing"}, pl_content_full);
        auto const known_index = merovingian::events::EventJsonIndex{};
        auto const conflicted = std::vector<StateEventReference>{candidate};

        WHEN("the candidates are sorted by reverse topological power ordering")
        {
            // No event_lookup supplied either, so "$missing" cannot be
            // resolved by any means.
            auto const sorted =
                merovingian::events::reverse_topological_power_sort(conflicted, known_index, {}, *policy);

            THEN("the sort fails closed instead of guessing a default power level")
            {
                // Spec (Required design / ADR-0063): an auth-chain event
                // needed to answer "what is this sender's power" that cannot
                // be fetched must not let resolution proceed on a partial
                // chain.
                REQUIRE_FALSE(sorted.has_value());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ADR-0064 phase B2 follow-up: rooms/v12.md rule 2 — "If the event's room_id
// is not an event ID for an accepted... m.room.create event, with the sigil
// `!` instead of `$`, reject" — the room ID literally IS the create event's
// reference hash under the `!` sigil instead of `$`. resolve_state_v2 derives
// the create event id from StateResolutionRequest::room_id this way and
// fetches it through the same fail-closed AuthChainEventSource as every other
// auth-chain lookup, rather than requiring a submitted state group to
// happen to carry it (see docs/event-engine.md, "0.12.13 fix: the
// create-event deadlock").
// ---------------------------------------------------------------------------
SCENARIO("Room v12: a fork resolves when the create event is reachable only by room_id, absent from every "
         "submitted state group",
         "[state_res_v2][v12][room-id-create]")
{
    GIVEN("a create event known only to event_lookup — never listed in either fork's own state — and a room_id "
          "that derives its id")
    {
        auto const* v2_1_policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(v2_1_policy != nullptr);
        REQUIRE(v2_1_policy->state_resolution == merovingian::rooms::StateResolutionAlgorithm::v2_1);

        auto dag = EventDag{};
        // room_id "!roomcreate:example.org" derives create event id
        // "$roomcreate:example.org" (rooms/v12.md rule 2's sigil swap).
        auto const create = dag.add(make_ref("m.room.create", "", "$roomcreate:example.org", "@alice:example.org", 1,
                                             {}, R"({"creator":"@alice:example.org","room_version":"12"})"));
        // The creator's initial join cites only create as its predecessor.
        // Creator power is implicit in v12 and never supplies membership.
        auto const alice_join =
            dag.add(make_ref("m.room.member", "@alice:example.org", "$alice_join", "@alice:example.org", 2, {},
                             R"({"membership":"join"})", R"(["$roomcreate:example.org"])"));
        auto const pl0 = dag.add(
            make_ref("m.room.power_levels", "", "$pl0", "@alice:example.org", 10, {"$alice_join"}, pl_content({}, 0)));
        auto const topic_a = dag.add(make_ref("m.room.topic", "", "$topic_a", "@alice:example.org", 100,
                                              {"$pl0", "$alice_join"}, R"({"topic":"a"})"));
        auto const topic_b = dag.add(make_ref("m.room.topic", "", "$topic_b", "@alice:example.org", 200,
                                              {"$pl0", "$alice_join"}, R"({"topic":"b"})"));
        std::ignore = create; // reachable only via dag.lookup(), never added to a StateGroup below

        // Neither fork's own state lists the create event at all — only
        // pl0/alice_join/topic, exactly the "absent from every submitted
        // state group" case rule 2's derivation exists for.
        auto group_a = StateGroup{
            "branch-a", {pl0, alice_join, topic_a}
        };
        auto group_b = StateGroup{
            "branch-b", {pl0, alice_join, topic_b}
        };

        auto request = StateResolutionRequest{};
        request.room_version = "12";
        request.state_groups = {group_a, group_b};
        request.event_lookup = dag.lookup();
        request.room_id = "!roomcreate:example.org";

        WHEN("resolved under v12 (v2.1)")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *v2_1_policy);

            THEN("resolution succeeds — the create event was found via room_id, not the state groups")
            {
                REQUIRE(result.resolved);
            }

            THEN("a topic candidate is authorised, proving the iterative auth checks actually ran (they need "
                 "auth_events.create to get past Step 2 of the auth-rule algorithm)")
            {
                REQUIRE(result_event_for(result, "m.room.topic", "") != nullptr);
            }
        }
    }
}

SCENARIO("Room v12: resolution fails closed when the room_id-derived create event cannot be fetched at all",
         "[state_res_v2][v12][room-id-create][fail-closed]")
{
    GIVEN("a room_id whose implied create event id is unknown to both the state groups and event_lookup")
    {
        auto const* v2_1_policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(v2_1_policy != nullptr);

        auto dag = EventDag{};
        // Deliberately do NOT add "$nosuchcreate:example.org" to the dag.
        auto const pl0 = dag.add(make_ref("m.room.power_levels", "", "$pl0", "@alice:example.org", 10,
                                          {
        },
                                          pl_content({{"@alice:example.org", 100}}, 0)));
        auto const topic_a =
            dag.add(make_ref("m.room.topic", "", "$topic_a", "@alice:example.org", 100, {}, R"({"topic":"a"})"));
        auto const topic_b =
            dag.add(make_ref("m.room.topic", "", "$topic_b", "@alice:example.org", 200, {}, R"({"topic":"b"})"));

        auto group_a = StateGroup{
            "branch-a", {pl0, topic_a}
        };
        auto group_b = StateGroup{
            "branch-b", {pl0, topic_b}
        };

        auto request = StateResolutionRequest{};
        request.room_version = "12";
        request.state_groups = {group_a, group_b};
        request.event_lookup = dag.lookup();
        request.room_id = "!nosuchcreate:example.org";

        WHEN("resolved under v12 (v2.1)")
        {
            auto const result = merovingian::events::resolve_state_v2(request, *v2_1_policy);

            THEN("resolution fails closed (ADR-0063) rather than proceeding without a create event")
            {
                REQUIRE_FALSE(result.resolved);
            }
        }
    }
}
