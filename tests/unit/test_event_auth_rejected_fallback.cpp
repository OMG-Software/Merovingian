// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace
{
using namespace merovingian;

[[nodiscard]] auto stored_event(std::string id, std::string json,
                                std::string status = "accepted") -> database::PersistentEvent
{
    return {std::move(id), "!create", "@admin:example.org", std::move(json), 1U, 0U, {}, {}, {}, std::move(status)};
}

[[nodiscard]] auto reference(events::EventLookupFn const& lookup, std::string_view id) -> events::StateEventReference
{
    auto ref = lookup(id);
    REQUIRE(ref.has_value());
    return std::move(*ref);
}
} // namespace

// Spec: Matrix v1.19 rooms/v10.md and rooms/v12.md — State resolution,
// Definitions, Iterative auth checks: use own auth_events only if not rejected.
SCENARIO("State resolution cannot recover membership from a rejected own-auth fallback",
         "[events][state-resolution][security][evt-12c-resolution]")
{
    GIVEN("conflicting topics whose only sender membership is in their own auth events")
    {
        using namespace merovingian;
        auto const version = GENERATE("3", "4", "5", "6", "7", "8", "9", "10", "11", "12");
        auto const status = GENERATE("rejected", "accepted", "soft_failed", "outlier");
        auto const indexed = GENERATE(false, true);
        CAPTURE(version, status, indexed);
        auto store = database::PersistentStore{};
        auto const legacy = std::string{version} != "12";
        auto const create_auth = legacy ? R"("$create")" : "";
        auto const topic_auth = legacy ? R"("$create","$pl","$mod_join")" : R"("$pl","$mod_join")";
        store.events.push_back(stored_event(
            "$create",
            R"({"type":"m.room.create","state_key":"","sender":"@admin:example.org","content":{"creator":"@admin:example.org","room_version":")" +
                std::string{version} + R"("},"auth_events":[]})"));
        store.events.push_back(stored_event(
            "$pl",
            R"({"type":"m.room.power_levels","state_key":"","sender":"@admin:example.org","content":{"state_default":50,"users":{"@mod:example.org":50}},"auth_events":[)" +
                std::string{create_auth} + "]}"));
        store.events.push_back(stored_event(
            "$mod_join",
            R"({"type":"m.room.member","state_key":"@mod:example.org","sender":"@mod:example.org","content":{"membership":"join"},"auth_events":[)" +
                std::string{create_auth} + "]}",
            status));
        store.events.push_back(stored_event(
            "$topic_a",
            R"({"type":"m.room.topic","state_key":"","sender":"@mod:example.org","origin_server_ts":10,"content":{"topic":"A"},"auth_events":[)" +
                std::string{topic_auth} + "]}"));
        store.events.push_back(stored_event(
            "$topic_b",
            R"({"type":"m.room.topic","state_key":"","sender":"@mod:example.org","origin_server_ts":20,"content":{"topic":"B"},"auth_events":[)" +
                std::string{topic_auth} + "]}"));
        auto const lookup = homeserver::make_store_event_lookup(store);
        auto const create = reference(lookup, "$create");
        auto const pl = reference(lookup, "$pl");
        auto const topic_a = reference(lookup, "$topic_a");
        auto const topic_b = reference(lookup, "$topic_b");
        auto request = events::StateResolutionRequest{};
        request.room_version = version;
        request.room_id = "!create";
        request.state_groups = {
            {"a", {create, pl, topic_a}},
            {"b", {create, pl, topic_b}}
        };
        request.event_lookup = lookup;
        // v12 starts iterative auth with no unconflicted membership. Exercise
        // both the known-event index and external lookup as fallback sources.
        if (indexed && !legacy)
        {
            auto const member = reference(lookup, "$mod_join");
            for (auto& group : request.state_groups)
            {
                group.state.push_back(member);
            }
        }
        auto const policy = *rooms::find_room_version_policy(version);
        WHEN("the conflicting topics are resolved")
        {
            auto const result = events::resolve_state_v2(request, policy);
            THEN("resolution completes without a topic authorized by rejected membership")
            {
                // Spec MUST: rejected own-auth entries are not used; other receipt statuses are not rejection.
                REQUIRE(result.resolved);
                auto const topic = std::ranges::find_if(result.resolved_state, [](auto const& ref) {
                    return ref.key.event_type == "m.room.topic";
                });
                REQUIRE((topic != result.resolved_state.end()) == (std::string{status} != "rejected"));
            }
        }
    }
}

// Spec: Matrix v1.19 rooms/v10.md — Rejected events: state resolution may
// reconsider events rejected against state, without using rejected own-auth fallback.
SCENARIO("Reauthorized auth-difference candidates retain trusted receipt metadata",
         "[events][state-resolution][security][evt-12c-materialize]")
{
    GIVEN("a receipt-rejected self-join in the auth difference and a public resolved join rule")
    {
        using namespace merovingian;
        auto store = database::PersistentStore{};
        store.events = {
            stored_event(
                "$create",
                R"({"type":"m.room.create","state_key":"","sender":"@admin:example.org","content":{"creator":"@admin:example.org","room_version":"10"},"auth_events":[]})"),
            stored_event(
                "$pl",
                R"({"type":"m.room.power_levels","state_key":"","sender":"@admin:example.org","content":{"state_default":50,"users":{"@admin:example.org":100,"@mod:example.org":50}},"auth_events":["$create"]})"),
            stored_event(
                "$jr",
                R"({"type":"m.room.join_rules","state_key":"","sender":"@admin:example.org","content":{"join_rule":"public"},"auth_events":["$create"]})"),
            stored_event(
                "$admin",
                R"({"type":"m.room.member","state_key":"@admin:example.org","sender":"@admin:example.org","content":{"membership":"join"},"auth_events":["$create","$jr"]})"),
            stored_event(
                "$mod",
                R"({"type":"m.room.member","state_key":"@mod:example.org","sender":"@mod:example.org","origin_server_ts":10,"content":{"membership":"join"},"auth_events":["$create","$jr","$pl"]})",
                "rejected"),
            stored_event(
                "$a",
                R"({"type":"m.room.topic","state_key":"","sender":"@mod:example.org","origin_server_ts":30,"content":{"topic":"A"},"auth_events":["$create","$pl","$mod"]})"),
            stored_event(
                "$b",
                R"({"type":"m.room.topic","state_key":"","sender":"@admin:example.org","origin_server_ts":40,"content":{"topic":"B"},"auth_events":["$create","$pl","$admin"]})")};
        auto const lookup = homeserver::make_store_event_lookup(store);
        auto const create = reference(lookup, "$create");
        auto const pl = reference(lookup, "$pl");
        auto const jr = reference(lookup, "$jr");
        auto const admin = reference(lookup, "$admin");
        auto request = events::StateResolutionRequest{};
        request.room_version = "10";
        request.room_id = "!create";
        request.event_lookup = lookup;
        request.state_groups = {
            {"a", {create, pl, jr, admin, reference(lookup, "$a")}},
            {"b", {create, pl, jr, admin, reference(lookup, "$b")}}
        };
        auto const policy = *rooms::find_room_version_policy("10");
        WHEN("the join is materialized from the auth difference and reauthorized")
        {
            auto const result = events::resolve_state_v2(request, policy);
            THEN("the candidate is not blanket-discarded and its receipt metadata is not erased")
            {
                REQUIRE(result.resolved);
                auto const member = std::ranges::find_if(result.resolved_state, [](auto const& ref) {
                    return ref.event_id == "$mod";
                });
                REQUIRE(member != result.resolved_state.end());
                REQUIRE(member->rejected);
            }
        }
    }
}

// Characterization only, NOT a conformance claim or an EVT-12(d) fix.
// Matrix v1.19 rooms/v3.md-v5.md allow finite float levels with truncation;
// the existing strict event pipeline still rejects them and is left unchanged.
SCENARIO("Legacy floating power levels remain a fail-closed compatibility gap",
         "[events][security][evt-12d-characterization]")
{
    GIVEN("a legacy power-level event with a finite fractional scalar")
    {
        using namespace merovingian;
        auto const version = GENERATE("3", "4", "5");
        auto const json =
            R"({"type":"m.room.power_levels","state_key":"","sender":"@admin:example.org","content":{"state_default":50.57}})";
        auto const parsed = canonicaljson::parse_json(json);
        REQUIRE(parsed.error == canonicaljson::ParseError::none);
        auto auth = events::AuthEventMap{};
        auto const create = canonicaljson::parse_lossless(
            R"({"type":"m.room.create","state_key":"","sender":"@admin:example.org","content":{"creator":"@admin:example.org","room_version":")" +
            std::string{version} + R"("}})");
        REQUIRE(create.error == canonicaljson::ParseError::none);
        auth.create = create.value;
        auth.sender_member =
            canonicaljson::parse_lossless(
                R"({"type":"m.room.member","state_key":"@admin:example.org","sender":"@admin:example.org","content":{"membership":"join"}})")
                .value;
        auto const policy = *rooms::find_room_version_policy(version);
        WHEN("authorization receives the fractional scalar")
        {
            auto const result = events::authorize_event_against_auth_events(parsed.value, policy, auth);
            THEN("the existing implementation refuses it rather than granting permission")
            {
                REQUIRE_FALSE(result.allowed);
                REQUIRE(result.reason == "state_default must be an integer");
                REQUIRE(canonicaljson::parse_lossless(json).error == canonicaljson::ParseError::invalid_number);
            }
        }
    }
}
