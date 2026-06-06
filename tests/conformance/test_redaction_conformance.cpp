// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX REDACTION CONFORMANCE TESTS                        |
// |                                                                         |
// |  Spec: Matrix v1.18 — Redaction rules per room version                 |
// |  v1–v10: https://spec.matrix.org/v1.18/rooms/v10/#redactions           |
// |  v11+:   https://spec.matrix.org/v1.18/rooms/v11/#redactions           |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the redaction           |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/events/redaction.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto redact_event(std::string_view event_json, std::string_view room_version) -> std::string
{
    auto const* policy = merovingian::rooms::find_room_version_policy(room_version);
    if (policy == nullptr)
    {
        return "POLICY_NOT_FOUND";
    }
    auto const parsed = merovingian::canonicaljson::parse_lossless(event_json);
    if (parsed.error != merovingian::canonicaljson::ParseError::none)
    {
        return "PARSE_ERROR";
    }
    auto const redacted = merovingian::events::redact_event(parsed.value, *policy);
    if (!redacted.error.empty())
    {
        return "REDACT_ERROR: " + redacted.error;
    }
    auto const serialized = merovingian::canonicaljson::serialize_canonical(redacted.event);
    if (serialized.error != merovingian::canonicaljson::CanonicalJsonError::none)
    {
        return "SERIALIZE_ERROR";
    }
    return serialized.output;
}

[[nodiscard]] auto has_field(std::string_view json, std::string_view field) -> bool
{
    auto const key = '"' + std::string{field} + '"';
    return json.find(key) != std::string_view::npos;
}

} // namespace

// ---------------------------------------------------------------------------
// Spec: v1–v10 redaction rules
// URL:  https://spec.matrix.org/v1.18/rooms/v10/#redactions
//
// Top-level fields preserved: event_id, type, room_id, sender, state_key,
//   content, hashes, signatures, depth, prev_events, auth_events, origin,
//   origin_server_ts, membership
//
// Content fields preserved per event type:
//   m.room.member:            membership
//   m.room.create:            creator
//   m.room.join_rules:        join_rule
//   m.room.power_levels:      ban, events, events_default, kick, redact,
//                              state_default, users, users_default
//   m.room.history_visibility: history_visibility
//   m.room.aliases:           aliases
// ---------------------------------------------------------------------------

SCENARIO("Redaction v1-v10: top-level fields are preserved as per spec",
         "[conformance][redaction][v10]")
{
    GIVEN("an m.room.message event with many top-level fields")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:example.org","type":"m.room.message","room_id":"!r:example.org",)"
            R"("sender":"@alice:example.org","origin":"example.org","origin_server_ts":1000,)"
            R"("depth":2,"prev_events":["$p:x"],"auth_events":["$a:x"],)"
            R"("hashes":{"sha256":"abc"},"signatures":{"example.org":{"ed25519:1":"sig"}},)"
            R"("unsigned":{"age":100},"membership":"join",)"
            R"("content":{"body":"hello","msgtype":"m.text"}})"};

        WHEN("the event is redacted under v10 rules")
        {
            auto const result = redact_event(event_json, "10");
            REQUIRE_FALSE(result.empty());

            THEN("all spec-required top-level fields are present after redaction")
            {
                // Spec MUST: these fields survive redaction in v1-v10.
                REQUIRE(has_field(result, "event_id"));
                REQUIRE(has_field(result, "type"));
                REQUIRE(has_field(result, "room_id"));
                REQUIRE(has_field(result, "sender"));
                REQUIRE(has_field(result, "hashes"));
                REQUIRE(has_field(result, "signatures"));
                REQUIRE(has_field(result, "depth"));
                REQUIRE(has_field(result, "prev_events"));
                REQUIRE(has_field(result, "auth_events"));
                REQUIRE(has_field(result, "origin_server_ts"));
                // Spec (v1-v10): origin and membership ARE preserved pre-v11.
                REQUIRE(has_field(result, "origin"));
            }

            THEN("non-preserved top-level fields are stripped after redaction")
            {
                // Spec MUST: unsigned is never preserved in any version.
                REQUIRE_FALSE(has_field(result, "unsigned"));
            }

            THEN("non-member content fields are stripped after redaction")
            {
                // Spec MUST: m.room.message content is fully stripped (body, msgtype removed).
                REQUIRE_FALSE(has_field(result, "body"));
                REQUIRE_FALSE(has_field(result, "msgtype"));
            }
        }
    }
}

SCENARIO("Redaction v1-v10: m.room.member preserves only membership from content",
         "[conformance][redaction][v10][member]")
{
    GIVEN("an m.room.member event with several content fields")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.member","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"@a:x","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},"content":{"membership":"join",)"
            R"("displayname":"Alice","avatar_url":"mxc://x/y",)"
            R"("join_authorised_via_users_server":"@server:x","reason":"hello"}})"};

        WHEN("the event is redacted under v10")
        {
            auto const result = redact_event(event_json, "10");

            THEN("membership is preserved and non-spec content fields are stripped")
            {
                // Spec MUST: membership survives redaction.
                REQUIRE(has_field(result, "membership"));
                // Spec MUST: join_authorised_via_users_server survives (v8+ addition to v10 rules).
                REQUIRE(has_field(result, "join_authorised_via_users_server"));
                // Spec MUST: displayname and avatar_url are stripped.
                REQUIRE_FALSE(has_field(result, "displayname"));
                REQUIRE_FALSE(has_field(result, "avatar_url"));
                REQUIRE_FALSE(has_field(result, "reason"));
            }
        }
    }
}

SCENARIO("Redaction v1-v10: m.room.create preserves creator from content",
         "[conformance][redaction][v10][create]")
{
    GIVEN("an m.room.create event with creator and extra content")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.create","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":0,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"creator":"@a:x","room_version":"10","extra_field":"value"}})"};

        WHEN("the event is redacted under v10")
        {
            auto const result = redact_event(event_json, "10");

            THEN("creator is preserved and extra content is stripped")
            {
                // Spec (v1-v10): m.room.create preserves only creator from content.
                REQUIRE(has_field(result, "creator"));
                REQUIRE_FALSE(has_field(result, "room_version"));
                REQUIRE_FALSE(has_field(result, "extra_field"));
            }
        }
    }
}

SCENARIO("Redaction v1-v10: m.room.power_levels preserves the specified content fields",
         "[conformance][redaction][v10][power-levels]")
{
    GIVEN("an m.room.power_levels event")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.power_levels","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"ban":50,"events":{},"events_default":0,"invite":0,"kick":50,)"
            R"("redact":50,"state_default":50,"users":{"@a:x":100},"users_default":0,)"
            R"("extra":"should_be_stripped"}})"};

        WHEN("the event is redacted under v10")
        {
            auto const result = redact_event(event_json, "10");

            THEN("spec-listed fields are preserved, extra is stripped")
            {
                REQUIRE(has_field(result, "ban"));
                REQUIRE(has_field(result, "events"));
                REQUIRE(has_field(result, "events_default"));
                REQUIRE(has_field(result, "kick"));
                REQUIRE(has_field(result, "redact"));
                REQUIRE(has_field(result, "state_default"));
                REQUIRE(has_field(result, "users"));
                REQUIRE(has_field(result, "users_default"));
                REQUIRE_FALSE(has_field(result, "extra"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: v11+ redaction rules differ from v1-v10
// URL:  https://spec.matrix.org/v1.18/rooms/v11/#redactions
//
// Key changes in v11:
//  1. "origin", "membership", "prev_state" are NO LONGER protected from
//     redaction (they used to be preserved in v1-v10).
//  2. m.room.create preserves the ENTIRE content (not just creator).
//  3. m.room.redaction preserves "redacts" under content (not as a top-level key).
//  4. m.room.power_levels now also preserves "invite" under content.
// ---------------------------------------------------------------------------

SCENARIO("Redaction v11+: origin is no longer preserved (v11 change from v10)",
         "[conformance][redaction][v11]")
{
    GIVEN("an event with an origin field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.message","room_id":"!r:x","sender":"@a:x",)"
            R"("origin":"example.org","origin_server_ts":1,"depth":1,)"
            R"("prev_events":[],"auth_events":[],"hashes":{"sha256":"h"},"signatures":{},)"
            R"("unsigned":{"age":1},"content":{"body":"hi"}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("origin is preserved in v10 but stripped in v11")
            {
                // Spec (v1-v10): "origin" IS preserved.
                REQUIRE(has_field(result_v10, "origin"));
                // Spec (v11+): "origin" is NO LONGER protected. It MUST be stripped.
                REQUIRE_FALSE(has_field(result_v11, "origin"));
            }

            THEN("unsigned is stripped in both versions")
            {
                // Spec MUST: "unsigned" is never preserved in any version.
                REQUIRE_FALSE(has_field(result_v10, "unsigned"));
                REQUIRE_FALSE(has_field(result_v11, "unsigned"));
            }
        }
    }
}

SCENARIO("Redaction v11+: m.room.create preserves all content, not just creator",
         "[conformance][redaction][v11][create]")
{
    GIVEN("an m.room.create event with several content fields")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.create","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":0,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"creator":"@a:x","room_version":"11","predecessor":{"room_id":"!old:x"}}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("v10 strips room_version and predecessor, v11 keeps all content fields")
            {
                // Spec (v1-v10): m.room.create only preserves creator.
                REQUIRE(has_field(result_v10, "creator"));
                REQUIRE_FALSE(has_field(result_v10, "room_version"));
                REQUIRE_FALSE(has_field(result_v10, "predecessor"));
                // Spec (v11+): m.room.create preserves ALL content fields.
                REQUIRE(has_field(result_v11, "creator"));
                REQUIRE(has_field(result_v11, "room_version"));
                REQUIRE(has_field(result_v11, "predecessor"));
            }
        }
    }
}

SCENARIO("Redaction v11+: m.room.power_levels preserves invite (v11 addition)",
         "[conformance][redaction][v11][power-levels]")
{
    GIVEN("an m.room.power_levels event with an invite field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.power_levels","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"ban":50,"events":{},"events_default":0,"invite":50,"kick":50,)"
            R"("redact":50,"state_default":50,"users":{},"users_default":0}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("invite is stripped in v10 but preserved in v11")
            {
                // Spec (v1-v10): "invite" is NOT in the preserved set for power_levels.
                REQUIRE_FALSE(has_field(result_v10, "invite"));
                // Spec (v11+): "invite" IS now preserved in power_levels content.
                REQUIRE(has_field(result_v11, "invite"));
            }
        }
    }
}

SCENARIO("Redaction v11+: m.room.redaction preserves redacts under content",
         "[conformance][redaction][v11][redaction-event]")
{
    GIVEN("an m.room.redaction event with redacts in content")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.redaction","room_id":"!r:x","sender":"@a:x",)"
            R"("origin_server_ts":1,"depth":5,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"redacts":"$target:x","reason":"spam"}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("redacts is stripped in v10 but preserved in v11 content")
            {
                // Spec (v1-v10): redacts was a top-level field; content had no protected fields.
                REQUIRE_FALSE(has_field(result_v10, "redacts"));
                // Spec (v11+): redacts is now preserved inside the content object.
                REQUIRE(has_field(result_v11, "redacts"));
                // reason is NOT in the preserved set in either version.
                REQUIRE_FALSE(has_field(result_v10, "reason"));
                REQUIRE_FALSE(has_field(result_v11, "reason"));
            }
        }
    }
}

SCENARIO("Redaction: unsigned is never preserved in any room version",
         "[conformance][redaction][all-versions]")
{
    GIVEN("a message event with unsigned data")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.message","room_id":"!r:x","sender":"@a:x",)"
            R"("origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("unsigned":{"age":100,"transaction_id":"tx1"},"content":{"body":"hi"}})"};

        WHEN("the event is redacted under several room versions")
        {
            auto const r10 = redact_event(event_json, "10");
            auto const r11 = redact_event(event_json, "11");
            auto const r12 = redact_event(event_json, "12");

            THEN("unsigned is stripped in all versions")
            {
                // Spec MUST: unsigned is not a protected field in any room version.
                REQUIRE_FALSE(has_field(r10, "unsigned"));
                REQUIRE_FALSE(has_field(r11, "unsigned"));
                REQUIRE_FALSE(has_field(r12, "unsigned"));
            }
        }
    }
}
