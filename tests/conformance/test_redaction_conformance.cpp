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
//   origin_server_ts, membership, prev_state
//   (v11 removes origin, membership, and prev_state from the protected set)
//
// Content fields preserved per event type:
//   m.room.member:             membership, join_authorised_via_users_server (v8+)
//   m.room.create:             creator
//   m.room.join_rules:         join_rule, allow  (v8–v10; v1–v7 preserved only join_rule)
//   m.room.power_levels:       ban, events, events_default, kick, redact,
//                               state_default, users, users_default
//                               (invite is NOT preserved until v11+)
//   m.room.history_visibility: history_visibility
//   m.room.aliases:            aliases
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
                // Spec (v1-v10): origin AND membership are preserved; v11 removes both.
                REQUIRE(has_field(result, "origin"));
                REQUIRE(has_field(result, "membership"));
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

            THEN("spec-listed fields are preserved, extra and invite are stripped")
            {
                REQUIRE(has_field(result, "ban"));
                REQUIRE(has_field(result, "events"));
                REQUIRE(has_field(result, "events_default"));
                REQUIRE(has_field(result, "kick"));
                REQUIRE(has_field(result, "redact"));
                REQUIRE(has_field(result, "state_default"));
                REQUIRE(has_field(result, "users"));
                REQUIRE(has_field(result, "users_default"));
                // Spec (v1-v10): "invite" is NOT in the preserved set for m.room.power_levels.
                // It was added to the preserved set in v11. Stripping it in v10 is a MUST.
                REQUIRE_FALSE(has_field(result, "invite"));
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

// ---------------------------------------------------------------------------
// Spec: membership and prev_state are preserved in v1–v10 but dropped in v11+
// v10: https://spec.matrix.org/v1.18/rooms/v10/#redactions
// v11: https://spec.matrix.org/v1.18/rooms/v11/#redactions
//
// v11 removes "origin", "membership", and "prev_state" from the protected set.
// ---------------------------------------------------------------------------

SCENARIO("Redaction v10 vs v11: membership and prev_state are preserved in v10 but stripped in v11",
         "[conformance][redaction][v10][v11]")
{
    GIVEN("an event carrying top-level membership and prev_state fields")
    {
        // prev_state was an early Matrix PDU field (an array of prior state events).
        // It appears in v1–v10 PDUs and is listed as a protected top-level key in
        // that redaction rule set. v11 removes it from the protected set.
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.message","room_id":"!r:x","sender":"@a:x",)"
            R"("origin":"example.org","origin_server_ts":1,"depth":1,)"
            R"("prev_events":[],"auth_events":[],"hashes":{"sha256":"h"},"signatures":{},)"
            R"("membership":"join","prev_state":[],)"
            R"("content":{"body":"hi"}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("membership is preserved in v10 but stripped in v11")
            {
                // Spec (v1-v10): "membership" IS a protected top-level field.
                REQUIRE(has_field(result_v10, "membership"));
                // Spec (v11+): "membership" is NO LONGER protected. It MUST be stripped.
                REQUIRE_FALSE(has_field(result_v11, "membership"));
            }

            THEN("prev_state is preserved in v10 but stripped in v11")
            {
                // Spec (v1-v10): "prev_state" IS a protected top-level field.
                REQUIRE(has_field(result_v10, "prev_state"));
                // Spec (v11+): "prev_state" is NO LONGER protected. It MUST be stripped.
                REQUIRE_FALSE(has_field(result_v11, "prev_state"));
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

// ---------------------------------------------------------------------------
// Spec: m.room.join_rules — preserved content fields differ by version
// v1–v7:  https://spec.matrix.org/v1.18/rooms/v7/#redactions
//   m.room.join_rules preserves: join_rule
// v8–v10: https://spec.matrix.org/v1.18/rooms/v10/#redactions
//   m.room.join_rules preserves: join_rule, allow  (restricted joins, MSC3083)
// v11+:   https://spec.matrix.org/v1.18/rooms/v11/#redactions
//   m.room.join_rules preserves: join_rule, allow
// ---------------------------------------------------------------------------

// Spec: room versions 1–7 do not include restricted joins (MSC3083); the
// m.room.join_rules redaction algorithm for those versions preserves only
// "join_rule" — not "allow".
// URL: https://spec.matrix.org/v1.18/rooms/v7/#redactions
SCENARIO("Redaction v1-v7: m.room.join_rules preserves only join_rule from content",
         "[conformance][redaction][v7][join-rules]")
{
    GIVEN("an m.room.join_rules event with join_rule, allow, and an extra field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.join_rules","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":"!p:x"}],"extra":"strip"}})"};

        WHEN("the event is redacted under v7")
        {
            auto const result = redact_event(event_json, "7");

            THEN("join_rule is preserved; allow and extra are stripped")
            {
                // Spec (v1-v7): m.room.join_rules preserves ONLY join_rule from content.
                REQUIRE(has_field(result, "join_rule"));
                // Spec MUST: allow is NOT in the v1-v7 preserved set.
                REQUIRE_FALSE(has_field(result, "allow"));
                REQUIRE_FALSE(has_field(result, "extra"));
            }
        }
    }
}

// Spec: room versions 8–10 introduce restricted joins (MSC3083). The
// m.room.join_rules redaction algorithm for those versions preserves both
// "join_rule" AND "allow".
// URL: https://spec.matrix.org/v1.18/rooms/v10/#redactions
SCENARIO("Redaction v8-v10: m.room.join_rules preserves both join_rule and allow",
         "[conformance][redaction][v8][v9][v10][join-rules]")
{
    GIVEN("an m.room.join_rules event with join_rule, allow, and an extra field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.join_rules","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":"!p:x"}],"extra":"strip"}})"};

        WHEN("the event is redacted under v8, v9, and v10")
        {
            auto const result_v8  = redact_event(event_json, "8");
            auto const result_v9  = redact_event(event_json, "9");
            auto const result_v10 = redact_event(event_json, "10");

            THEN("both join_rule and allow are preserved; extra is stripped for all three versions")
            {
                // Spec (v8-v10): m.room.join_rules preserves join_rule AND allow.
                // The allow field was introduced by restricted joins (MSC3083) in room v8.
                REQUIRE(has_field(result_v8, "join_rule"));
                REQUIRE(has_field(result_v8, "allow"));
                REQUIRE_FALSE(has_field(result_v8, "extra"));

                REQUIRE(has_field(result_v9, "join_rule"));
                REQUIRE(has_field(result_v9, "allow"));
                REQUIRE_FALSE(has_field(result_v9, "extra"));

                REQUIRE(has_field(result_v10, "join_rule"));
                REQUIRE(has_field(result_v10, "allow"));
                REQUIRE_FALSE(has_field(result_v10, "extra"));
            }
        }
    }
}

SCENARIO("Redaction v11+: m.room.join_rules preserves both join_rule and allow",
         "[conformance][redaction][v11][join-rules]")
{
    GIVEN("an m.room.join_rules event with join_rule, allow, and an extra field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.join_rules","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"join_rule":"restricted","allow":[{"type":"m.room_membership","room_id":"!p:x"}],"extra":"strip"}})"};

        WHEN("the event is redacted under v11 and v12")
        {
            auto const result_v11 = redact_event(event_json, "11");
            auto const result_v12 = redact_event(event_json, "12");

            THEN("both join_rule and allow are preserved; extra is stripped")
            {
                // Spec (v11+): m.room.join_rules preserves join_rule AND allow.
                REQUIRE(has_field(result_v11, "join_rule"));
                REQUIRE(has_field(result_v11, "allow"));
                REQUIRE_FALSE(has_field(result_v11, "extra"));
                // v12 inherits v11 redaction rules.
                REQUIRE(has_field(result_v12, "join_rule"));
                REQUIRE(has_field(result_v12, "allow"));
                REQUIRE_FALSE(has_field(result_v12, "extra"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: m.room.history_visibility — history_visibility preserved in all versions
// v10: https://spec.matrix.org/v1.18/rooms/v10/#redactions
// v11: https://spec.matrix.org/v1.18/rooms/v11/#redactions
// ---------------------------------------------------------------------------

SCENARIO("Redaction: m.room.history_visibility preserves history_visibility in all versions",
         "[conformance][redaction][all-versions][history-visibility]")
{
    GIVEN("an m.room.history_visibility event with extra content")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.history_visibility","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"history_visibility":"shared","extra":"strip"}})"};

        WHEN("the event is redacted under v10 and v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("history_visibility is preserved in both versions; extra is stripped")
            {
                // Spec MUST: m.room.history_visibility preserves history_visibility in v10 and v11+.
                REQUIRE(has_field(result_v10, "history_visibility"));
                REQUIRE(has_field(result_v11, "history_visibility"));
                REQUIRE_FALSE(has_field(result_v10, "extra"));
                REQUIRE_FALSE(has_field(result_v11, "extra"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: m.room.aliases — preserved in v1–v10, NOT preserved in v11+
// v10: aliases preserved; v11: not listed → stripped
// ---------------------------------------------------------------------------

SCENARIO("Redaction: m.room.aliases preserves aliases in v10 but strips it in v11",
         "[conformance][redaction][v10][v11][aliases]")
{
    GIVEN("an m.room.aliases event")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.aliases","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"example.org","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"aliases":["#general:example.org"],"extra":"strip"}})"};

        WHEN("the event is redacted under v10 vs v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("aliases is preserved in v10 but stripped in v11")
            {
                // Spec (v1-v10): m.room.aliases preserves aliases from content.
                REQUIRE(has_field(result_v10, "aliases"));
                REQUIRE_FALSE(has_field(result_v10, "extra"));
                // Spec (v11+): m.room.aliases is no longer listed; the aliases field is stripped.
                REQUIRE_FALSE(has_field(result_v11, "aliases"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: m.room.third_party_invite — signed preserved in all versions
// URL:  https://spec.matrix.org/v1.18/rooms/v10/#redactions
// ---------------------------------------------------------------------------

SCENARIO("Redaction: m.room.third_party_invite preserves signed from content",
         "[conformance][redaction][all-versions][third-party-invite]")
{
    GIVEN("an m.room.third_party_invite event")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.third_party_invite","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"tok","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"display_name":"Alice","key_validity_url":"https://x/k","public_key":"abc",)"
            R"("signed":{"mxid":"@a:x","signatures":{},"token":"tok"},"extra":"strip"}})"};

        WHEN("the event is redacted under v10 and v11")
        {
            auto const result_v10 = redact_event(event_json, "10");
            auto const result_v11 = redact_event(event_json, "11");

            THEN("signed is preserved in both versions; other content fields are stripped")
            {
                // Spec MUST: m.room.third_party_invite preserves signed from content.
                REQUIRE(has_field(result_v10, "signed"));
                REQUIRE(has_field(result_v11, "signed"));
                // display_name, public_key, and key_validity_url are stripped.
                REQUIRE_FALSE(has_field(result_v10, "display_name"));
                REQUIRE_FALSE(has_field(result_v11, "display_name"));
                REQUIRE_FALSE(has_field(result_v10, "extra"));
                REQUIRE_FALSE(has_field(result_v11, "extra"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: state_key is a top-level protected field in all room versions
// URL:  https://spec.matrix.org/v1.18/rooms/v10/#redactions
// ---------------------------------------------------------------------------

SCENARIO("Redaction: state_key is preserved as a top-level field in all versions",
         "[conformance][redaction][all-versions]")
{
    GIVEN("a state event with a non-empty state_key")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.member","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"@a:x","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},"content":{"membership":"join"}})"};

        WHEN("the event is redacted under v10, v11, and v12")
        {
            auto const r10 = redact_event(event_json, "10");
            auto const r11 = redact_event(event_json, "11");
            auto const r12 = redact_event(event_json, "12");

            THEN("state_key is preserved in all versions")
            {
                // Spec MUST: state_key is a protected top-level field across all room versions.
                REQUIRE(has_field(r10, "state_key"));
                REQUIRE(has_field(r11, "state_key"));
                REQUIRE(has_field(r12, "state_key"));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Spec: v12 inherits v11 redaction rules
// URL:  https://spec.matrix.org/v1.18/rooms/v12/
// ---------------------------------------------------------------------------

SCENARIO("Redaction v12: m.room.power_levels preserves invite as in v11",
         "[conformance][redaction][v12]")
{
    GIVEN("an m.room.power_levels event with an invite field")
    {
        auto constexpr event_json = std::string_view{
            R"({"event_id":"$ev:x","type":"m.room.power_levels","room_id":"!r:x","sender":"@a:x",)"
            R"("state_key":"","origin_server_ts":1,"depth":1,"prev_events":[],"auth_events":[],)"
            R"("hashes":{"sha256":"h"},"signatures":{},)"
            R"("content":{"ban":50,"events":{},"events_default":0,"invite":50,"kick":50,)"
            R"("redact":50,"state_default":50,"users":{},"users_default":0,"extra":"strip"}})"};

        WHEN("the event is redacted under v12")
        {
            auto const result = redact_event(event_json, "12");

            THEN("invite is preserved (v12 inherits v11 rules) and extra is stripped")
            {
                // Spec (v12): redaction rules same as v11.
                // m.room.power_levels preserves invite (added in v11).
                REQUIRE(has_field(result, "invite"));
                REQUIRE(has_field(result, "ban"));
                REQUIRE(has_field(result, "users"));
                REQUIRE_FALSE(has_field(result, "extra"));
            }
        }
    }
}
