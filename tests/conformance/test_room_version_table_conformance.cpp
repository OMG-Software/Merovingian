// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX ROOM VERSION TABLE CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix v1.19 — Room Versions                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/rooms/index.md                             |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec.        |
// |  If a test fails:                                                        |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  The room version feature table from the spec (§ Room Versions) is the  |
// |  authority for which algorithm applies to each room version.             |
// +-------------------------------------------------------------------------+

#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

namespace
{

using merovingian::rooms::AuthRules;
using merovingian::rooms::EventFormat;
using merovingian::rooms::EventIdFormat;
using merovingian::rooms::RedactionRules;
using merovingian::rooms::StateResolutionAlgorithm;

} // namespace

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// The spec defines 12 stable room versions (v1–v12) and lets a server choose
// which it supports: the m.room_versions capability lists "The room versions
// the server supports" (client-server-api.md), and createRoom answers an
// unsupported one with M_UNSUPPORTED_ROOM_VERSION. This scenario previously
// claimed a server MUST support every stable version, which the spec does not
// say. Versions 1 and 2 are not supported (ADR-0076): their event-ID format
// ($localpart:domain, carried in the event) was never implemented, and their
// event_id-domain signature rule was never checked.
SCENARIO("Stable room versions v3 through v12 are registered; v1 and v2 are not supported",
         "[rooms][versions][conformance][v1_v2_unsupported]")
{
    GIVEN("the room version registry")
    {
        THEN("v1 is not supported")
        {
            REQUIRE(merovingian::rooms::find_room_version_policy("1") == nullptr);
            REQUIRE_FALSE(merovingian::rooms::room_version_is_supported("1"));
        }

        THEN("v2 is not supported")
        {
            REQUIRE(merovingian::rooms::find_room_version_policy("2") == nullptr);
            REQUIRE_FALSE(merovingian::rooms::room_version_is_supported("2"));
        }

        THEN("neither is among the known room versions")
        {
            for (auto const& policy : merovingian::rooms::known_room_versions())
            {
                REQUIRE(policy.id != "1");
                REQUIRE(policy.id != "2");
            }
        }

        THEN("v3 is registered")
        {
            // Spec MUST: v3 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("3") != nullptr);
        }

        THEN("v4 is registered")
        {
            // Spec MUST: v4 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("4") != nullptr);
        }

        THEN("v5 is registered")
        {
            // Spec MUST: v5 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("5") != nullptr);
        }

        THEN("v6 is registered")
        {
            // Spec MUST: v6 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("6") != nullptr);
        }

        THEN("v7 is registered")
        {
            // Spec MUST: v7 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("7") != nullptr);
        }

        THEN("v8 is registered")
        {
            // Spec MUST: v8 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("8") != nullptr);
        }

        THEN("v9 is registered")
        {
            // Spec MUST: v9 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("9") != nullptr);
        }

        THEN("v10 is registered")
        {
            // Spec MUST: v10 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("10") != nullptr);
        }

        THEN("v11 is registered")
        {
            // Spec MUST: v11 is a stable room version.
            REQUIRE(merovingian::rooms::find_room_version_policy("11") != nullptr);
        }

        THEN("v12 is registered")
        {
            // Spec MUST: v12 is a stable room version (MSC4291).
            REQUIRE(merovingian::rooms::find_room_version_policy("12") != nullptr);
        }

        THEN("non-existent versions are not registered")
        {
            // Spec: version 0 and 13+ do not exist.
            REQUIRE(merovingian::rooms::find_room_version_policy("0") == nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("13") == nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("") == nullptr);
            // "v1" is NOT the same as "1" — version strings are bare numerals.
            REQUIRE(merovingian::rooms::find_room_version_policy("v1") == nullptr);
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// v1–v5 use the original auth rules (room_v1), where the sender domain is NOT
// required to match the creator's domain. v6 introduced that requirement.
SCENARIO("Room versions v3–v5 use the original auth rules (no domain check)",
         "[rooms][versions][conformance][auth-rules]")
{
    GIVEN("the room version registry")
    {
        for (auto const* v : {"3", "4", "5"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("auth rules are room_v1 (no sender-domain check)")
                {
                    // Spec MUST: v1–v5 do not enforce sender-domain == creator-domain.
                    // Do NOT change to room_v6_plus — that would incorrectly block
                    // cross-domain events that the spec permits for these versions.
                    REQUIRE(policy->auth_rules == AuthRules::room_v1);
                }
            }
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// v6 introduced the conditional sender-domain check (active only when
// content.m.federate is false). v6–v11 all share the room_v6_plus auth rule set.
SCENARIO("Room versions v6–v11 use the room_v6_plus auth rules", "[rooms][versions][conformance][auth-rules]")
{
    GIVEN("the room version registry")
    {
        for (auto const* v : {"6", "7", "8", "9", "10", "11"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("auth rules are room_v6_plus")
                {
                    // Spec MUST: v6–v11 use the room_v6_plus rule set.
                    REQUIRE(policy->auth_rules == AuthRules::room_v6_plus);
                }
            }
        }
    }
}

// Spec: Matrix Room Version 12 (MSC4289/MSC4291)
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// v12 extends v6+ auth rules with creator privilege and implicit create;
// it uses a distinct auth rule tag for auditability.
SCENARIO("Room version 12 uses the room_v12 auth rules (distinct from v6+)",
         "[rooms][versions][conformance][auth-rules][room-version]")
{
    GIVEN("the room version registry")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        WHEN("the v12 auth_rules field is inspected")
        {
            THEN("auth rules are room_v12 — not room_v6_plus")
            {
                // Spec MUST: v12 uses room_v12 to distinguish creator-privilege
                // and implicit-create semantics from the base v6+ rule set.
                REQUIRE(policy->auth_rules == AuthRules::room_v12);
                REQUIRE(policy->auth_rules != AuthRules::room_v6_plus);
            }
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// v2 and above use the SDSS (State Resolution v2) algorithm; v12 uses v2.1.
// (v1's original algorithm is not implemented: v1 is not supported, ADR-0076.)
SCENARIO("Room version state resolution algorithm matches the spec table",
         "[rooms][versions][conformance][state-resolution]")
{
    GIVEN("the room version registry")
    {
        for (auto const* v : {"3", "4", "5", "6", "7", "8", "9", "10", "11"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("state resolution algorithm is v2 (SDSS)")
                {
                    // Spec MUST: v2+ use the State-Resolution v2 (SDSS) algorithm.
                    REQUIRE(policy->state_resolution == StateResolutionAlgorithm::v2);
                }
            }
        }

        WHEN("version 12 policy is retrieved")
        {
            auto const* policy = merovingian::rooms::find_room_version_policy("12");
            REQUIRE(policy != nullptr);

            THEN("state resolution algorithm is v2.1 (the v12 SDSS modifications)")
            {
                // Spec MUST: rooms/v12.md "State resolution" — "largely the same as
                // the algorithm found in room version 2 with the following
                // modifications" (empty starting map for iterative auth checks,
                // conflicted state subgraph, full conflicted set changes).
                REQUIRE(policy->state_resolution == StateResolutionAlgorithm::v2_1);
            }
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// v3 introduced the simplified event format where prev_events and auth_events
// are bare event ID strings. (v1–v2's [event_id, hashes] tuple format is not
// implemented: those versions are not supported, ADR-0076.)
SCENARIO("Room version event format matches the spec table", "[rooms][versions][conformance][event-format]")
{
    GIVEN("the room version registry")
    {
        for (auto const* v : {"3", "4", "5", "6", "7", "8", "9", "10", "11", "12"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("event format is room_v3_plus (prev_events/auth_events are bare event ID strings)")
                {
                    // Spec MUST: v3+ use the simplified event format with bare event IDs.
                    REQUIRE(policy->event_format == EventFormat::room_v3_plus);
                }
            }
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// v11 changed the redaction algorithm. v1–v10 use the original rules;
// v11+ use the new rules (origin no longer protected, m.room.create preserves
// all content, m.room.redaction.content.redacts survives, invite added to
// m.room.power_levels preserved keys).
SCENARIO("Room version redaction rules match the spec table", "[rooms][versions][conformance][redaction]")
{
    GIVEN("the room version registry")
    {
        // Spec: v1–v7 use the original redaction rules; join_rules preserves
        // only "join_rule" (no allow field — restricted joins didn't exist yet).
        // URL: ../../docs/matrix-v1.19-spec/rooms/v7.md#redactions
        for (auto const* v : {"3", "4", "5", "6", "7"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("redaction rules are room_v1_v7")
                {
                    // Spec MUST: v1–v7 use the original redaction rules.
                    REQUIRE(policy->redaction_rules == RedactionRules::room_v1_v7);
                }
            }
        }

        // Spec: v8–v10 introduced restricted joins (MSC3083); the allow field in
        // m.room.join_rules content is now preserved through redaction.
        // URL: ../../docs/matrix-v1.19-spec/rooms/v10.md#redactions
        for (auto const* v : {"8", "9", "10"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("redaction rules are room_v8_v10")
                {
                    // Spec MUST: v8–v10 use the v8 redaction rules (join_rule AND allow preserved).
                    REQUIRE(policy->redaction_rules == RedactionRules::room_v8_v10);
                }
            }
        }

        for (auto const* v : {"11", "12"})
        {
            WHEN(std::string{"version "} + v + " policy is retrieved")
            {
                auto const* policy = merovingian::rooms::find_room_version_policy(v);
                REQUIRE(policy != nullptr);

                THEN("redaction rules are room_v11_plus")
                {
                    // Spec MUST: v11+ use the new redaction rules introduced in v11.
                    REQUIRE(policy->redaction_rules == RedactionRules::room_v11_plus);
                }
            }
        }
    }
}

// Spec: Matrix v1.19 — Room Versions v12 (MSC4289, MSC4291)
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// Room v12 adds two new MSC features:
//   MSC4289: room creators hold an effectively infinite power level
//   MSC4291: the room ID is derived from the hash of the create event
SCENARIO("Room version 12 enables MSC4289 and MSC4291 flags", "[rooms][versions][conformance][v12]")
{
    GIVEN("the v12 room version policy")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);

        THEN("MSC4289 privileged creators flag is set")
        {
            // Spec MUST (MSC4289): create event sender is a privileged creator
            // with effectively infinite power level.
            REQUIRE(policy->privilege_room_creators);
        }

        THEN("MSC4291 create-event-is-room-id flag is set")
        {
            // Spec MUST (MSC4291): the room ID is the reference hash of the
            // create event — the room does not have a separate room_id field.
            REQUIRE(policy->create_event_is_room_id);
        }

        THEN("v11 does NOT set either MSC flag")
        {
            // Spec: MSC4289 and MSC4291 are v12-only. Do NOT backport.
            auto const* v11 = merovingian::rooms::find_room_version_policy("11");
            REQUIRE(v11 != nullptr);
            REQUIRE(!v11->privilege_room_creators);
            REQUIRE(!v11->create_event_is_room_id);
        }
    }
}

// Spec: Matrix v1.19 — Room Versions
// URL: ../../docs/matrix-v1.19-spec/rooms/index.md
//
// All registered versions must be marked stable. Unstable room versions are
// experimental and may not be registered under a numeric string identifier.
SCENARIO("All registered room versions are marked stable", "[rooms][versions][conformance]")
{
    GIVEN("the full list of known room versions")
    {
        auto const versions = merovingian::rooms::known_room_versions();

        THEN("every registered version has stable = true")
        {
            // Spec MUST: unstable room versions MUST NOT be registered under
            // the stable version ID space.
            for (auto const& policy : versions)
            {
                INFO("version: " << policy.id);
                REQUIRE(policy.stable);
            }
        }

        THEN("the stable set includes exactly all 12 spec-defined versions")
        {
            // Spec: v1–v12 are the currently stable versions.
            REQUIRE(versions.size() == 12U);
        }
    }
}
