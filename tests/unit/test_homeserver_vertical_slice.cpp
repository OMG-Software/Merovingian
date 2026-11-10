// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |   MEMBERSHIP TEMPLATE CHECKS (the runtime flows are in                  |
// |   tests/integration/test_homeserver_vertical_slice_flow.cpp)            |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19                                   |
// |        Matrix Server-Server API v1.19                                   |
// |  CS URL: ../../docs/matrix-v1.19-spec/client-server-api.md               |
// |  SS URL: ../../docs/matrix-v1.19-spec/server-server-api.md               |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a   |
// |  hard security invariant. If a test fails:                              |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "../support/cross_signing_fixture.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/Ed25519SecretKeyHandle.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/ResolvedAddressSet.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/SrvRecord.hpp"
#include "merovingian/federation/WellKnownServerResult.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalRoom.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/observability/HealthStatus.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

// Spec: Matrix Server-Server API v1.19, "Joining Rooms"
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms
//
// "The joining server is expected to add or replace the origin,
// origin_server_ts, and event_id on the templated event received by the
// resident server. The joining server MUST also verify that the type, room_id,
// sender, state_key and content.membership fields have the expected values."
// So a template without origin_server_ts is accepted (we add our own), and a
// template whose checked fields are wrong is refused, never repaired.
SCENARIO("Remote join validates the make_join template fields the joining server must check",
         "[homeserver][vertical][rooms][federation][make-join]")
{
    GIVEN("a make_join response whose event omits origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation succeeds: the joining server adds origin_server_ts itself")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.room_version == "12");
            }
        }
    }

    GIVEN("a make_join response whose content.membership is not join")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin_server_ts":1234,"content":{"membership":"leave"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation fails rather than repairing the membership")
            {
                REQUIRE_FALSE(parsed.ok);
                REQUIRE(parsed.reason.find("membership") != std::string::npos);
            }
        }
    }

    GIVEN("a make_join response whose event omits the origin field but includes origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin_server_ts":1234,"content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation succeeds because origin was removed from events in room version 4")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.room_version == "12");
            }
        }
    }

    GIVEN("a make_join response whose event shape includes origin and origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin":"remote.example.org","origin_server_ts":1234,"content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation succeeds and returns the room version from the response")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.room_version == "12");
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, "Leaving Rooms (Rejecting Invites)"
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#leaving-rooms-rejecting-invites
//
// make_leave returns a template like make_join's, which the leaving server
// fills in the same way: the timestamp is the leaving server's to add.
SCENARIO("Remote leave accepts a make_leave template without origin_server_ts",
         "[homeserver][vertical][rooms][federation][make-join]")
{
    GIVEN("a make_leave response whose event omits origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","content":{"membership":"leave"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_leave_response("!room:remote.example.org",
                                                                                      "@alice:local.example.org", body);

            THEN("validation succeeds")
            {
                REQUIRE(parsed.ok);
            }
        }
    }
}

namespace
{
[[nodiscard]] auto member_of(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Value const*
{
    auto const found = std::ranges::find_if(object, [key](auto const& member) {
        return member.key == key;
    });
    return found == object.end() ? nullptr : found->value.get();
}

[[nodiscard]] auto string_of(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::optional<std::string>
{
    auto const* value = member_of(object, key);
    auto const* text = value == nullptr ? nullptr : std::get_if<std::string>(&value->storage());
    return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
}

[[nodiscard]] auto integer_of(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> std::optional<std::int64_t>
{
    auto const* value = member_of(object, key);
    auto const* number = value == nullptr ? nullptr : std::get_if<std::int64_t>(&value->storage());
    return number == nullptr ? std::nullopt : std::optional<std::int64_t>{*number};
}
} // namespace

// Spec: Matrix Server-Server API v1.19, "Joining Rooms"
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms
//
// "The joining server is expected to add or replace the origin,
// origin_server_ts, and event_id on the templated event received by the
// resident server." The event is ours once we sign it, so the resident must
// not choose its timestamp: from room version 5 other servers judge our key's
// validity at that timestamp (ADR-0075).
SCENARIO("The joining server puts its own origin and timestamp on a membership template",
         "[homeserver][vertical][rooms][federation][make-join]")
{
    GIVEN("a validated make_join template carrying the resident's origin, timestamp and an event_id")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin":"remote.example.org","origin_server_ts":1234,"event_id":"$resident-chosen","depth":7,"content":{"membership":"join"}}})"};
        auto parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                           "@alice:local.example.org", body);
        REQUIRE(parsed.ok);

        WHEN("this server claims the template")
        {
            merovingian::homeserver::claim_membership_event_template(parsed.event, "local.example.org",
                                                                     1'800'000'000'000);

            THEN("origin and origin_server_ts are ours, event_id is gone, and the checked fields are untouched")
            {
                REQUIRE(string_of(parsed.event, "origin") == "local.example.org");
                REQUIRE(integer_of(parsed.event, "origin_server_ts") == 1'800'000'000'000);
                REQUIRE(member_of(parsed.event, "event_id") == nullptr);
                REQUIRE(string_of(parsed.event, "room_id") == "!room:remote.example.org");
                REQUIRE(string_of(parsed.event, "sender") == "@alice:local.example.org");
                REQUIRE(string_of(parsed.event, "state_key") == "@alice:local.example.org");
                REQUIRE(integer_of(parsed.event, "depth") == 7);
            }
        }
    }

    GIVEN("a validated make_join template without origin or origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","content":{"membership":"join"}}})"};
        auto parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                           "@alice:local.example.org", body);
        REQUIRE(parsed.ok);

        WHEN("this server claims the template")
        {
            merovingian::homeserver::claim_membership_event_template(parsed.event, "local.example.org", 42);

            THEN("both fields are added")
            {
                REQUIRE(string_of(parsed.event, "origin") == "local.example.org");
                REQUIRE(integer_of(parsed.event, "origin_server_ts") == 42);
            }
        }
    }
}

SCENARIO("join_room advertises room versions 10 11 and 12 all of which have registered policies",
         "[homeserver][vertical][rooms][federation]")
{
    GIVEN("the room version policy registry")
    {
        // If any advertised version lacks a policy, a successful make_join for that
        // room version would be immediately followed by a 500 "room version policy missing"
        // error when Merovingian tries to sign the join event.
        THEN("every version Merovingian advertises to the remote server has a registered policy")
        {
            REQUIRE(merovingian::rooms::find_room_version_policy("10") != nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("11") != nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("12") != nullptr);
        }
    }
}
