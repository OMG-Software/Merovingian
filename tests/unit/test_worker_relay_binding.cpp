// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// GHSA-3p5v-vrg8-f545 (ADR-0595): the permits main gives a verified federation request for the claim and query relays
// a worker may make while serving it. Spec: server-server-api.md "Claiming one-time keys", "Querying keys for a
// user", "GET /_matrix/federation/v1/user/devices/{userId}" and "GET /_matrix/federation/v1/query/profile".

#include "merovingian/federation/WorkerRelayKind.hpp"
#include "merovingian/federation/WorkerRelayBinding.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <optional>
#include <string>
#include <vector>

namespace
{

using merovingian::federation::user_devices_path_user_id;
using merovingian::federation::verified_request_relay_digests;
using merovingian::federation::worker_relay_digest;
using merovingian::federation::WorkerRelayKind;

[[nodiscard]] auto digest_of(WorkerRelayKind kind, std::string const& argument) -> std::string
{
    auto digest = worker_relay_digest(kind, argument);
    REQUIRE(digest.has_value());
    return *digest;
}

} // namespace

SCENARIO("a verified request yields the one relay permit its route can cause", "[unit][ghsa-3p5v][relay-binding]")
{
    REQUIRE(sodium_init() >= 0);

    GIVEN("the bodies and user IDs of the four routes whose relays reach data the worker is denied")
    {
        auto const claim_body = std::string{R"({"one_time_keys":{"@alice:hs.example":{"DEV":"signed_curve25519"}}})"};
        auto const query_body = std::string{R"({"device_keys":{"@alice:hs.example":[]}})"};

        WHEN("each route's permits are computed as WorkerPool::handle computes them")
        {
            auto const claim =
                verified_request_relay_digests("POST", "/_matrix/federation/v1/user/keys/claim", claim_body);
            auto const query =
                verified_request_relay_digests("POST", "/_matrix/federation/v1/user/keys/query", query_body);
            auto const devices =
                verified_request_relay_digests("GET", "/_matrix/federation/v1/user/devices/%40alice%3Ahs.example", "");
            auto const profile = verified_request_relay_digests(
                "GET", "/_matrix/federation/v1/query/profile?field=displayname&user_id=%40alice%3Ahs.example", "");

            THEN("each is the digest of the argument the worker's frame carries, of that route's kind")
            {
                CHECK(claim == std::vector<std::string>{digest_of(WorkerRelayKind::otk_claim, claim_body)});
                CHECK(query == std::vector<std::string>{digest_of(WorkerRelayKind::device_keys_query, query_body)});
                CHECK(devices ==
                      std::vector<std::string>{digest_of(WorkerRelayKind::user_devices, "@alice:hs.example")});
                CHECK(profile ==
                      std::vector<std::string>{digest_of(WorkerRelayKind::profile_query, "@alice:hs.example")});
            }
        }
    }

    GIVEN("routes that cause none of these relays, or whose argument cannot be read")
    {
        WHEN("their permits are computed")
        {
            auto const send = verified_request_relay_digests("PUT", "/_matrix/federation/v1/send/txn1", "{}");
            auto const no_user = verified_request_relay_digests("GET", "/_matrix/federation/v1/query/profile", "");
            auto const wrong_method =
                verified_request_relay_digests("GET", "/_matrix/federation/v1/user/keys/claim", "{}");

            THEN("there are none")
            {
                CHECK(send.empty());
                CHECK(no_user.empty());
                CHECK(wrong_method.empty());
            }
        }
    }
}

SCENARIO("a relay digest depends on the relay's kind and its whole argument", "[unit][ghsa-3p5v][relay-binding]")
{
    REQUIRE(sodium_init() >= 0);

    GIVEN("one user ID")
    {
        auto const user = std::string{"@alice:hs.example"};

        WHEN("it is digested as a device list, a profile query, and with a byte changed")
        {
            auto const as_devices = digest_of(WorkerRelayKind::user_devices, user);
            auto const as_profile = digest_of(WorkerRelayKind::profile_query, user);
            auto const as_devices_again = digest_of(WorkerRelayKind::user_devices, user);
            auto const other_user = digest_of(WorkerRelayKind::user_devices, "@alicf:hs.example");

            THEN("only the same kind and argument give the same digest, so a permit cannot be spent as another")
            {
                CHECK(as_devices == as_devices_again);
                CHECK(as_devices != as_profile);
                CHECK(as_devices != other_user);
            }
        }
    }
}

SCENARIO("the device-list relay argument is read as the federation handler reads it",
         "[unit][ghsa-3p5v][relay-binding]")
{
    GIVEN("request targets with and without the path segment")
    {
        WHEN("the device-list user is extracted")
        {
            THEN("the device-list path's user is decoded, and a path naming nothing or another route has none")
            {
                CHECK(user_devices_path_user_id("/_matrix/federation/v1/user/devices/%40b%3Ac?x=1") ==
                      std::optional<std::string>{"@b:c"});
                CHECK_FALSE(user_devices_path_user_id("/_matrix/federation/v1/user/devices/").has_value());
                CHECK_FALSE(user_devices_path_user_id("/_matrix/federation/v1/user/keys/query").has_value());
            }
        }
    }
}
