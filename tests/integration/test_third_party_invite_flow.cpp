// SPDX-License-Identifier: GPL-3.0-or-later
//
// Third-party invite exchange: decisions of this server (ADR-0484, ADR-0485), run against a real runtime.

#include "../support/third_party_invite_fixture.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace merovingian::tests::third_party_invite;

// A decision of this server (ADR-0485), not a spec rule: the auth rules let a third-party invite stand in for the
// usual membership checks, so a replayed `signed` object must not move a member who is already in the room.
SCENARIO("A third-party invite does not move a user who is already in the room", "[federation][3pid][exchange]")
{
    GIVEN("a user who is joined and a valid signed object for them")
    {
        auto started = merovingian::homeserver::start_client_server(exchange_config());
        REQUIRE(started.started);
        auto const identity_key = fed::test::keypair_from_seed("exchange-identity-server");
        auto const room = room_with_third_party_invite(started.runtime, "tok3", identity_key);

        WHEN("the exchange names the joined sender as the invitee")
        {
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@alice:example.org", "@alice:example.org",
                            signed_object("@alice:example.org", "tok3", identity_key)),
                "test");

            THEN("it is refused and the membership stays join")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(membership_of(started.runtime, room.room_id, "@alice:example.org") == "join");
            }
        }
    }
}

SCENARIO("An identity server's bind notification invites the bound user to the rooms that invited them",
         "[federation][3pid][onbind]")
{
    GIVEN("a pending third-party invite and a bind notification for bob carrying the signed object")
    {
        auto started = merovingian::homeserver::start_client_server(exchange_config());
        REQUIRE(started.started);
        auto const identity_key = fed::test::keypair_from_seed("exchange-identity-server");
        auto const room = room_with_third_party_invite(started.runtime, "tok4", identity_key);
        auto const body = std::string{R"({"address":"bob@example.net","invites":[{"address":"bob@example.net",)"
                                      R"("medium":"email","mxid":"@bob:example.org","room_id":")"} +
                          room.room_id + R"(","sender":"@alice:example.org","signed":)" +
                          signed_object("@bob:example.org", "tok4", identity_key) +
                          R"(}],"medium":"email","mxid":"@bob:example.org"})";
        auto const parsed = fed::parse_third_party_bind_notification(body);
        REQUIRE(parsed.notification.has_value());

        WHEN("the notification is acted on")
        {
            auto const result = merovingian::homeserver::notify_third_party_bind(started.runtime.homeserver,
                                                                                 *parsed.notification, "ip");

            THEN("bob is invited to the room")
            {
                REQUIRE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org") == "invite");
            }
        }
    }

    GIVEN("a bind notification whose signed object was signed by another key")
    {
        auto started = merovingian::homeserver::start_client_server(exchange_config());
        REQUIRE(started.started);
        auto const identity_key = fed::test::keypair_from_seed("exchange-identity-server");
        auto const attacker_key = fed::test::keypair_from_seed("exchange-attacker");
        auto const room = room_with_third_party_invite(started.runtime, "tok5", identity_key);
        auto const body = std::string{R"({"address":"bob@example.net","invites":[{"address":"bob@example.net",)"
                                      R"("medium":"email","mxid":"@bob:example.org","room_id":")"} +
                          room.room_id + R"(","sender":"@alice:example.org","signed":)" +
                          signed_object("@bob:example.org", "tok5", attacker_key) +
                          R"(}],"medium":"email","mxid":"@bob:example.org"})";
        auto const parsed = fed::parse_third_party_bind_notification(body);
        REQUIRE(parsed.notification.has_value());

        WHEN("the notification is acted on")
        {
            std::ignore = merovingian::homeserver::notify_third_party_bind(started.runtime.homeserver,
                                                                           *parsed.notification, "ip");

            THEN("nobody is invited")
            {
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org").empty());
            }
        }
    }
}
