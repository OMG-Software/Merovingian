// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |      THIRD-PARTY INVITE EXCHANGE CONFORMANCE TESTS                      |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19, Third-party invites              |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#third-party-invites |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec. If a   |
// |  test fails, fix the IMPLEMENTATION; never weaken an assertion.         |
// |  The signature checks are the point: a `signed` object that the room's  |
// |  m.room.third_party_invite keys do not vouch for MUST NOT become an     |
// |  invite.                                                                |
// +-------------------------------------------------------------------------+

#include "../support/third_party_invite_fixture.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

using namespace merovingian::tests::third_party_invite;

// Spec: Matrix Server-Server API v1.19, PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv1exchange_third_party_inviteroomid
// Section: "Verifying the invite" (same document, Third-party invites)
//
// "The receiving server will verify the partial `m.room.member` event given in the request body. If valid, the
// receiving server will issue an invite." The `signed` object must be signed by a key the room's
// `m.room.third_party_invite` (state key = `token`) lists, and `mxid` must be the invited user.
SCENARIO("A third-party invite signed by the identity server's key becomes an invite",
         "[conformance][federation][3pid][exchange]")
{
    GIVEN("a room with a pending third-party invite and the identity server's signed object for bob")
    {
        auto started = merovingian::homeserver::start_client_server(exchange_config());
        REQUIRE(started.started);
        auto const identity_key = fed::test::keypair_from_seed("exchange-identity-server");
        auto const room = room_with_third_party_invite(started.runtime, "tok1", identity_key);
        auto const exchange = exchange_of(room.room_id, "@alice:example.org", "@bob:example.org",
                                          signed_object("@bob:example.org", "tok1", identity_key));

        WHEN("the exchange is requested")
        {
            auto const result =
                merovingian::homeserver::exchange_third_party_invite(started.runtime.homeserver, exchange, "test");

            THEN("bob is invited, by alice, with the third-party invite in the event")
            {
                REQUIRE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org") == "invite");
                auto const& invites = started.runtime.homeserver.database.persistent_store.invites;
                auto const found = std::ranges::find_if(invites, [&](auto const& invite) {
                    return invite.room_id == room.room_id && invite.user_id == "@bob:example.org";
                });
                REQUIRE(found != invites.end());
                REQUIRE(found->sender_user_id == "@alice:example.org");
                REQUIRE(found->signed_event_json.find("\"third_party_invite\"") != std::string::npos);
                REQUIRE(found->signed_event_json.find("\"display_name\":\"Bob\"") != std::string::npos);
            }

            AND_WHEN("the same exchange is requested again")
            {
                auto const again =
                    merovingian::homeserver::exchange_third_party_invite(started.runtime.homeserver, exchange, "test");

                THEN("it succeeds and stores nothing more")
                {
                    REQUIRE(again.ok);
                    auto const& invites = started.runtime.homeserver.database.persistent_store.invites;
                    REQUIRE(std::ranges::count_if(invites, [&](auto const& invite) {
                                return invite.room_id == room.room_id && invite.user_id == "@bob:example.org";
                            }) == 1);
                }
            }
        }
    }
}

SCENARIO("A third-party invite whose signature does not verify is refused",
         "[conformance][federation][3pid][exchange][signature]")
{
    GIVEN("a room with a pending third-party invite")
    {
        auto started = merovingian::homeserver::start_client_server(exchange_config());
        REQUIRE(started.started);
        auto const identity_key = fed::test::keypair_from_seed("exchange-identity-server");
        auto const attacker_key = fed::test::keypair_from_seed("exchange-attacker");
        auto const room = room_with_third_party_invite(started.runtime, "tok2", identity_key);

        WHEN("the signed object is signed by a key the invite does not list")
        {
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@alice:example.org", "@bob:example.org",
                            signed_object("@bob:example.org", "tok2", attacker_key)),
                "test");

            THEN("no invite is issued")
            {
                // Spec MUST: rule 4.3.1.7 - a signature in `signed` matches a public key of the invite event.
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 403U);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org").empty());
            }
        }

        WHEN("the signed object is changed after it was signed")
        {
            auto const genuine = signed_object("@bob:example.org", "tok2", identity_key);
            auto tampered = genuine;
            tampered.replace(tampered.find("bob"), 3U, "bab");
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@alice:example.org", "@bob:example.org", tampered), "test");

            THEN("no invite is issued")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org").empty());
            }
        }

        WHEN("the signed object names another user than the one invited")
        {
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@alice:example.org", "@bob:example.org",
                            signed_object("@alice:example.org", "tok2", identity_key)),
                "test");

            THEN("no invite is issued")
            {
                // Spec MUST: rule 4.3.1.4 - `mxid` must match the invited user.
                REQUIRE_FALSE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org").empty());
            }
        }

        WHEN("the token matches no m.room.third_party_invite of the room")
        {
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@alice:example.org", "@bob:example.org",
                            signed_object("@bob:example.org", "no-such-token", identity_key)),
                "test");

            THEN("no invite is issued")
            {
                // Spec MUST: rule 4.3.1.5 - there is an m.room.third_party_invite whose state key is the token.
                REQUIRE_FALSE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@bob:example.org").empty());
            }
        }

        WHEN("the sender is not the user who sent the m.room.third_party_invite")
        {
            auto const result = merovingian::homeserver::exchange_third_party_invite(
                started.runtime.homeserver,
                exchange_of(room.room_id, "@bob:example.org", "@alice:example.org",
                            signed_object("@alice:example.org", "tok2", identity_key)),
                "test");

            THEN("no invite is issued")
            {
                // Spec MUST: rule 4.3.1.6 - `sender` matches the sender of the m.room.third_party_invite.
                REQUIRE_FALSE(result.ok);
                REQUIRE(membership_of(started.runtime, room.room_id, "@alice:example.org") == "join");
            }
        }
    }
}
