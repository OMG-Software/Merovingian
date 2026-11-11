// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Release-gate audit, unbounded stored invites per local user (ADR-0619), through the federation invite handler.
//
// Spec: server-server-api.md, PUT /_matrix/federation/v2/invite: 403 M_FORBIDDEN, "The sender is not allowed to send
// invites to the target user/homeserver".

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <string_view>
#include <tuple>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;

constexpr auto alice = std::string_view{"@alice:example.org"};

[[nodiscard]] auto invite_from(std::string_view origin, std::size_t number) -> merovingian::federation::InviteRequest
{
    auto const room = "!r" + std::to_string(number) + ":" + std::string{origin};
    auto request = merovingian::federation::InviteRequest{};
    request.room_id = room;
    request.event_id = "$invite" + std::to_string(number) + ":" + std::string{origin};
    request.room_version = "12";
    request.origin = std::string{origin};
    request.invite_event_json = std::string{R"({"auth_events":[],"content":{"membership":"invite"},"depth":7,)"
                                            R"("origin_server_ts":1,"prev_events":[],"room_id":")"} +
                                room + R"(","sender":"@a:)" + std::string{origin} + R"(","state_key":")" +
                                std::string{alice} + R"(","type":"m.room.member"})";
    return request;
}

} // namespace

SCENARIO("the federation invite handler refuses past the stored invite limits with 403 M_FORBIDDEN",
         "[federation][invite][security][gate-m-sync]")
{
    GIVEN("a local user one invite short of the limit")
    {
        auto started = hs::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = merovingian::tests::register_and_login_alice(runtime);
        hs::wire_federation_callbacks(runtime.homeserver);
        REQUIRE(runtime.homeserver.federation.invite_handler);
        auto& store = runtime.homeserver.database.persistent_store;
        store.max_remote_invites_per_user = 4U;
        store.remote_invite_origin_share_divisor = 1U;
        for (auto number = std::size_t{0U}; number < 3U; ++number)
        {
            REQUIRE(runtime.homeserver.federation.invite_handler(invite_from("remote.example.org", number)).accepted);
        }

        WHEN("the invite that reaches the limit arrives")
        {
            auto const accepted = runtime.homeserver.federation.invite_handler(invite_from("remote.example.org", 3U));

            THEN("it is signed and stored")
            {
                REQUIRE(accepted.accepted);
                REQUIRE(store.invites.size() == 4U);
            }

            AND_WHEN("one more arrives")
            {
                auto const events_before = store.events.size();
                auto const refused =
                    runtime.homeserver.federation.invite_handler(invite_from("remote.example.org", 4U));

                THEN("it is answered 403 M_FORBIDDEN and nothing is stored")
                {
                    REQUIRE_FALSE(refused.accepted);
                    REQUIRE(refused.status == 403U);
                    REQUIRE(refused.reason.find("M_FORBIDDEN") != std::string::npos);
                    REQUIRE(store.invites.size() == 4U);
                    REQUIRE(store.events.size() == events_before);
                    REQUIRE(db::find_membership_row(store, "!r4:remote.example.org", alice) == nullptr);
                }
            }

            AND_WHEN("the inviter re-sends an invite the user already holds")
            {
                auto const repeat = runtime.homeserver.federation.invite_handler(invite_from("remote.example.org", 0U));

                THEN("it is not refused for the limit")
                {
                    REQUIRE(repeat.status != 403U);
                    REQUIRE(store.invites.size() == 4U);
                }
            }
        }
    }
}
