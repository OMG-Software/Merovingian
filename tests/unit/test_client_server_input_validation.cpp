// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

// Client-server request validation that the analysis low findings (0.12.81) tightened: device IDs in the
// /devices/{deviceId} path are percent-decoded (C12), ban/kick/unban require a valid user_id (C15),
// /keys/claim validates its whole body before it spends a one-time key (C16), GET /relations pages and
// validates dir (C19), and GET /messages requires dir (CS10).
//
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3devicesdeviceid
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3roomsroomidban
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3keysclaim
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv1roomsroomidrelationseventid
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3roomsroomidmessages

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto validation_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto errcode_of(Reply const& reply) -> std::string
{
    auto const parsed = parse_object(reply.body);
    auto const* errcode = string_member(parsed, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

constexpr auto password = "CorrectHorse7!";

// Registers `localpart` and logs it in as `device_id`, returning the access token.
[[nodiscard]] auto login_as(ClientServerRuntime& rt, std::string const& localpart, std::string const& device_id)
    -> std::string
{
    auto const registered =
        call(rt, "POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password));
    REQUIRE(registered.status == 200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                 R"(:example.org"},"password":")" + password + R"(","device_id":")" + device_id + R"("})");
    REQUIRE(login.status == 200U);
    auto const parsed = parse_object(login.body);
    auto const* token = string_member(parsed, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto create_room(ClientServerRuntime& rt, std::string const& token) -> std::string
{
    auto const reply = call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})");
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* room_id = string_member(parsed, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

[[nodiscard]] auto event_id_of(Reply const& reply) -> std::string
{
    REQUIRE(reply.status == 200U);
    auto const parsed = parse_object(reply.body);
    auto const* id = string_member(parsed, "event_id");
    REQUIRE(id != nullptr);
    return *id;
}

} // namespace

SCENARIO("A device whose ID needs percent-encoding in the path can be read, renamed and deleted",
         "[client-server][devices][analysis-lows]")
{
    GIVEN("a user logged in on a device whose ID holds characters that a client percent-encodes")
    {
        auto started = merovingian::homeserver::start_client_server(validation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = login_as(rt, "alice", "DEV[1]%x");
        auto const other_login = call(
            rt, "POST", "/_matrix/client/v3/login", {},
            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"OTHER"})");
        REQUIRE(other_login.status == 200U);
        auto const other_token = *string_member(parse_object(other_login.body), "access_token");
        auto const path = std::string{"/_matrix/client/v3/devices/DEV%5B1%5D%25x"};

        WHEN("the device is read with its encoded ID")
        {
            auto const reply = call(rt, "GET", path, other_token);

            THEN("it is found under its decoded ID")
            {
                REQUIRE(reply.status == 200U);
                auto const parsed = parse_object(reply.body);
                REQUIRE(*string_member(parsed, "device_id") == "DEV[1]%x");
            }
        }

        WHEN("the device is renamed with its encoded ID")
        {
            auto const rename = call(rt, "PUT", path, other_token, R"({"display_name":"Renamed"})");
            auto const reply = call(rt, "GET", path, other_token);

            THEN("the rename lands on the decoded device")
            {
                REQUIRE(rename.status == 200U);
                REQUIRE(reply.status == 200U);
                REQUIRE(*string_member(parse_object(reply.body), "display_name") == "Renamed");
            }
        }

        WHEN("the device is deleted with its encoded ID")
        {
            auto const removed = call(rt, "DELETE", path, other_token,
                                      R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})");
            auto const reply = call(rt, "GET", path, other_token);

            THEN("it is removed and a later read finds nothing")
            {
                REQUIRE(removed.status == 200U);
                REQUIRE(reply.status == 404U);
            }
        }

        WHEN("the same bytes are read without being decoded")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/devices/DEV%255B1", other_token);

            THEN("no device is found")
            {
                REQUIRE(reply.status == 404U);
            }
        }
    }
}

SCENARIO("Ban, kick and unban refuse a body without a valid user_id", "[client-server][membership][analysis-lows]")
{
    GIVEN("a room owner and a room")
    {
        auto started = merovingian::homeserver::start_client_server(validation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = login_as(rt, "alice", "A");
        auto const room_id = create_room(rt, token);
        auto const members_before = rt.homeserver.database.persistent_store.memberships.size();
        auto const events_before = rt.homeserver.database.persistent_store.events.size();

        for (auto const* action : {"ban", "kick", "unban"})
        {
            WHEN(std::string{"POST /"} + action + " carries only the third-party invite triple")
            {
                auto const reply =
                    call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/" + action, token,
                         R"({"id_server":"is.example.org","medium":"email","address":"bob@example.org"})");

                THEN("it is M_BAD_JSON and no membership event is composed")
                {
                    REQUIRE(reply.status == 400U);
                    REQUIRE(errcode_of(reply) == "M_BAD_JSON");
                    REQUIRE(rt.homeserver.database.persistent_store.events.size() == events_before);
                    REQUIRE(rt.homeserver.database.persistent_store.memberships.size() == members_before);
                }
            }

            WHEN(std::string{"POST /"} + action + " carries an empty user_id")
            {
                auto const reply =
                    call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/" + action, token, R"({"user_id":""})");

                THEN("it is M_BAD_JSON")
                {
                    REQUIRE(reply.status == 400U);
                    REQUIRE(errcode_of(reply) == "M_BAD_JSON");
                }
            }

            WHEN(std::string{"POST /"} + action + " carries a user_id that is not a Matrix user ID")
            {
                auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/" + action, token,
                                        R"({"user_id":"not-a-user-id"})");

                THEN("it is M_INVALID_PARAM")
                {
                    REQUIRE(reply.status == 400U);
                    REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
                }
            }
        }

        WHEN("the services are called directly with an empty or malformed target")
        {
            auto const banned = merovingian::homeserver::ban_user(rt.homeserver, token, room_id, "", "");
            auto const kicked = merovingian::homeserver::kick_user(rt.homeserver, token, room_id, "bob", "");
            auto const unbanned = merovingian::homeserver::unban_user(rt.homeserver, token, room_id, "");

            THEN("each refuses with 400 M_INVALID_PARAM and composes nothing")
            {
                for (auto const* result : {&banned, &kicked, &unbanned})
                {
                    REQUIRE_FALSE(result->ok);
                    REQUIRE(result->status == 400U);
                    REQUIRE(result->errcode == "M_INVALID_PARAM");
                }
                REQUIRE(rt.homeserver.database.persistent_store.events.size() == events_before);
            }
        }

        WHEN("a well-formed user_id is banned")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/rooms/" + room_id + "/ban", token,
                                    R"({"user_id":"@bob:example.org","reason":"spam"})");

            THEN("the ban is accepted")
            {
                REQUIRE(reply.status == 200U);
            }
        }
    }
}

SCENARIO("POST /keys/claim validates the whole body before it spends a one-time key",
         "[client-server][e2ee][keys][analysis-lows]")
{
    GIVEN("bob holds one one-time key and alice claims from bob and then from a malformed entry")
    {
        auto started = merovingian::homeserver::start_client_server(validation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice = login_as(rt, "alice", "ALICE_DEV");
        auto const bob = login_as(rt, "bob", "BOB_DEV");
        auto const keypair = merovingian::federation::test::keypair_from_seed("claim-validation-seed");
        auto const public_key = merovingian::events::matrix_base64_from_bytes(keypair.public_key);
        auto const device_keys =
            std::string{R"({"device_keys":{"user_id":"@bob:example.org","device_id":"BOB_DEV",)"
                        R"("algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:BOB_DEV":"BOB_CURVE",)"
                        R"("ed25519:BOB_DEV":")"} +
            public_key + R"("}}})";
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/keys/upload", bob, device_keys).status == 200U);
        auto const otk = merovingian::federation::test::make_signed_otk_json("@bob:example.org", "BOB_DEV", "BOB_OTK",
                                                                             keypair.secret_key);
        REQUIRE(call(rt, "POST", "/_matrix/client/v3/keys/upload", bob,
                     R"({"one_time_keys":{"signed_curve25519:BOB_OTK_AAAA":)" + otk + "}}")
                    .status == 200U);

        WHEN("a later entry of the claim names no algorithm")
        {
            auto const refused = call(
                rt, "POST", "/_matrix/client/v3/keys/claim", alice,
                R"({"one_time_keys":{"@bob:example.org":{"BOB_DEV":"signed_curve25519"},"@carol:example.org":{"C":""}}})");
            auto const claimed = call(rt, "POST", "/_matrix/client/v3/keys/claim", alice,
                                      R"({"one_time_keys":{"@bob:example.org":{"BOB_DEV":"signed_curve25519"}}})");

            THEN("the request is a 400 and bob's key is still there to claim")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(errcode_of(refused) == "M_BAD_JSON");
                REQUIRE(claimed.status == 200U);
                REQUIRE(claimed.body.find("BOB_OTK") != std::string::npos);
            }
        }

        WHEN("a later user's value is not a device map")
        {
            auto const refused = call(
                rt, "POST", "/_matrix/client/v3/keys/claim", alice,
                R"({"one_time_keys":{"@bob:example.org":{"BOB_DEV":"signed_curve25519"},"@carol:example.org":"x"}})");
            auto const claimed = call(rt, "POST", "/_matrix/client/v3/keys/claim", alice,
                                      R"({"one_time_keys":{"@bob:example.org":{"BOB_DEV":"signed_curve25519"}}})");

            THEN("the request is a 400 and bob's key is still there to claim")
            {
                REQUIRE(refused.status == 400U);
                REQUIRE(claimed.body.find("BOB_OTK") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /relations validates dir and offers next_batch only when the limit cut the page",
         "[client-server][relations][analysis-lows]")
{
    GIVEN("a parent event with three children")
    {
        auto started = merovingian::homeserver::start_client_server(validation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = login_as(rt, "alice", "A");
        auto const room_id = create_room(rt, token);
        auto const root =
            event_id_of(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/root", token,
                             R"({"msgtype":"m.text","body":"root"})"));
        for (auto index = 0; index < 3; ++index)
        {
            REQUIRE(call(rt, "PUT",
                         "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/c" + std::to_string(index),
                         token,
                         R"({"msgtype":"m.text","body":"r","m.relates_to":{"rel_type":"m.reference","event_id":")" +
                             root + R"("}})")
                        .status == 200U);
        }
        auto const base = "/_matrix/client/v1/rooms/" + room_id + "/relations/" + root;

        WHEN("dir is neither b nor f")
        {
            auto const reply = call(rt, "GET", base + "?dir=x", token);

            THEN("it is M_INVALID_PARAM, not a silent backward page")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
            }
        }

        WHEN("dir is omitted")
        {
            auto const reply = call(rt, "GET", base, token);

            THEN("the default page is returned")
            {
                REQUIRE(reply.status == 200U);
            }
        }

        WHEN("a forward page is cut by the limit")
        {
            auto const first = call(rt, "GET", base + "?dir=f&limit=1", token);
            auto const parsed = parse_object(first.body);
            auto const* next = string_member(parsed, "next_batch");

            THEN("it carries a next_batch")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(next != nullptr);
            }

            AND_WHEN("the next page is bounded by a `to` that ends it at the last event the range allows")
            {
                REQUIRE(next != nullptr);
                // `next` is the second child's position; the range up to it holds the first two children,
                // although a third child lies beyond `to`.
                auto const bounded = call(rt, "GET", base + "?dir=f&to=" + *next, token);
                auto const bounded_body = parse_object(bounded.body);

                THEN("the range is complete, so no next_batch is offered")
                {
                    REQUIRE(bounded.status == 200U);
                    REQUIRE(object_member_as_array(bounded_body, "chunk")->size() == 2U);
                    REQUIRE(string_member(bounded_body, "next_batch") == nullptr);
                }
            }
        }

        WHEN("a forward page is bounded by `to` and also cut by the limit")
        {
            auto const first = call(rt, "GET", base + "?dir=f&limit=1", token);
            auto const first_body = parse_object(first.body);
            auto const* next = string_member(first_body, "next_batch");
            REQUIRE(next != nullptr);
            auto const bounded = call(rt, "GET", base + "?dir=f&limit=1&to=" + *next, token);
            auto const bounded_body = parse_object(bounded.body);

            THEN("more results exist within the range, so next_batch is offered")
            {
                REQUIRE(bounded.status == 200U);
                REQUIRE(string_member(bounded_body, "next_batch") != nullptr);
            }
        }
    }
}

SCENARIO("GET /messages requires dir to be b or f", "[client-server][messages][analysis-lows]")
{
    GIVEN("a room with a message")
    {
        auto started = merovingian::homeserver::start_client_server(validation_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = login_as(rt, "alice", "A");
        auto const room_id = create_room(rt, token);
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/t1", token,
                     R"({"msgtype":"m.text","body":"hello"})")
                    .status == 200U);
        auto const base = "/_matrix/client/v3/rooms/" + room_id + "/messages";

        WHEN("dir is missing")
        {
            auto const reply = call(rt, "GET", base, token);

            THEN("it is M_MISSING_PARAM")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_MISSING_PARAM");
            }
        }

        WHEN("dir is neither b nor f")
        {
            auto const reply = call(rt, "GET", base + "?dir=sideways", token);

            THEN("it is M_INVALID_PARAM")
            {
                REQUIRE(reply.status == 400U);
                REQUIRE(errcode_of(reply) == "M_INVALID_PARAM");
            }
        }

        WHEN("dir is b or f")
        {
            auto const backward = call(rt, "GET", base + "?dir=b", token);
            auto const forward = call(rt, "GET", base + "?dir=f", token);

            THEN("both are served")
            {
                REQUIRE(backward.status == 200U);
                REQUIRE(forward.status == 200U);
                REQUIRE(backward.body.find("hello") != std::string::npos);
            }
        }
    }
}
