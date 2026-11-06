// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Fixtures for the third-party invite exchange tests: a runtime with two users, a room of alice's holding an
// m.room.third_party_invite, and the identity server's signed object.

#include "../federation_signing_test_support.hpp"
#include "in_memory_database_config.hpp"
#include "json_test_support.hpp"
#include "master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/federation/third_party_invite.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "registration_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <variant>

namespace merovingian::tests::third_party_invite
{

using namespace merovingian::tests;
namespace fed = merovingian::federation;

[[nodiscard]] inline auto exchange_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] inline auto log_in(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& name)
    -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(name, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// The `signed` object the identity server delivers on a bind: {mxid, token} signed with its key.
[[nodiscard]] inline auto signed_object(std::string const& mxid, std::string const& token,
                                        fed::test::SigningKeypair const& signing_key) -> std::string
{
    auto const payload = R"({"mxid":")" + mxid + R"(","token":")" + token + R"("})";
    auto const signature = fed::test::sign_payload_b64(payload, signing_key.secret_key);
    return R"({"mxid":")" + mxid + R"(","signatures":{"is.example":{"ed25519:0":")" + signature + R"("}},"token":")" +
           token + R"("})";
}

[[nodiscard]] inline auto exchange_of(std::string const& room_id, std::string const& sender, std::string const& target,
                                      std::string const& signed_json) -> fed::ThirdPartyInviteExchange
{
    auto const signed_value = merovingian::canonicaljson::parse_json(signed_json);
    REQUIRE(signed_value.error == merovingian::canonicaljson::ParseError::none);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&signed_value.value.storage());
    REQUIRE(object != nullptr);
    auto mxid = std::string{};
    auto token = std::string{};
    for (auto const& member : *object)
    {
        if (auto const* text = std::get_if<std::string>(&member.value->storage()); text != nullptr)
        {
            (member.key == "mxid" ? mxid : token) = member.key == "mxid" || member.key == "token" ? *text : token;
        }
    }
    return {
        room_id, sender, target, {mxid, token, signed_json}
    };
}

[[nodiscard]] inline auto membership_of(merovingian::homeserver::ClientServerRuntime& runtime,
                                        std::string const& room_id, std::string const& user_id) -> std::string
{
    auto const& memberships = runtime.homeserver.database.persistent_store.memberships;
    auto const found = std::ranges::find_if(memberships, [&](auto const& membership) {
        return membership.room_id == room_id && membership.user_id == user_id;
    });
    return found == memberships.end() ? std::string{} : found->membership;
}

// A room of alice's holding an m.room.third_party_invite for `token` whose key is `identity_key`'s.
struct InviteRoom final
{
    std::string room_id{};
    std::string alice_token{};
};

[[nodiscard]] inline auto room_with_third_party_invite(merovingian::homeserver::ClientServerRuntime& runtime,
                                                       std::string const& token,
                                                       fed::test::SigningKeypair const& identity_key) -> InviteRoom
{
    auto const alice = log_in(runtime, "alice");
    std::ignore = log_in(runtime, "bob");
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", alice, "{}"});
    REQUIRE(created.response.status == 200U);
    auto const created_body = parse_object(created.response.body);
    auto const* room_id = string_member(created_body, "room_id");
    REQUIRE(room_id != nullptr);
    auto const put = merovingian::homeserver::handle_client_server_request(
        runtime, {"PUT", "/_matrix/client/v3/rooms/" + *room_id + "/state/m.room.third_party_invite/" + token, alice,
                  R"({"display_name":"Bob","key_validity_url":"https://is.example/pubkey/isvalid","public_key":")" +
                      fed::test::pubkey_b64(identity_key) + R"("})"});
    REQUIRE(put.response.status == 200U);
    return {*room_id, alice};
}

} // namespace merovingian::tests::third_party_invite
