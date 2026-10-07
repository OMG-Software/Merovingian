// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// Shared fixtures for the CSAZ-10 per-user cap scenarios: a runtime whose
// end-to-end key and filter caps are set by the test, and a logged-in user.

#include "in_memory_database_config.hpp"
#include "master_key.hpp"
#include "registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::tests
{

[[nodiscard]] inline auto caps_config(std::uint32_t one_time_keys, std::uint32_t key_signatures, std::uint32_t filters)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.client_api.max_one_time_keys_per_device = one_time_keys;
    server.client_api.max_key_signatures_per_user = key_signatures;
    server.client_api.max_filters_per_user = filters;
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] inline auto access_token_from(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] inline auto string_field(std::string const& body, std::string_view name) -> std::string
{
    auto const key = "\"" + std::string{name} + "\":\"";
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

// Registers @alice and logs in on DEVICE1, returning her access token.
[[nodiscard]] inline auto register_and_login_alice(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const registered = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(registered.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST",
         "/_matrix/client/v3/login",
         {},
         R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    return access_token_from(login.response.body);
}

// A body uploading the plain (unsigned) curve25519 one-time keys named by
// `key_ids`. Plain keys need no device signature, which keeps these scenarios
// about the cap rather than about signature validation.

} // namespace merovingian::tests
