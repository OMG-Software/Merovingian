// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// CSAZ-10 (security audit 2026-09-29). Owner policy: refuse over-cap uploads with
// M_TOO_LARGE and never evict; the caps are operator-configurable.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

[[nodiscard]] auto one_time_keys_body(std::initializer_list<std::string_view> key_ids,
                                      std::string_view extra_members = {}) -> std::string
{
    auto body = std::string{R"({)"};
    if (!extra_members.empty())
    {
        body += std::string{extra_members} + ",";
    }
    body += R"("one_time_keys":{)";
    auto first = true;
    for (auto const key_id : key_ids)
    {
        if (!first)
        {
            body += ",";
        }
        first = false;
        body += "\"curve25519:" + std::string{key_id} + "\":\"value-" + std::string{key_id} + "\"";
    }
    body += "}}";
    return body;
}

[[nodiscard]] auto stored_one_time_key_count(merovingian::homeserver::ClientServerRuntime const& runtime) -> std::size_t
{
    return runtime.homeserver.database.persistent_store.one_time_keys.size();
}

} // namespace

SCENARIO("/keys/upload refuses one-time keys beyond the per-device cap and stores nothing",
         "[csaz-10][e2ee][homeserver][client-server][limits]")
{
    GIVEN("a runtime capped at 3 one-time keys per device and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(3U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);

        WHEN("exactly 3 keys are uploaded")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, one_time_keys_body({"A", "B", "C"})});

            THEN("the upload is accepted at the cap")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_one_time_key_count(runtime) == 3U);
            }
        }

        WHEN("4 keys are uploaded in one request")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, one_time_keys_body({"A", "B", "C", "D"})});

            THEN("it is refused with M_TOO_LARGE and no key is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_one_time_key_count(runtime) == 0U);
            }
        }

        WHEN("the device is at the cap and uploads one more new key alongside device and fallback keys")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, one_time_keys_body({"A", "B", "C"})})
                        .response.status == 200U);
            auto const body = one_time_keys_body(
                {"D"},
                R"("device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"CURVE","ed25519:DEVICE1":"ED"}},"fallback_keys":{"curve25519:FB":"fallback"})");
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body});

            THEN("it is refused with M_TOO_LARGE and nothing from the request is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_one_time_key_count(runtime) == 3U);
                auto const& store = runtime.homeserver.database.persistent_store;
                REQUIRE(store.device_keys.empty());
                REQUIRE(store.fallback_keys.empty());
            }
        }

        WHEN("the device is at the cap and re-uploads key ids it already holds")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, one_time_keys_body({"A", "B", "C"})})
                        .response.status == 200U);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/upload", token, one_time_keys_body({"A", "B"})});

            THEN("the stored ids are not counted twice and the upload is accepted")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_one_time_key_count(runtime) == 3U);
            }
        }
    }
}
