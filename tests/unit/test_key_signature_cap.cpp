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

[[nodiscard]] auto signature_upload_body(std::initializer_list<std::string_view> target_device_ids) -> std::string
{
    auto body = std::string{R"({"@alice:example.org":{)"};
    auto first = true;
    for (auto const device_id : target_device_ids)
    {
        if (!first)
        {
            body += ",";
        }
        first = false;
        body += "\"" + std::string{device_id} + R"(":{"user_id":"@alice:example.org","device_id":")" +
                std::string{device_id} + R"(","signatures":{"@alice:example.org":{"ed25519:SSK":"sig"}}})";
    }
    body += "}}";
    return body;
}

[[nodiscard]] auto stored_signature_count(merovingian::homeserver::ClientServerRuntime const& runtime) -> std::size_t
{
    return runtime.homeserver.database.persistent_store.key_signatures.size();
}

} // namespace

SCENARIO("/keys/signatures/upload refuses signatures beyond the per-user cap and stores nothing",
         "[csaz-10][e2ee][homeserver][client-server][limits]")
{
    GIVEN("a runtime capped at 3 key signatures per user and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 3U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login_alice(runtime);

        WHEN("signatures for exactly 3 targets are uploaded")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                          signature_upload_body({"D1", "D2", "D3"})});

            THEN("the upload is accepted at the cap")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_signature_count(runtime) == 3U);
            }
        }

        WHEN("signatures for 4 targets are uploaded in one request")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                          signature_upload_body({"D1", "D2", "D3", "D4"})});

            THEN("it is refused with M_TOO_LARGE and no signature is stored")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_signature_count(runtime) == 0U);
            }
        }

        WHEN("the user is at the cap and signs a fourth target")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                                  signature_upload_body({"D1", "D2", "D3"})})
                        .response.status == 200U);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token, signature_upload_body({"D4"})});

            THEN("it is refused with M_TOO_LARGE and the stored rows are unchanged")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(response.response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(stored_signature_count(runtime) == 3U);
            }
        }

        WHEN("the user is at the cap and re-signs targets already signed")
        {
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        runtime, {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                                  signature_upload_body({"D1", "D2", "D3"})})
                        .response.status == 200U);
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/signatures/upload", token, signature_upload_body({"D1", "D3"})});

            THEN("the existing pairs are not counted twice and the upload is accepted")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(stored_signature_count(runtime) == 3U);
            }
        }
    }
}
