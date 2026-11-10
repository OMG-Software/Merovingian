// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-36 (ADR-0337) and F-37 (ADR-0338).
//
// F-36: a client's POST /keys/claim merged every user a remote server named into the response, so a
// hostile server could name a user the client also asked a local answer for, the response then held
// a duplicate member, the serializer refused it and the client got an empty 200 after the local
// one-time keys were already spent. The answer is now filtered to what was asked of that server.
//
// F-37: /keys/upload accepted any non-null value for an unsigned one-time or fallback key, and any
// size for device keys, so memory and storage grew with the 1 MiB body, not the key count.
//
// Spec: client-server-api.md, "POST /keys/claim" (one_time_keys is a map of user ID to device ID to
// `<algorithm>:<key_id>` to the key object: "the claimed key might be a fallback key"; "If the
// homeserver could be reached, but the user or device was unknown, no failure is recorded. Instead,
// the corresponding user or device is missing") and "POST /keys/upload" (a one-time or fallback
// key is `string|KeyObject`; a KeyObject is `{key, signatures, fallback?}`).

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/federation/KeyQuery.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

[[nodiscard]] auto upload(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                          std::string body) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(
               runtime, {"POST", "/_matrix/client/v3/keys/upload", token, std::move(body)})
        .response;
}

[[nodiscard]] auto stored_keys(merovingian::homeserver::ClientServerRuntime const& runtime) -> std::size_t
{
    auto const& store = runtime.homeserver.database.persistent_store;
    return store.one_time_keys.size() + store.fallback_keys.size();
}

constexpr auto good_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 43 characters, as a curve25519 key is

} // namespace

SCENARIO("/keys/upload accepts the key shapes the spec defines and refuses the rest",
         "[homeserver][client-server][e2ee][security][run2][f37]")
{
    GIVEN("a logged-in user with no keys")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);

        // F-37: the size and shape checks must not reject the legitimate shapes the spec defines, so valid uploads come
        // first.
        WHEN("she uploads unsigned curve25519 keys as plain strings, as an older client does")
        {
            auto const response = upload(runtime, token,
                                         std::string{R"({"one_time_keys":{"curve25519:AAAAAQ":")"} + good_key +
                                             R"(","curve25519:AAAAAg":")" + good_key + R"("}})");

            THEN("both are stored")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(stored_keys(runtime) == 2U);
            }
        }

        WHEN("she uploads a one-time key and a fallback key as key objects")
        {
            auto const response =
                upload(runtime, token,
                       std::string{R"({"one_time_keys":{"curve25519:AAAAAQ":{"key":")"} + good_key +
                           R"(","signatures":{"@alice:example.org":{"ed25519:DEVICE1":"c2ln"}}}},)" +
                           R"("fallback_keys":{"curve25519:AAAAAA":{"key":")" + good_key + R"(","fallback":true}}})");

            THEN("both are stored")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(stored_keys(runtime) == 2U);
            }
        }

        // Each refusal case checks stored_keys is zero: an oversized or malformed key must be rejected before anything
        // is persisted.
        WHEN("she uploads a one-time key whose string is a megabyte long")
        {
            auto const response = upload(runtime, token,
                                         std::string{R"({"one_time_keys":{"curve25519:AAAAAQ":")"} +
                                             std::string(900U * 1024U, 'A') + R"("}})");

            THEN("it is refused with M_BAD_JSON and nothing is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(stored_keys(runtime) == 0U);
            }
        }

        // Wrong JSON types are a malformed request (M_BAD_JSON), not something to coerce or skip.
        WHEN("she uploads a fallback key that is a number, and a one-time key that is a list")
        {
            auto const fallback = upload(runtime, token, R"({"fallback_keys":{"curve25519:AAAAAA":7}})");
            auto const list = upload(runtime, token, R"({"one_time_keys":{"curve25519:AAAAAQ":["a","b"]}})");

            THEN("both are refused with M_BAD_JSON and nothing is stored")
            {
                REQUIRE(fallback.status == 400U);
                REQUIRE(fallback.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(list.status == 400U);
                REQUIRE(list.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(stored_keys(runtime) == 0U);
            }
        }

        // The padding is an extra member, so the length of the key string alone cannot be what the limit is applied to.
        WHEN("she uploads a key object whose members make it far larger than a key")
        {
            auto const response = upload(runtime, token,
                                         std::string{R"({"one_time_keys":{"curve25519:AAAAAQ":{"key":")"} + good_key +
                                             R"(","pad":")" + std::string(8U * 1024U, 'x') + R"("}}})");

            THEN("it is refused with M_BAD_JSON and nothing is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_BAD_JSON") != std::string::npos);
                REQUIRE(stored_keys(runtime) == 0U);
            }
        }

        WHEN("she uploads device keys padded to many kilobytes with an extra member")
        {
            auto const response =
                upload(runtime, token,
                       std::string{R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1",)"} +
                           R"("algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:DEVICE1":"CURVE",)" +
                           R"("ed25519:DEVICE1":"ED"},"pad":")" + std::string(64U * 1024U, 'x') + R"("}})");

            THEN("it is refused with M_TOO_LARGE and no device keys are stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.device_keys.empty());
            }
        }

        // Control case: an ordinary device-keys upload must still pass the new size limit.
        WHEN("she uploads ordinary device keys")
        {
            auto const response = upload(
                runtime, token,
                R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE1","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE1":"CURVE","ed25519:DEVICE1":"ED"},"signatures":{"@alice:example.org":{"ed25519:DEVICE1":"c2ln"}}}})");

            THEN("they are stored")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.device_keys.size() == 1U);
            }
        }

        WHEN("she uploads a signature for a key that is padded to many kilobytes")
        {
            auto const response =
                merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST", "/_matrix/client/v3/keys/signatures/upload", token,
                     std::string{R"({"@alice:example.org":{"DEVICE1":{"user_id":"@alice:example.org","pad":")"} +
                         std::string(64U * 1024U, 'x') + R"("}}})"})
                    .response;

            THEN("it is refused with M_TOO_LARGE and no signature is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.key_signatures.empty());
            }
        }

        // Cross-signing upload needs the user-interactive password stage, which is supplied so the refusal is for size
        // and not for missing auth.
        WHEN("she uploads a cross-signing key padded to many kilobytes")
        {
            auto const response =
                merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                     std::string{R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"},)"} +
                         R"("master_key":{"user_id":"@alice:example.org","usage":["master"],)" +
                         R"("keys":{"ed25519:MASTER":"MASTER"},"pad":")" + std::string(64U * 1024U, 'x') + R"("}})"})
                    .response;

            THEN("it is refused with M_TOO_LARGE and no cross-signing key is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.cross_signing_keys.empty());
            }
        }
    }
}
