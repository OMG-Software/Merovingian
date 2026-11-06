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

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/federation/key_query.hpp"
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

namespace fed = merovingian::federation;

using Requested = std::vector<std::pair<std::string, std::vector<std::string>>>;

[[nodiscard]] auto serialized(merovingian::canonicaljson::Object const& object) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{object}).output;
}

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

SCENARIO("a remote server's key claim answer is kept only for the users and devices asked of it",
         "[federation][key-claim][security][run2][f36]")
{
    GIVEN("a claim sent to evil.example for @mallory:evil.example device D")
    {
        auto const requested = Requested{
            {"@mallory:evil.example", {"D"}}
        };

        WHEN("the answer also names a local user and a device that was not asked for")
        {
            auto const response =
                std::string{
                    R"({"one_time_keys":{"@mallory:evil.example":{"D":{"signed_curve25519:AAAA":{"key":"k"}},)"} +
                R"("OTHER":{"signed_curve25519:BBBB":{"key":"k"}}},"@victim:local.example":{"X":{"signed_curve25519:CCCC":{"key":"k"}}}}})";
            auto const accepted = fed::accept_remote_key_claim_response("evil.example", response, requested);

            THEN("only the requested user's requested device is kept")
            {
                REQUIRE(accepted.has_value());
                auto const text = serialized(accepted->one_time_keys);
                REQUIRE(text.find("@mallory:evil.example") != std::string::npos);
                REQUIRE(text.find("signed_curve25519:AAAA") != std::string::npos);
                REQUIRE(text.find("OTHER") == std::string::npos);
                REQUIRE(text.find("@victim:local.example") == std::string::npos);
            }
        }

        WHEN("the answer's device is not a map of key IDs to keys")
        {
            auto const response = std::string{R"({"one_time_keys":{"@mallory:evil.example":{"D":"not-an-object"}}})"};
            auto const accepted = fed::accept_remote_key_claim_response("evil.example", response, requested);

            THEN("nothing is kept for it")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(accepted->one_time_keys.empty());
            }
        }

        WHEN("the answer's key is neither a string nor an object")
        {
            auto const response =
                std::string{R"({"one_time_keys":{"@mallory:evil.example":{"D":{"curve25519:A":7}}}})"};
            auto const accepted = fed::accept_remote_key_claim_response("evil.example", response, requested);

            THEN("nothing is kept for it")
            {
                REQUIRE(accepted.has_value());
                REQUIRE(accepted->one_time_keys.empty());
            }
        }

        WHEN("the answer is not a JSON object with one_time_keys")
        {
            auto const not_json = fed::accept_remote_key_claim_response("evil.example", "nonsense", requested);
            auto const no_member = fed::accept_remote_key_claim_response("evil.example", "{}", requested);

            THEN("it is refused so the caller can record a failure for the server")
            {
                REQUIRE_FALSE(not_json.has_value());
                REQUIRE_FALSE(no_member.has_value());
            }
        }
    }

    GIVEN("a claim sent to a server for two of its users")
    {
        auto const requested = Requested{
            {"@a:remote.example", {"D1", "D2"}},
            {"@b:remote.example", {"D1"}      }
        };

        WHEN("the answer is what an honest server sends, with a string key and a key object")
        {
            auto const response =
                std::string{
                    R"({"one_time_keys":{"@a:remote.example":{"D1":{"signed_curve25519:K1":{"key":"k","signatures":{}}},)"} +
                R"("D2":{"curve25519:K2":"plain-key"}},"@b:remote.example":{"D1":{"signed_curve25519:K3":{"key":"k","fallback":true}}}}})";
            auto const accepted = fed::accept_remote_key_claim_response("remote.example", response, requested);

            THEN("all of it is kept")
            {
                REQUIRE(accepted.has_value());
                auto const text = serialized(accepted->one_time_keys);
                for (auto const* expected : {"@a:remote.example", "@b:remote.example", "D1", "D2",
                                             "signed_curve25519:K1", "curve25519:K2", "signed_curve25519:K3"})
                {
                    REQUIRE(text.find(expected) != std::string::npos);
                }
            }
        }
    }
}

SCENARIO("/keys/upload accepts the key shapes the spec defines and refuses the rest",
         "[homeserver][client-server][e2ee][security][run2][f37]")
{
    GIVEN("a logged-in user with no keys")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);

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
