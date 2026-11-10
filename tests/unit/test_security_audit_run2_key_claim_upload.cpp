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

namespace fed = merovingian::federation;

using Requested = std::vector<std::pair<std::string, std::vector<std::string>>>;

[[nodiscard]] auto serialized(merovingian::canonicaljson::Object const& object) -> std::string
{
    return merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{object}).output;
}

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
