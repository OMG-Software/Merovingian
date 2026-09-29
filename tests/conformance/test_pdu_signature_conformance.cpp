// SPDX-License-Identifier: GPL-3.0-or-later
//
// Conformance tests for the signature step of the checks performed on receipt
// of a PDU, and for how long a remote server's signing key is trusted.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Validating hashes and
// signatures on received events", "GET /_matrix/key/v2/server"
// (valid_until_ts); docs/matrix-v1.19-spec/rooms/v5.md — "Signing key
// validity period" (unchanged through room version 12).
//
// Every REQUIRE encodes a MUST from the spec. If one fails, fix the
// implementation; do not weaken the assertion.

#include "../federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace
{

constexpr auto signing_server = std::string_view{"remote.example.org"};
constexpr auto signing_key_id = std::string_view{"ed25519:auto"};
constexpr auto signing_key_seed = std::string_view{"pdu-signature-conformance"};
constexpr auto event_ts = std::int64_t{5'000'000};

// A message PDU from `signing_server`, sent at `event_ts`, signed under the
// rules of `room_version`.
[[nodiscard]] auto signed_pdu(std::string const& room_version) -> merovingian::federation::FederationPdu
{
    namespace cj = merovingian::canonicaljson;
    auto content = cj::Object{};
    content.push_back(cj::make_member("body", cj::Value{std::string{"hello"}}));
    content.push_back(cj::make_member("msgtype", cj::Value{std::string{"m.text"}}));
    auto obj = cj::Object{};
    obj.push_back(cj::make_member("auth_events", cj::Value{cj::Array{}}));
    obj.push_back(cj::make_member("content", cj::Value{std::move(content)}));
    obj.push_back(cj::make_member("depth", cj::Value{std::int64_t{3}}));
    obj.push_back(cj::make_member("origin_server_ts", cj::Value{event_ts}));
    obj.push_back(cj::make_member("prev_events", cj::Value{cj::Array{}}));
    obj.push_back(cj::make_member("room_id", cj::Value{std::string{"!room:"} + std::string{signing_server}}));
    obj.push_back(cj::make_member("sender", cj::Value{std::string{"@alice:"} + std::string{signing_server}}));
    obj.push_back(cj::make_member("type", cj::Value{std::string{"m.room.message"}}));
    auto const unsigned_json = cj::serialize_canonical(cj::Value{std::move(obj)});
    REQUIRE(unsigned_json.error == cj::CanonicalJsonError::none);

    auto const signed_json = merovingian::federation::test::make_signed_event_json(
        unsigned_json.output, signing_server, signing_key_id, signing_key_seed, room_version);
    REQUIRE_FALSE(signed_json.empty());
    auto pdu = merovingian::federation::parse_federation_pdu(signed_json, [&room_version](std::string_view) {
        return room_version;
    });
    REQUIRE_FALSE(pdu.event_id.empty());
    return pdu;
}

[[nodiscard]] auto signing_key_valid_until(std::uint64_t valid_until_ts) -> merovingian::federation::FederationKeyRecord
{
    auto key = merovingian::federation::FederationKeyRecord{};
    key.server_name = std::string{signing_server};
    key.key_id = std::string{signing_key_id};
    key.valid_until_ts = valid_until_ts;
    key.public_key_bytes = merovingian::federation::test::keypair_from_seed(signing_key_seed).public_key;
    return key;
}

} // namespace

// Spec: Matrix Room Version 5 (and every later version through 12)
// Section: Signing key validity period
// URL: ../../docs/matrix-v1.19-spec/rooms/v5.md#signing-key-validity-period
//
// "When validating event signatures, servers MUST enforce the valid_until_ts
// property from a key request is at least as large as the origin_server_ts
// for the event being validated."
SCENARIO("Room versions 5 and later reject a PDU signed by a key that expired before the event was sent",
         "[federation][pdu][signing][key_validity][conformance]")
{
    for (auto const version : {"5", "6", "7", "8", "9", "10", "11", "12"})
    {
        GIVEN("a PDU sent in room version " + std::string{version})
        {
            auto const pdu = signed_pdu(version);
            auto const ts = static_cast<std::uint64_t>(event_ts);

            WHEN("the signing key's valid_until_ts is one millisecond before the event's origin_server_ts")
            {
                auto const decision = merovingian::federation::authorize_federation_pdu(
                    pdu, signing_server, signing_key_valid_until(ts - 1U));

                THEN("the PDU is rejected")
                {
                    // Spec MUST: valid_until_ts at least as large as origin_server_ts.
                    REQUIRE_FALSE(decision.accepted);
                }
            }

            WHEN("the signing key's valid_until_ts equals the event's origin_server_ts")
            {
                auto const decision =
                    merovingian::federation::authorize_federation_pdu(pdu, signing_server, signing_key_valid_until(ts));

                THEN("the PDU is accepted")
                {
                    // Spec MUST: "at least as large as" includes equality.
                    REQUIRE(decision.accepted);
                }
            }

            WHEN("the signing key's validity has no known end (valid_until_ts 0)")
            {
                auto const decision =
                    merovingian::federation::authorize_federation_pdu(pdu, signing_server, signing_key_valid_until(0U));

                THEN("the PDU is rejected: 0 is not at least as large as origin_server_ts")
                {
                    // Spec MUST: the check is enforced, so an unknown validity cannot pass it.
                    REQUIRE_FALSE(decision.accepted);
                }
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: GET /_matrix/key/v2/server, valid_until_ts
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixkeyv2server
//
// "This field MUST be ignored in room versions 1, 2, 3, and 4."
SCENARIO("Room versions 3 and 4 ignore the signing key's valid_until_ts",
         "[federation][pdu][signing][key_validity][conformance]")
{
    for (auto const version : {"3", "4"})
    {
        GIVEN("a PDU sent in room version " + std::string{version} + " and a key that expired long before it")
        {
            auto const pdu = signed_pdu(version);

            WHEN("the PDU is authorised")
            {
                auto const decision =
                    merovingian::federation::authorize_federation_pdu(pdu, signing_server, signing_key_valid_until(1U));

                THEN("the PDU is accepted on its signature")
                {
                    // Spec MUST: valid_until_ts is ignored in room versions 1 to 4.
                    REQUIRE(decision.accepted);
                }
            }
        }
    }
}

// Spec: Matrix Room Version 5 (and every later version through 12)
// Section: Signing key validity period
// URL: ../../docs/matrix-v1.19-spec/rooms/v5.md#signing-key-validity-period
//
// "Servers MUST use the lesser of valid_until_ts and 7 days into the future
// when determining if a key is valid." Keys are capped when cached, at the
// time they were fetched, so a cached key is never trusted for longer than
// seven days without being fetched again.
SCENARIO("A cached remote signing key is trusted for at most seven days after it was fetched",
         "[federation][remote-key-cache][key_validity][conformance]")
{
    constexpr auto seven_days_ms = std::uint64_t{7U * 24U * 60U * 60U * 1000U};
    constexpr auto fetched_at = std::uint64_t{1'700'000'000'000};
    auto const public_key =
        merovingian::federation::test::pubkey_b64(merovingian::federation::test::keypair_from_seed(signing_key_seed));

    GIVEN("a key response whose valid_until_ts is thirty days after the fetch")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto response = merovingian::federation::RemoteKeyResponse{};
        response.server_name = std::string{signing_server};
        response.valid_until_ts = fetched_at + (30U * 24U * 60U * 60U * 1000U);
        response.verify_keys.push_back({std::string{signing_key_id}, public_key});

        WHEN("it is cached")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, response, fetched_at));
            auto const found =
                merovingian::federation::find_cached_remote_key(open_result.store, signing_server, signing_key_id);

            THEN("its validity ends seven days after the fetch")
            {
                REQUIRE(found.has_value());
                // Spec MUST: the lesser of valid_until_ts and 7 days into the future.
                REQUIRE(found->valid_until_ts == fetched_at + seven_days_ms);
            }
        }
    }

    GIVEN("a key response whose valid_until_ts is one day after the fetch")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto response = merovingian::federation::RemoteKeyResponse{};
        response.server_name = std::string{signing_server};
        response.valid_until_ts = fetched_at + (24U * 60U * 60U * 1000U);
        response.verify_keys.push_back({std::string{signing_key_id}, public_key});

        WHEN("it is cached")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, response, fetched_at));
            auto const found =
                merovingian::federation::find_cached_remote_key(open_result.store, signing_server, signing_key_id);

            THEN("its published valid_until_ts is kept, being the lesser")
            {
                REQUIRE(found.has_value());
                // Spec MUST: the lesser of the two.
                REQUIRE(found->valid_until_ts == response.valid_until_ts);
            }
        }
    }
}
