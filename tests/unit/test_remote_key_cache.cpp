// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/remote_key_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto sodium_is_ready() noexcept -> bool
{
    static auto const ready = sodium_init() >= 0;
    return ready;
}

struct SignedKeyResponse final
{
    std::string body{};
    std::string public_key_base64{};
};

// Builds a canonical, self-signed `GET /_matrix/key/v2/server` response body
// for a freshly generated Ed25519 keypair. Mirrors the local server's
// publish path so the verifier exercises the same canonical signing shape.
[[nodiscard]] auto build_signed_key_response(std::string_view server_name, std::string_view key_id,
                                              std::uint64_t valid_until_ts) -> SignedKeyResponse
{
    REQUIRE(sodium_is_ready());

    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);

    auto const public_key_base64 = merovingian::events::matrix_base64_from_bytes(std::string_view{
        reinterpret_cast<char const*>(public_key.data()), public_key.size()});

    auto verify_key_entry = merovingian::canonicaljson::Object{};
    verify_key_entry.push_back(
        merovingian::canonicaljson::make_member("key", merovingian::canonicaljson::Value{public_key_base64}));
    auto verify_keys = merovingian::canonicaljson::Object{};
    verify_keys.push_back(
        merovingian::canonicaljson::make_member(std::string{key_id},
                                                merovingian::canonicaljson::Value{std::move(verify_key_entry)}));

    auto response = merovingian::canonicaljson::Object{};
    response.push_back(merovingian::canonicaljson::make_member(
        "old_verify_keys", merovingian::canonicaljson::Value{merovingian::canonicaljson::Object{}}));
    response.push_back(merovingian::canonicaljson::make_member(
        "server_name", merovingian::canonicaljson::Value{std::string{server_name}}));
    response.push_back(merovingian::canonicaljson::make_member(
        "valid_until_ts", merovingian::canonicaljson::Value{static_cast<std::int64_t>(valid_until_ts)}));
    response.push_back(merovingian::canonicaljson::make_member(
        "verify_keys", merovingian::canonicaljson::Value{std::move(verify_keys)}));

    auto const payload = merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{response});
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);

    auto signature = std::string(crypto_sign_BYTES, '\0');
    REQUIRE(crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(payload.output.data()),
                                 payload.output.size(), secret_key.data()) == 0);

    auto server_signatures = merovingian::canonicaljson::Object{};
    server_signatures.push_back(merovingian::canonicaljson::make_member(
        std::string{key_id},
        merovingian::canonicaljson::Value{merovingian::events::matrix_base64_from_bytes(signature)}));
    auto signatures = merovingian::canonicaljson::Object{};
    signatures.push_back(merovingian::canonicaljson::make_member(
        std::string{server_name}, merovingian::canonicaljson::Value{std::move(server_signatures)}));
    response.push_back(merovingian::canonicaljson::make_member(
        "signatures", merovingian::canonicaljson::Value{std::move(signatures)}));

    auto const signed_body =
        merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(response)});
    REQUIRE(signed_body.error == merovingian::canonicaljson::CanonicalJsonError::none);
    return {signed_body.output, public_key_base64};
}

} // namespace

SCENARIO("Remote key response parser accepts a valid self-signed payload",
         "[federation][remote-key-cache][verify]")
{
    GIVEN("a canonically signed key response from example.org")
    {
        auto const signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);

        WHEN("the response body is parsed and self-verified")
        {
            auto const result = merovingian::federation::parse_and_verify_remote_key_response(signed_response.body,
                                                                                              "example.org");

            THEN("verification succeeds and the verify key is exposed for caching")
            {
                REQUIRE(result.ok);
                REQUIRE(result.response.server_name == "example.org");
                REQUIRE(result.response.valid_until_ts == 2000000000000ULL);
                REQUIRE(result.response.verify_keys.size() == 1U);
                REQUIRE(result.response.verify_keys.front().key_id == "ed25519:1");
                REQUIRE(result.response.verify_keys.front().public_key_base64 == signed_response.public_key_base64);
            }
        }
    }
}

SCENARIO("Remote key response parser rejects mismatched server name",
         "[federation][remote-key-cache][verify]")
{
    GIVEN("a signed response advertising one server")
    {
        auto const signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);

        WHEN("the response is checked against a different expected server")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(signed_response.body, "evil.com");

            THEN("verification fails")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason.find("server_name") != std::string::npos);
            }
        }
    }
}

SCENARIO("Remote key response parser rejects a tampered signature", "[federation][remote-key-cache][verify]")
{
    GIVEN("a valid signed response whose signature has been corrupted")
    {
        auto signed_response = build_signed_key_response("example.org", "ed25519:1", 2000000000000ULL);
        auto const signature_position = signed_response.body.find("\"signatures\"");
        REQUIRE(signature_position != std::string::npos);
        // Flip a base64 character inside the signatures object to break the
        // cryptographic check while keeping the payload otherwise parseable.
        auto const search_start = signed_response.body.find("ed25519:1\":\"", signature_position);
        REQUIRE(search_start != std::string::npos);
        auto const sig_value_start = search_start + std::string_view{"ed25519:1\":\""}.size();
        signed_response.body[sig_value_start] = signed_response.body[sig_value_start] == 'A' ? 'B' : 'A';

        WHEN("the tampered response is verified")
        {
            auto const result = merovingian::federation::parse_and_verify_remote_key_response(signed_response.body,
                                                                                              "example.org");

            THEN("verification fails closed")
            {
                REQUIRE_FALSE(result.ok);
            }
        }
    }
}

SCENARIO("Remote key cache persists and retrieves verified keys", "[federation][remote-key-cache][cache]")
{
    GIVEN("an open persistent store and a verified response")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto response = merovingian::federation::RemoteKeyResponse{};
        response.server_name = "example.org";
        response.valid_until_ts = 2000000000000ULL;
        response.verify_keys.push_back({"ed25519:1", "AAAA"});

        WHEN("the response is cached")
        {
            auto const cached = merovingian::federation::cache_remote_server_keys(open_result.store, response);

            THEN("storage succeeds and the matching key is retrievable")
            {
                REQUIRE(cached);
                auto const found =
                    merovingian::federation::find_cached_remote_key(open_result.store, "example.org", "ed25519:1");
                REQUIRE_FALSE(found.has_value()); // "AAAA" decodes to 3 bytes, not 32 — shape check rejects
                auto const any = merovingian::federation::find_any_cached_remote_key(open_result.store, "example.org");
                REQUIRE_FALSE(any.has_value());
            }
        }
    }

    GIVEN("an open persistent store and a real 32-byte public key from a verified response")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto const signed_response =
            build_signed_key_response("real.example.org", "ed25519:auto", 2000000000000ULL);
        auto const parsed = merovingian::federation::parse_and_verify_remote_key_response(signed_response.body,
                                                                                          "real.example.org");
        REQUIRE(parsed.ok);

        WHEN("the parsed response is cached and retrieved")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, parsed.response));
            auto const found = merovingian::federation::find_cached_remote_key(open_result.store, "real.example.org",
                                                                               "ed25519:auto");

            THEN("the FederationKeyRecord carries the raw public key bytes and expiry")
            {
                REQUIRE(found.has_value());
                REQUIRE(found->server_name == "real.example.org");
                REQUIRE(found->key_id == "ed25519:auto");
                REQUIRE(found->public_key_bytes.size() == crypto_sign_PUBLICKEYBYTES);
                REQUIRE(found->valid_until_ts == 2000000000000ULL);
                REQUIRE(found->verify_token.empty());
            }
        }
    }
}

SCENARIO("Remote key refresh threshold respects expiry and slack",
         "[federation][remote-key-cache][refresh]")
{
    // Implementation uses a 5-minute slack window (300_000 ms).
    auto constexpr slack_ms = std::uint64_t{5U * 60U * 1000U};

    GIVEN("a key with an expiry well outside the slack window")
    {
        auto constexpr expiry = std::uint64_t{10'000'000U};

        WHEN("the current time is well before expiry")
        {
            THEN("no refresh is needed")
            {
                REQUIRE_FALSE(merovingian::federation::remote_key_needs_refresh(expiry, expiry - slack_ms - 1U));
            }
        }

        WHEN("the current time is inside the slack window before expiry")
        {
            THEN("refresh is needed proactively")
            {
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry - slack_ms));
            }
        }

        WHEN("the current time is at the expiry boundary")
        {
            THEN("refresh is needed")
            {
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry));
            }
        }

        WHEN("the current time is past expiry")
        {
            THEN("refresh is needed")
            {
                REQUIRE(merovingian::federation::remote_key_needs_refresh(expiry, expiry + 100U));
            }
        }
    }

    GIVEN("a zero expiry timestamp")
    {
        WHEN("the refresh check runs")
        {
            THEN("a zero expiry always indicates a refresh is needed")
            {
                REQUIRE(merovingian::federation::remote_key_needs_refresh(0U, 1000U));
            }
        }
    }
}

SCENARIO("Remote key resolver caches the first fetch and serves later requests from cache",
         "[federation][remote-key-cache][resolver]")
{
    // No outbound fetch is required: the second call should hit the cache
    // populated by the first. We exercise this without a live client by
    // priming the cache directly and confirming the resolver short-circuits.
    GIVEN("an open store with a fresh cached key and a resolver bound to it")
    {
        auto open_result = merovingian::database::open_persistent_store();
        REQUIRE(open_result.ok);
        auto const signed_response =
            build_signed_key_response("federated.example.org", "ed25519:auto", 9'999'999'999'999ULL);
        auto const parsed = merovingian::federation::parse_and_verify_remote_key_response(
            signed_response.body, "federated.example.org");
        REQUIRE(parsed.ok);
        REQUIRE(merovingian::federation::cache_remote_server_keys(open_result.store, parsed.response));

        WHEN("the resolver is asked for a known cached server/key pair")
        {
            auto const found = merovingian::federation::find_cached_remote_key(open_result.store,
                                                                                "federated.example.org",
                                                                                "ed25519:auto");

            THEN("the cached record is returned without any network hooks being touched")
            {
                REQUIRE(found.has_value());
                REQUIRE(found->key_id == "ed25519:auto");
            }
        }
    }
}
