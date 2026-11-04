// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// HF-B F1: a remote server that rotated a key publishes the retired one under
// `old_verify_keys` with the time it stopped using it. Events signed before the
// rotation, arriving later through send_join state, /backfill or
// /get_missing_events, can only be verified with that key.
//
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys
// ("old_verify_keys which are only valid for signing events"; expired_ts is
// "Required") and ../../docs/matrix-v1.19-spec/rooms/v5.md ("Signing key
// validity period").
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

#include <sodium.h>
#include <stdlib.h>

namespace
{
namespace cj = merovingian::canonicaljson;

constexpr auto now_ms = std::uint64_t{1'800'000'000'000U};
constexpr auto day_ms = std::uint64_t{24U * 60U * 60U * 1000U};
constexpr auto old_expired_ts = std::uint64_t{1'700'000'000'000U};

class DatabaseScratch final
{
public:
    DatabaseScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-old-keys-XXXXXX").string();
        auto const* made = ::mkdtemp(pattern.data());
        if (made == nullptr)
        {
            throw std::runtime_error{"temporary directory unavailable"};
        }
        path = made;
    }
    DatabaseScratch(DatabaseScratch const&) = delete;
    auto operator=(DatabaseScratch const&) -> DatabaseScratch& = delete;
    ~DatabaseScratch()
    {
        auto ec = std::error_code{};
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;
};

[[nodiscard]] auto fresh_public_key_base64() -> std::string
{
    REQUIRE(sodium_init() >= 0);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);
    return merovingian::events::matrix_base64_from_bytes(
        std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()});
}

[[nodiscard]] auto key_entry(std::string_view key_base64) -> cj::Value
{
    auto entry = cj::Object{};
    entry.push_back(cj::make_member("key", cj::Value{std::string{key_base64}}));
    return cj::Value{std::move(entry)};
}

[[nodiscard]] auto old_key_entry(std::string_view key_base64, cj::Value expired_ts) -> cj::Value
{
    auto entry = cj::Object{};
    entry.push_back(cj::make_member("expired_ts", std::move(expired_ts)));
    entry.push_back(cj::make_member("key", cj::Value{std::string{key_base64}}));
    return cj::Value{std::move(entry)};
}

[[nodiscard]] auto integer(std::int64_t value) -> cj::Value
{
    return cj::Value{value};
}

struct SignedKeyResponse final
{
    std::string body{};
    std::string current_key_base64{};
    std::string old_key_base64{};
};

// A canonical GET /_matrix/key/v2/server body self-signed by its one verify
// key. `old_verify_keys` is the member's value as given, so a test can publish
// a malformed one.
[[nodiscard]] auto signed_response(std::string_view server_name, cj::Value old_verify_keys,
                                   std::string old_key_base64 = {}) -> SignedKeyResponse
{
    REQUIRE(sodium_init() >= 0);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);
    auto const current = merovingian::events::matrix_base64_from_bytes(
        std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()});

    auto verify_keys = cj::Object{};
    verify_keys.push_back(cj::make_member("ed25519:cur", key_entry(current)));
    auto response = cj::Object{};
    response.push_back(cj::make_member("old_verify_keys", std::move(old_verify_keys)));
    response.push_back(cj::make_member("server_name", cj::Value{std::string{server_name}}));
    response.push_back(cj::make_member("valid_until_ts", integer(static_cast<std::int64_t>(now_ms + 30U * day_ms))));
    response.push_back(cj::make_member("verify_keys", cj::Value{std::move(verify_keys)}));

    auto const payload = cj::serialize_canonical(cj::Value{response});
    REQUIRE(payload.error == cj::CanonicalJsonError::none);
    auto signature = std::string(crypto_sign_BYTES, '\0');
    REQUIRE(crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                                 secret_key.data()) == 0);
    auto server_signatures = cj::Object{};
    server_signatures.push_back(
        cj::make_member("ed25519:cur", cj::Value{merovingian::events::matrix_base64_from_bytes(signature)}));
    auto signatures = cj::Object{};
    signatures.push_back(cj::make_member(std::string{server_name}, cj::Value{std::move(server_signatures)}));
    response.push_back(cj::make_member("signatures", cj::Value{std::move(signatures)}));
    auto const body = cj::serialize_canonical(cj::Value{std::move(response)});
    REQUIRE(body.error == cj::CanonicalJsonError::none);
    return {body.output, current, std::move(old_key_base64)};
}

[[nodiscard]] auto signed_response_with_old_key(std::string_view server_name, std::uint64_t expired_ts)
    -> SignedKeyResponse
{
    auto const old_key = fresh_public_key_base64();
    auto old_keys = cj::Object{};
    old_keys.push_back(
        cj::make_member("ed25519:old", old_key_entry(old_key, integer(static_cast<std::int64_t>(expired_ts)))));
    return signed_response(server_name, cj::Value{std::move(old_keys)}, old_key);
}

[[nodiscard]] auto allowed_discovery(std::string_view server_name) -> merovingian::federation::ServerDiscoveryResult
{
    auto discovery = merovingian::federation::ServerDiscoveryResult{};
    discovery.server_name = std::string{server_name};
    discovery.resolved_host = "192.0.2.10";
    discovery.tls_server_name = std::string{server_name};
    discovery.pinned_addresses = {"192.0.2.10"};
    discovery.discovery_allowed = true;
    return discovery;
}

[[nodiscard]] auto event_at(std::int64_t origin_server_ts) -> cj::Value
{
    auto const parsed = cj::parse_lossless("{\"origin_server_ts\":" + std::to_string(origin_server_ts) + "}");
    REQUIRE(parsed.error == cj::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto retired_record(std::uint64_t expired_ts) -> merovingian::federation::FederationKeyRecord
{
    auto key = merovingian::federation::FederationKeyRecord{};
    key.server_name = "remote.example.org";
    key.key_id = "ed25519:old";
    key.valid_until_ts = expired_ts;
    key.expired_ts = expired_ts;
    key.retired = true;
    key.public_key_bytes = std::string(32U, 'k');
    return key;
}

// A resolver over a scratch store whose only network step returns `body`.
struct ResolverFixture final
{
    DatabaseScratch scratch{};
    merovingian::database::PersistentStoreOpenResult opened;
    merovingian::http::OutboundClient client{};
    std::string body;
    merovingian::federation::RemoteKeyResolver resolver{};

    explicit ResolverFixture(std::string response_body)
        : opened{merovingian::database::open_sqlite_persistent_store((scratch.path / "store.db").string())}
        , body{std::move(response_body)}
    {
        REQUIRE(opened.ok);
        resolver = merovingian::federation::make_remote_key_resolver(
            opened.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                return allowed_discovery(server_name);
            },
            [this](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                return merovingian::federation::parse_and_verify_remote_key_response(body, server_name);
            },
            "local.example.org");
    }
    ResolverFixture(ResolverFixture const&) = delete;
    auto operator=(ResolverFixture const&) -> ResolverFixture& = delete;
};
} // namespace

SCENARIO("A key response's old_verify_keys are parsed with their expiry", "[federation][remote-key-cache][old-keys]")
{
    GIVEN("a self-signed key response that lists one retired key")
    {
        auto const published = signed_response_with_old_key("remote.example.org", old_expired_ts);

        WHEN("the response is parsed and self-verified")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(published.body, "remote.example.org");

            THEN("the current key is kept and the retired key is exposed with its expired_ts")
            {
                REQUIRE(result.ok);
                REQUIRE(result.response.verify_keys.size() == 1U);
                REQUIRE(result.response.verify_keys.front().key_id == "ed25519:cur");
                REQUIRE(result.response.old_verify_keys.size() == 1U);
                REQUIRE(result.response.old_verify_keys.front().key_id == "ed25519:old");
                REQUIRE(result.response.old_verify_keys.front().public_key_base64 == published.old_key_base64);
                REQUIRE(result.response.old_verify_keys.front().expired_ts == old_expired_ts);
            }
        }

        WHEN("a retired key's expiry is altered after the response was signed")
        {
            auto tampered = published.body;
            auto const digits = std::to_string(old_expired_ts);
            auto const at = tampered.find(digits);
            REQUIRE(at != std::string::npos);
            tampered.replace(at, digits.size(), std::to_string(old_expired_ts + day_ms));
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(tampered, "remote.example.org");

            THEN("the response signature no longer verifies, so nothing in it is trusted")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.response.old_verify_keys.empty());
            }
        }
    }
}

SCENARIO("A malformed old_verify_keys entry costs only itself", "[federation][remote-key-cache][old-keys]")
{
    GIVEN("a signed key response whose old_verify_keys mixes one good entry with broken ones")
    {
        auto const good_key = fresh_public_key_base64();
        auto old_keys = cj::Object{};
        old_keys.push_back(cj::make_member("ed25519:good", old_key_entry(good_key, integer(1000))));
        old_keys.push_back(cj::make_member("ed25519:no_ts", key_entry(fresh_public_key_base64())));
        old_keys.push_back(cj::make_member("ed25519:negative", old_key_entry(fresh_public_key_base64(), integer(-5))));
        old_keys.push_back(cj::make_member("ed25519:zero", old_key_entry(fresh_public_key_base64(), integer(0))));
        old_keys.push_back(
            cj::make_member("ed25519:text", old_key_entry(fresh_public_key_base64(), cj::Value{std::string{"1000"}})));
        auto no_key = cj::Object{};
        no_key.push_back(cj::make_member("expired_ts", integer(1000)));
        old_keys.push_back(cj::make_member("ed25519:no_key", cj::Value{std::move(no_key)}));
        old_keys.push_back(cj::make_member("ed25519:not_object", cj::Value{std::string{"nope"}}));
        old_keys.push_back(cj::make_member("ed25519:bad_b64", old_key_entry("not valid base64 !!", integer(1000))));
        // The id of a current key cannot also be a retired one.
        old_keys.push_back(cj::make_member("ed25519:cur", old_key_entry(fresh_public_key_base64(), integer(1000))));
        auto const published = signed_response("remote.example.org", cj::Value{std::move(old_keys)});

        WHEN("the response is parsed")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(published.body, "remote.example.org");

            THEN("the response and its current key are usable and only the well-formed retired key is kept")
            {
                REQUIRE(result.ok);
                REQUIRE(result.response.verify_keys.size() == 1U);
                REQUIRE(result.response.verify_keys.front().key_id == "ed25519:cur");
                REQUIRE(result.response.old_verify_keys.size() == 1U);
                REQUIRE(result.response.old_verify_keys.front().key_id == "ed25519:good");
            }
        }
    }

    GIVEN("a signed key response whose old_verify_keys is not an object")
    {
        auto const published = signed_response("remote.example.org", cj::Value{std::string{"garbage"}});

        WHEN("the response is parsed")
        {
            auto const result =
                merovingian::federation::parse_and_verify_remote_key_response(published.body, "remote.example.org");

            THEN("the current key is usable and no retired key is trusted")
            {
                REQUIRE(result.ok);
                REQUIRE(result.response.verify_keys.size() == 1U);
                REQUIRE(result.response.old_verify_keys.empty());
            }
        }
    }
}

SCENARIO("The key resolver answers a retired key id from the fetched response, as retired",
         "[federation][remote-key-cache][old-keys][resolver]")
{
    GIVEN("a remote that rotated its key and publishes the old one under old_verify_keys")
    {
        auto const published = signed_response_with_old_key("remote.example.org", old_expired_ts);
        auto fixture = ResolverFixture{published.body};

        WHEN("the retired key id is resolved")
        {
            auto const resolved = fixture.resolver("remote.example.org", "ed25519:old");

            THEN("its key is returned marked retired, valid only until it expired, and is not cached as a live key")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.retired);
                REQUIRE(resolved->signing_key.expired_ts == old_expired_ts);
                REQUIRE(resolved->signing_key.valid_until_ts == old_expired_ts);
                REQUIRE(merovingian::events::matrix_base64_from_bytes(resolved->signing_key.public_key_bytes) ==
                        published.old_key_base64);
                REQUIRE_FALSE(merovingian::federation::find_cached_remote_key(fixture.opened.store,
                                                                              "remote.example.org", "ed25519:old")
                                  .has_value());
            }
        }

        WHEN("the current key id is resolved")
        {
            auto const resolved = fixture.resolver("remote.example.org", "ed25519:cur");

            THEN("it is not marked retired")
            {
                REQUIRE(resolved.has_value());
                REQUIRE_FALSE(resolved->signing_key.retired);
            }
        }

        WHEN("an unlisted key id is resolved")
        {
            auto const resolved = fixture.resolver("remote.example.org", "ed25519:other");

            THEN("nothing is returned")
            {
                REQUIRE_FALSE(resolved.has_value());
            }
        }
    }

    GIVEN("a remote claiming a retired key expires in the future")
    {
        auto const published = signed_response_with_old_key("remote.example.org", now_ms + 100U * day_ms);
        auto fixture = ResolverFixture{published.body};

        WHEN("the retired key id is resolved")
        {
            auto const resolved = fixture.resolver("remote.example.org", "ed25519:old");

            THEN("it is trusted no later than the moment it was fetched")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.expired_ts == now_ms);
            }
        }
    }
}

SCENARIO("A retired key verifies only events sent before it expired", "[federation][old-keys][validity]")
{
    GIVEN("a retired key that expired at a known time")
    {
        auto const key = retired_record(old_expired_ts);
        auto const* v10 = merovingian::rooms::find_room_version_policy("10");
        auto const* v3 = merovingian::rooms::find_room_version_policy("3");
        REQUIRE(v10 != nullptr);
        REQUIRE(v3 != nullptr);

        WHEN("the event was sent before the key expired")
        {
            auto const decision = merovingian::federation::check_signing_key_valid_for_event(
                key, event_at(static_cast<std::int64_t>(old_expired_ts) - 1), *v10);
            THEN("the key is valid for it")
            {
                REQUIRE(decision.accepted);
            }
        }

        WHEN("the event was sent at or after the key expired")
        {
            auto const at_expiry = merovingian::federation::check_signing_key_valid_for_event(
                key, event_at(static_cast<std::int64_t>(old_expired_ts)), *v10);
            auto const after = merovingian::federation::check_signing_key_valid_for_event(
                key, event_at(static_cast<std::int64_t>(old_expired_ts) + 1), *v10);
            THEN("the key is refused with 403")
            {
                REQUIRE_FALSE(at_expiry.accepted);
                REQUIRE(at_expiry.status == 403U);
                REQUIRE_FALSE(after.accepted);
                REQUIRE(after.status == 403U);
            }
        }

        WHEN("the key's expiry is missing")
        {
            auto broken = key;
            broken.expired_ts = 0U;
            auto const decision =
                merovingian::federation::check_signing_key_valid_for_event(broken, event_at(1000), *v10);
            THEN("the key is refused")
            {
                REQUIRE_FALSE(decision.accepted);
            }
        }

        WHEN("the room version ignores key validity")
        {
            auto const decision = merovingian::federation::check_signing_key_valid_for_event(
                key, event_at(static_cast<std::int64_t>(old_expired_ts) + 1), *v3);
            THEN("the retired key is accepted as any key is")
            {
                REQUIRE(decision.accepted);
            }
        }
    }
}
