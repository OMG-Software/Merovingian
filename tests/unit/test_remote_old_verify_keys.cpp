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
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

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
    int fetches{0};
    merovingian::federation::RemoteKeyResolver resolver{};

    [[nodiscard]] auto store_path() const -> std::string
    {
        return (scratch.path / "store.db").string();
    }

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
                ++fetches;
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

            THEN("its key is returned marked retired, valid only until it expired, and is cached as a retired key, "
                 "never a live one")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.retired);
                REQUIRE(resolved->signing_key.expired_ts == old_expired_ts);
                REQUIRE(resolved->signing_key.valid_until_ts == old_expired_ts);
                REQUIRE(merovingian::events::matrix_base64_from_bytes(resolved->signing_key.public_key_bytes) ==
                        published.old_key_base64);
                auto const cached_key = merovingian::federation::find_cached_remote_key(
                    fixture.opened.store, "remote.example.org", "ed25519:old");
                REQUIRE(cached_key.has_value());
                REQUIRE(cached_key->retired);
                REQUIRE(cached_key->expired_ts == old_expired_ts);
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

namespace
{
[[nodiscard]] auto response_with(std::vector<std::pair<std::string, std::string>> current,
                                 std::vector<merovingian::federation::RemoteOldVerifyKey> old)
    -> merovingian::federation::RemoteKeyResponse
{
    auto response = merovingian::federation::RemoteKeyResponse{};
    response.server_name = "remote.example.org";
    response.valid_until_ts = now_ms + 30U * day_ms;
    for (auto& [key_id, key] : current)
    {
        response.verify_keys.push_back({std::move(key_id), std::move(key)});
    }
    response.old_verify_keys = std::move(old);
    return response;
}

[[nodiscard]] auto cached(merovingian::database::PersistentStore const& store, std::string_view key_id)
    -> std::optional<merovingian::federation::FederationKeyRecord>
{
    return merovingian::federation::find_cached_remote_key(store, "remote.example.org", key_id);
}
} // namespace

SCENARIO("A retired key is persisted and outlives a reload", "[federation][remote-key-cache][old-keys][persist]")
{
    GIVEN("a store that cached a response listing a retired key")
    {
        auto const published = signed_response_with_old_key("remote.example.org", old_expired_ts);
        auto fixture = ResolverFixture{published.body};
        REQUIRE(fixture.resolver("remote.example.org", "ed25519:old").has_value());

        WHEN("the same database is opened again")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(fixture.store_path());
            REQUIRE(reopened.ok);

            THEN("the key is still retired, with its expiry, and the current key is not")
            {
                auto const old_key = cached(reopened.store, "ed25519:old");
                REQUIRE(old_key.has_value());
                REQUIRE(old_key->retired);
                REQUIRE(old_key->expired_ts == old_expired_ts);
                REQUIRE(old_key->valid_until_ts == old_expired_ts);
                REQUIRE(merovingian::events::matrix_base64_from_bytes(old_key->public_key_bytes) ==
                        published.old_key_base64);
                auto const current = cached(reopened.store, "ed25519:cur");
                REQUIRE(current.has_value());
                REQUIRE_FALSE(current->retired);
            }
        }
    }
}

SCENARIO("A cached retired key is answered without a fetch", "[federation][remote-key-cache][old-keys][resolver]")
{
    GIVEN("a resolver that already fetched a response listing a retired key")
    {
        auto const published = signed_response_with_old_key("remote.example.org", old_expired_ts);
        auto fixture = ResolverFixture{published.body};
        REQUIRE(fixture.resolver("remote.example.org", "ed25519:old").has_value());
        REQUIRE(fixture.fetches == 1);

        WHEN("the retired key id is resolved again")
        {
            auto const again = fixture.resolver("remote.example.org", "ed25519:old");

            THEN("it is a cache hit: still retired and nothing is fetched")
            {
                REQUIRE(again.has_value());
                REQUIRE(again->signing_key.retired);
                REQUIRE(again->signing_key.expired_ts == old_expired_ts);
                REQUIRE(fixture.fetches == 1);
            }
        }
    }

    GIVEN("a worker whose key mirror predates the key main cached")
    {
        auto const published = signed_response_with_old_key("remote.example.org", old_expired_ts);
        auto main_fixture = ResolverFixture{published.body};
        auto worker = merovingian::database::open_sqlite_persistent_store(
            main_fixture.store_path(), merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);
        REQUIRE(main_fixture.resolver("remote.example.org", "ed25519:old").has_value());
        REQUIRE_FALSE(cached(worker.store, "ed25519:old").has_value());
        auto worker_fetches = 0;
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::make_remote_key_resolver(
            worker.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                return allowed_discovery(server_name);
            },
            [&worker_fetches](merovingian::http::OutboundClient&, std::string_view, std::uint32_t) {
                ++worker_fetches;
                return merovingian::federation::RemoteKeyFetchResult{};
            },
            "local.example.org", merovingian::federation::KeyMirrorRefresh::on_miss);

        WHEN("the worker resolves the retired key id")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:old");

            THEN("it reads the retired row from the database and fetches nothing")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.retired);
                REQUIRE(resolved->signing_key.expired_ts == old_expired_ts);
                REQUIRE(worker_fetches == 0);
            }
        }
    }
}

SCENARIO("A key once listed as retired stays retired and keeps the earliest expiry",
         "[federation][remote-key-cache][old-keys][persist]")
{
    GIVEN("a store holding a current key")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto opened = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(opened.ok);
        auto const key = fresh_public_key_base64();
        auto const other = fresh_public_key_base64();
        REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                  response_with(
                                                                      {
                                                                          {"ed25519:k", key}
        },
                                                                      {}),
                                                                  now_ms));
        REQUIRE_FALSE(cached(opened.store, "ed25519:k")->retired);

        WHEN("a later response lists that key under old_verify_keys")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:o", other}
            },
                                                                          {{"ed25519:k", key, 5000U}}),
                                                                      now_ms));

            THEN("it is retired at once, valid only until it expired")
            {
                auto const record = cached(opened.store, "ed25519:k");
                REQUIRE(record.has_value());
                REQUIRE(record->retired);
                REQUIRE(record->expired_ts == 5000U);
                REQUIRE(record->valid_until_ts == 5000U);
            }
        }

        WHEN("it is retired, then listed again with a later and then an earlier expiry")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:o", other}
            },
                                                                          {{"ed25519:k", key, 5000U}}),
                                                                      now_ms));
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:o", other}
            },
                                                                          {{"ed25519:k", key, 9000U}}),
                                                                      now_ms));
            auto const after_later = cached(opened.store, "ed25519:k");
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:o", other}
            },
                                                                          {{"ed25519:k", key, 3000U}}),
                                                                      now_ms));
            auto const after_earlier = cached(opened.store, "ed25519:k");
            auto reopened = merovingian::database::open_sqlite_persistent_store(path);
            REQUIRE(reopened.ok);
            auto const reloaded = cached(reopened.store, "ed25519:k");

            THEN("a later expiry never raises the stored one and an earlier one lowers it, durably")
            {
                REQUIRE(after_later->expired_ts == 5000U);
                REQUIRE(after_earlier->expired_ts == 3000U);
                REQUIRE(after_earlier->valid_until_ts == 3000U);
                REQUIRE(reloaded->expired_ts == 3000U);
            }
        }

        WHEN("it is retired and a later response lists it under verify_keys again")
        {
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:o", other}
            },
                                                                          {{"ed25519:k", key, 5000U}}),
                                                                      now_ms));
            REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                      response_with(
                                                                          {
                                                                              {"ed25519:k", key  },
                                                                              {"ed25519:o", other}
            },
                                                                          {}),
                                                                      now_ms));
            auto const in_memory = cached(opened.store, "ed25519:k");
            auto reopened = merovingian::database::open_sqlite_persistent_store(path);
            REQUIRE(reopened.ok);
            auto const reloaded = cached(reopened.store, "ed25519:k");

            THEN("it is still retired with its expiry, in memory and after a reload")
            {
                REQUIRE(in_memory->retired);
                REQUIRE(in_memory->expired_ts == 5000U);
                REQUIRE(reloaded->retired);
                REQUIRE(reloaded->expired_ts == 5000U);
            }
        }

        WHEN("a retirement is written for a row that holds this server's own secret")
        {
            auto own = merovingian::database::PersistentServerSigningKey{"remote.example.org", "ed25519:own", key,
                                                                         now_ms + day_ms, "sealed-secret"};
            REQUIRE(merovingian::database::store_server_signing_key(opened.store, own));
            auto retirement =
                merovingian::database::PersistentServerSigningKey{"remote.example.org", "ed25519:own", key, 5000U};
            retirement.expired_ts = 5000U;
            auto with_secret = own;
            with_secret.key_id = "ed25519:own2";
            with_secret.expired_ts = 5000U;

            THEN("neither takes effect: own keys never get an expiry")
            {
                REQUIRE_FALSE(merovingian::database::store_server_signing_key(opened.store, retirement));
                REQUIRE_FALSE(merovingian::database::store_server_signing_key(opened.store, with_secret));
                auto const row =
                    merovingian::database::find_server_signing_key(opened.store, "remote.example.org", "ed25519:own");
                REQUIRE(row->expired_ts == 0U);
                REQUIRE(row->valid_until_ts == now_ms + day_ms);
            }
        }
    }
}

SCENARIO("Cached retired keys are never treated as current", "[federation][remote-key-cache][old-keys]")
{
    GIVEN("a store holding a retired key and a current one for the same server")
    {
        auto scratch = DatabaseScratch{};
        auto opened = merovingian::database::open_sqlite_persistent_store((scratch.path / "store.db").string());
        REQUIRE(opened.ok);
        auto const retired_key = fresh_public_key_base64();
        REQUIRE(merovingian::federation::cache_remote_server_keys(opened.store,
                                                                  response_with(
                                                                      {
                                                                          {"ed25519:cur", fresh_public_key_base64()}
        },
                                                                      {{"ed25519:old", retired_key, old_expired_ts}}),
                                                                  now_ms));

        WHEN("any cached key is asked for by server name alone")
        {
            auto const any = merovingian::federation::find_any_cached_remote_key(opened.store, "remote.example.org");

            THEN("only the current key can be returned")
            {
                REQUIRE(any.has_value());
                REQUIRE(any->key_id == "ed25519:cur");
                REQUIRE_FALSE(any->retired);
            }
        }

        WHEN("the freshness of the cached keys is judged long after the retired one expired")
        {
            auto const retired = cached(opened.store, "ed25519:old");
            auto const current = cached(opened.store, "ed25519:cur");
            auto request = merovingian::federation::SignedFederationRequest{};
            request.origin = "remote.example.org";
            request.key_id = "ed25519:old";
            request.now_ts = old_expired_ts - 1U;
            request.canonical_json_verified = true;
            request.body = "{}";
            auto const decision = merovingian::federation::verify_signed_federation_request(request, *retired);

            THEN("the retired key is usable from the cache and still never valid for a request")
            {
                REQUIRE(merovingian::federation::cached_remote_key_usable(*retired, now_ms + 400U * day_ms));
                REQUIRE_FALSE(merovingian::federation::cached_remote_key_usable(*current, now_ms + 400U * day_ms));
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.status == 403U);
            }
        }

        WHEN("an event sent before and one sent at the expiry are checked against the cached key")
        {
            auto const retired = cached(opened.store, "ed25519:old");
            auto const* v10 = merovingian::rooms::find_room_version_policy("10");
            REQUIRE(v10 != nullptr);
            auto const before = merovingian::federation::check_signing_key_valid_for_event(
                *retired, event_at(static_cast<std::int64_t>(old_expired_ts) - 1), *v10);
            auto const at = merovingian::federation::check_signing_key_valid_for_event(
                *retired, event_at(static_cast<std::int64_t>(old_expired_ts)), *v10);

            THEN("the first verifies with no network and the second is refused")
            {
                REQUIRE(before.accepted);
                REQUIRE_FALSE(at.accepted);
                REQUIRE(at.status == 403U);
            }
        }
    }
}
