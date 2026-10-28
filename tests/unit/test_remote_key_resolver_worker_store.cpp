// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0238: the remote key resolver uses the key it has just fetched and
// verified, whether or not caching it succeeds. A federation worker cannot
// write the key cache: its SQLite connection is read-only, and its PostgreSQL
// role has SELECT only on server_signing_keys. A resolver that read the key
// back from the store after a failed write refused every server it had not
// already cached when it started (Complement run 2, "remote is unknown").
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <sodium.h>
#include <stdlib.h>

namespace
{
class DatabaseScratch final
{
public:
    DatabaseScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-key-resolver-XXXXXX").string();
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

struct SignedKeyResponse final
{
    std::string body{};
    std::string public_key_base64{};
};

// A canonical, self-signed GET /_matrix/key/v2/server response for a fresh keypair.
[[nodiscard]] auto signed_key_response(std::string_view server_name, std::string_view key_id,
                                       std::uint64_t valid_until_ts) -> SignedKeyResponse
{
    REQUIRE(sodium_init() >= 0);
    auto public_key = std::array<unsigned char, crypto_sign_PUBLICKEYBYTES>{};
    auto secret_key = std::array<unsigned char, crypto_sign_SECRETKEYBYTES>{};
    REQUIRE(crypto_sign_keypair(public_key.data(), secret_key.data()) == 0);
    auto const public_key_base64 = merovingian::events::matrix_base64_from_bytes(
        std::string_view{reinterpret_cast<char const*>(public_key.data()), public_key.size()});

    namespace cj = merovingian::canonicaljson;
    auto key_entry = cj::Object{};
    key_entry.push_back(cj::make_member("key", cj::Value{public_key_base64}));
    auto verify_keys = cj::Object{};
    verify_keys.push_back(cj::make_member(std::string{key_id}, cj::Value{std::move(key_entry)}));
    auto response = cj::Object{};
    response.push_back(cj::make_member("old_verify_keys", cj::Value{cj::Object{}}));
    response.push_back(cj::make_member("server_name", cj::Value{std::string{server_name}}));
    response.push_back(cj::make_member("valid_until_ts", cj::Value{static_cast<std::int64_t>(valid_until_ts)}));
    response.push_back(cj::make_member("verify_keys", cj::Value{std::move(verify_keys)}));

    auto const payload = cj::serialize_canonical(cj::Value{response});
    REQUIRE(payload.error == cj::CanonicalJsonError::none);
    auto signature = std::string(crypto_sign_BYTES, '\0');
    REQUIRE(crypto_sign_detached(reinterpret_cast<unsigned char*>(signature.data()), nullptr,
                                 reinterpret_cast<unsigned char const*>(payload.output.data()), payload.output.size(),
                                 secret_key.data()) == 0);
    auto server_signatures = cj::Object{};
    server_signatures.push_back(
        cj::make_member(std::string{key_id}, cj::Value{merovingian::events::matrix_base64_from_bytes(signature)}));
    auto signatures = cj::Object{};
    signatures.push_back(cj::make_member(std::string{server_name}, cj::Value{std::move(server_signatures)}));
    response.push_back(cj::make_member("signatures", cj::Value{std::move(signatures)}));
    auto const signed_body = cj::serialize_canonical(cj::Value{std::move(response)});
    REQUIRE(signed_body.error == cj::CanonicalJsonError::none);
    return {signed_body.output, public_key_base64};
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

constexpr auto now_ms = std::uint64_t{1'800'000'000'000U};
constexpr auto day_ms = std::uint64_t{24U * 60U * 60U * 1000U};
} // namespace

SCENARIO("A federation worker's resolver uses the key it fetched although it cannot cache it",
         "[federation][remote-key-cache][resolver][worker-key-cache]")
{
    GIVEN("main's SQLite database, opened read-only as a federation worker opens it, and a remote serving a "
          "self-signed key")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        REQUIRE(merovingian::database::open_sqlite_persistent_store(path).ok);
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);

        auto const published = signed_key_response("remote.example.org", "ed25519:abc", now_ms + 30U * day_ms);
        auto fetches = 0;
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::make_remote_key_resolver(
            worker.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                return allowed_discovery(server_name);
            },
            [&published, &fetches](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                ++fetches;
                return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
            },
            "local.example.org");

        WHEN("the worker resolves the remote's key for the first time")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("it returns the fetched key, trusted for at most seven days, although nothing was cached")
            {
                REQUIRE(fetches == 1);
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.server_name == "remote.example.org");
                REQUIRE(resolved->signing_key.key_id == "ed25519:abc");
                REQUIRE(merovingian::events::matrix_base64_from_bytes(resolved->signing_key.public_key_bytes) ==
                        published.public_key_base64);
                // rooms/v5.md: the lesser of valid_until_ts and seven days after the fetch.
                REQUIRE(resolved->signing_key.valid_until_ts == now_ms + 7U * day_ms);
                REQUIRE_FALSE(
                    merovingian::federation::find_cached_remote_key(worker.store, "remote.example.org", "ed25519:abc")
                        .has_value());
            }
        }

        WHEN("the worker asks for a key ID the remote does not publish")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:other");

            THEN("nothing resolves")
            {
                REQUIRE(fetches == 1);
                REQUIRE_FALSE(resolved.has_value());
            }
        }
    }
}

SCENARIO("Main's resolver still caches the key it fetched",
         "[federation][remote-key-cache][resolver][worker-key-cache]")
{
    GIVEN("a writable store and a remote serving a self-signed key")
    {
        auto main = merovingian::database::open_persistent_store();
        REQUIRE(main.ok);
        auto const published = signed_key_response("remote.example.org", "ed25519:abc", now_ms + 2U * day_ms);
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::make_remote_key_resolver(
            main.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                return allowed_discovery(server_name);
            },
            [&published](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
            },
            "local.example.org");

        WHEN("the key is resolved")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("it is returned and cached with the published validity, which is under seven days")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(resolved->signing_key.valid_until_ts == now_ms + 2U * day_ms);
                auto const cached =
                    merovingian::federation::find_cached_remote_key(main.store, "remote.example.org", "ed25519:abc");
                REQUIRE(cached.has_value());
                REQUIRE(cached->public_key_bytes == resolved->signing_key.public_key_bytes);
            }
        }
    }
}

SCENARIO("The resolver refuses a fetched key when discovery refuses the server",
         "[federation][remote-key-cache][resolver][worker-key-cache][security]")
{
    GIVEN("a read-only worker store and a remote whose discovery is refused")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        REQUIRE(merovingian::database::open_sqlite_persistent_store(path).ok);
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);
        auto const published = signed_key_response("remote.example.org", "ed25519:abc", now_ms + 30U * day_ms);
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::make_remote_key_resolver(
            worker.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                auto refused = merovingian::federation::ServerDiscoveryResult{};
                refused.server_name = std::string{server_name};
                refused.reason = "address denied";
                return refused;
            },
            [&published](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
            },
            "local.example.org");

        WHEN("the key is resolved")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("nothing resolves: a server we cannot reach SSRF-safely is not admitted")
            {
                REQUIRE_FALSE(resolved.has_value());
            }
        }
    }
}
