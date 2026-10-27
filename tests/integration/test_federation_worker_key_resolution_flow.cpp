// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Regression for Complement run 2 (0.12.58): a federation worker refused every
// signed request from a server it had not cached at start-up with
// `403 remote is unknown`. The worker's key cache is read-only (its SQLite
// connection; on PostgreSQL its role), and the resolver read the key back from
// the cache after writing it (ADR-0238).
//
// This drives the real inbound gate (handle_inbound_federation_request) and the
// real resolver composition over main's SQLite database opened as a worker
// opens it. Only the HTTP fetch is replaced: it returns a key response
// genuinely self-signed by the key that signs the X-Matrix header, so the
// request is verified with the key the worker fetched.
#include "../federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include <stdlib.h>

namespace
{
class DatabaseScratch final
{
public:
    DatabaseScratch()
    {
        auto pattern = (std::filesystem::temp_directory_path() / "merov-worker-keys-XXXXXX").string();
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

constexpr auto origin = std::string_view{"newcomer.example.org"};
constexpr auto key_id = std::string_view{"ed25519:k1"};
constexpr auto key_seed = std::string_view{"worker-key-resolution-regression"};
constexpr auto now_ms = std::uint64_t{1000U};
constexpr auto day_ms = std::uint64_t{24U * 60U * 60U * 1000U};

// GET /_matrix/key/v2/server for `origin`, self-signed by the seeded keypair.
[[nodiscard]] auto published_keys() -> std::string
{
    namespace cj = merovingian::canonicaljson;
    auto const keypair = merovingian::federation::test::keypair_from_seed(key_seed);
    auto key_entry = cj::Object{};
    key_entry.push_back(cj::make_member("key", cj::Value{merovingian::federation::test::pubkey_b64(keypair)}));
    auto verify_keys = cj::Object{};
    verify_keys.push_back(cj::make_member(std::string{key_id}, cj::Value{std::move(key_entry)}));
    auto response = cj::Object{};
    response.push_back(cj::make_member("old_verify_keys", cj::Value{cj::Object{}}));
    response.push_back(cj::make_member("server_name", cj::Value{std::string{origin}}));
    response.push_back(cj::make_member("valid_until_ts", cj::Value{static_cast<std::int64_t>(now_ms + 30U * day_ms)}));
    response.push_back(cj::make_member("verify_keys", cj::Value{std::move(verify_keys)}));
    auto const payload = cj::serialize_canonical(cj::Value{response});
    REQUIRE(payload.error == cj::CanonicalJsonError::none);

    auto key_signature = cj::Object{};
    key_signature.push_back(cj::make_member(
        std::string{key_id},
        cj::Value{merovingian::federation::test::sign_payload_b64(payload.output, keypair.secret_key)}));
    auto signatures = cj::Object{};
    signatures.push_back(cj::make_member(std::string{origin}, cj::Value{std::move(key_signature)}));
    response.push_back(cj::make_member("signatures", cj::Value{std::move(signatures)}));
    auto const body = cj::serialize_canonical(cj::Value{std::move(response)});
    REQUIRE(body.error == cj::CanonicalJsonError::none);
    return body.output;
}

// An empty /send transaction from `origin`, X-Matrix-signed with its key.
[[nodiscard]] auto signed_transaction(std::string_view txn_id) -> merovingian::federation::SignedFederationRequest
{
    auto request = merovingian::federation::SignedFederationRequest{};
    request.method = "PUT";
    request.target = "/_matrix/federation/v1/send/" + std::string{txn_id};
    request.origin = std::string{origin};
    request.destination = "local.example.org";
    request.key_id = std::string{key_id};
    request.now_ts = now_ms;
    request.canonical_json_verified = true;
    request.body = R"({"origin":")" + std::string{origin} + R"(","origin_server_ts":1000,"pdus":[]})";
    request.signature = merovingian::federation::make_federation_signature(
        request.origin, request.destination, request.method, request.target, request.body,
        merovingian::federation::test::keypair_from_seed(key_seed).secret_key);
    return request;
}

[[nodiscard]] auto federation_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 4096U;
    config.remote_timeout_seconds = 30U;
    return config;
}
} // namespace

SCENARIO("A federation worker accepts a signed request from a server it has never cached",
         "[integration][federation-worker][worker-key-cache][security]")
{
    GIVEN("main's SQLite database opened read-only as a worker opens it, and the worker's inbound gate with the "
          "persistent resolver over that store")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        REQUIRE(merovingian::database::open_sqlite_persistent_store(path).ok);
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);

        auto const keys = published_keys();
        auto fetches = 0;
        auto client = merovingian::http::OutboundClient{};
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_config());
        runtime.remote_key_resolver = merovingian::federation::make_remote_key_resolver(
            worker.store, client, 1U,
            [] {
                return now_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                auto discovery = merovingian::federation::ServerDiscoveryResult{};
                discovery.server_name = std::string{server_name};
                discovery.resolved_host = std::string{server_name};
                discovery.tls_server_name = std::string{server_name};
                discovery.pinned_addresses = {"203.0.113.20"};
                discovery.discovery_allowed = true;
                return discovery;
            },
            [&keys, &fetches](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                ++fetches;
                return merovingian::federation::parse_and_verify_remote_key_response(keys, server_name);
            },
            "local.example.org");

        WHEN("the server's first signed transaction arrives")
        {
            auto const first =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_transaction("t1"));

            THEN("it is accepted with the fetched key, although the worker could not cache it")
            {
                REQUIRE(first.status == 200U);
                REQUIRE(first.body == R"({"pdus":{}})");
                REQUIRE(fetches == 1);
                REQUIRE_FALSE(
                    merovingian::federation::find_cached_remote_key(worker.store, origin, key_id).has_value());
            }

            AND_WHEN("a second transaction arrives from the same server")
            {
                auto const second =
                    merovingian::federation::handle_inbound_federation_request(runtime, signed_transaction("t2"));

                THEN("it is accepted from the worker's in-memory record, without another fetch")
                {
                    REQUIRE(second.status == 200U);
                    REQUIRE(fetches == 1);
                }
            }
        }
    }
}
