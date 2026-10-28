// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A6 (Complement run 9): a federation worker's key mirror is a snapshot taken
// when it started. A server main met afterwards was unknown to the worker, which
// then fetched its keys again over a fresh connection, discovery and TLS
// handshake included, in front of the first PDU main had already authenticated.
// The worker may read the row main verified and persisted; it still never reads
// this server's own signing secret.
//
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys
// (valid_until_ts: "Servers MUST use the lesser of this field and 7 days").
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/runtime.hpp"
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
        auto pattern = (std::filesystem::temp_directory_path() / "merov-key-readthrough-XXXXXX").string();
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

[[nodiscard]] auto runtime_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            security,
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}
} // namespace

SCENARIO("A federation worker reads a key main cached after the worker started instead of fetching it again",
         "[federation][remote-key-cache][resolver][worker-key-cache][worker-key-read-through]")
{
    GIVEN("a worker whose store was opened before main cached a remote's key")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);

        auto const published = signed_key_response("remote.example.org", "ed25519:abc", now_ms + 30U * day_ms);
        auto client = merovingian::http::OutboundClient{};
        auto const discover = [](std::string_view server_name, std::uint32_t) {
            return allowed_discovery(server_name);
        };
        auto main_fetches = 0;
        auto main_resolver = merovingian::federation::make_remote_key_resolver(
            main.store, client, 1U,
            [] {
                return now_ms;
            },
            discover,
            [&published, &main_fetches](merovingian::http::OutboundClient&, std::string_view server_name,
                                        std::uint32_t) {
                ++main_fetches;
                return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
            },
            "local.example.org");
        REQUIRE(main_resolver("remote.example.org", "ed25519:abc").has_value());
        REQUIRE(main_fetches == 1);
        REQUIRE_FALSE(merovingian::federation::find_cached_remote_key(worker.store, "remote.example.org", "ed25519:abc")
                          .has_value());

        auto worker_fetches = 0;
        auto const fetch = [&published, &worker_fetches](merovingian::http::OutboundClient&,
                                                         std::string_view server_name, std::uint32_t) {
            ++worker_fetches;
            return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
        };

        WHEN("the worker resolves that key with the database read-through enabled")
        {
            auto resolver = merovingian::federation::make_remote_key_resolver(
                worker.store, client, 1U,
                [] {
                    return now_ms;
                },
                discover, fetch, "local.example.org", merovingian::federation::KeyMirrorRefresh::on_miss);
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("it resolves the key main verified without fetching, trusted for the cached validity")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(worker_fetches == 0);
                REQUIRE(merovingian::events::matrix_base64_from_bytes(resolved->signing_key.public_key_bytes) ==
                        published.public_key_base64);
                REQUIRE(resolved->signing_key.valid_until_ts == now_ms + 7U * day_ms);
            }
        }

        WHEN("the worker resolves that key without the read-through")
        {
            auto resolver = merovingian::federation::make_remote_key_resolver(
                worker.store, client, 1U,
                [] {
                    return now_ms;
                },
                discover, fetch, "local.example.org");
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("it fetches as before, so the read-through is what removes the round trip")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(worker_fetches == 1);
            }
        }

        WHEN("the worker asks, with the read-through enabled, for a key ID the remote does not publish")
        {
            auto resolver = merovingian::federation::make_remote_key_resolver(
                worker.store, client, 1U,
                [] {
                    return now_ms;
                },
                discover, fetch, "local.example.org", merovingian::federation::KeyMirrorRefresh::on_miss);
            auto const unknown = resolver("remote.example.org", "ed25519:never_published");

            THEN("an absent row still falls through to a verified fetch, which fails for that key ID")
            {
                REQUIRE_FALSE(unknown.has_value());
                REQUIRE(worker_fetches == 1);
            }
        }
    }
}

SCENARIO("A federation worker reads a refreshed key row once its mirror of that row has lapsed",
         "[federation][remote-key-cache][resolver][worker-key-cache][worker-key-read-through]")
{
    GIVEN("a worker whose mirror holds a key that lapsed, and main has since re-cached it with a later validity")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        auto const published = signed_key_response("remote.example.org", "ed25519:abc", now_ms + 30U * day_ms);
        REQUIRE(merovingian::database::store_server_signing_key(
            main.store, {"remote.example.org", "ed25519:abc", published.public_key_base64, now_ms + day_ms / 24U}));
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);
        REQUIRE(merovingian::database::store_server_signing_key(
            main.store, {"remote.example.org", "ed25519:abc", published.public_key_base64, now_ms + 5U * day_ms}));

        auto fetches = 0;
        auto client = merovingian::http::OutboundClient{};
        auto resolver = merovingian::federation::make_remote_key_resolver(
            worker.store, client, 1U,
            [] {
                return now_ms + day_ms;
            },
            [](std::string_view server_name, std::uint32_t) {
                return allowed_discovery(server_name);
            },
            [&published, &fetches](merovingian::http::OutboundClient&, std::string_view server_name, std::uint32_t) {
                ++fetches;
                return merovingian::federation::parse_and_verify_remote_key_response(published.body, server_name);
            },
            "local.example.org", merovingian::federation::KeyMirrorRefresh::on_miss);

        WHEN("the worker resolves the key a day later")
        {
            auto const resolved = resolver("remote.example.org", "ed25519:abc");

            THEN("it uses main's refreshed row, not its lapsed copy and not a fetch")
            {
                REQUIRE(resolved.has_value());
                REQUIRE(fetches == 0);
                REQUIRE(resolved->signing_key.valid_until_ts == now_ms + 5U * day_ms);
            }
        }
    }
}

SCENARIO("A worker's key refresh reads public columns only and never this server's signing secret",
         "[federation][remote-key-cache][worker-key-cache][worker-key-read-through][security]")
{
    GIVEN("a worker opened before main stored this server's own signing key with its secret")
    {
        auto scratch = DatabaseScratch{};
        auto const path = (scratch.path / "store.db").string();
        auto main = merovingian::database::open_sqlite_persistent_store(path);
        REQUIRE(main.ok);
        auto worker = merovingian::database::open_sqlite_persistent_store(
            path, merovingian::database::TableLoadProfile::federation_worker);
        REQUIRE(worker.ok);
        REQUIRE(merovingian::database::store_server_signing_key(
            main.store, {"local.example.org", "ed25519:own", "cHVibGljLWtleQ", now_ms + day_ms, "SECRET-CIPHERTEXT"}));

        WHEN("the worker refreshes the signing keys it holds for this server's name")
        {
            REQUIRE(merovingian::database::refresh_remote_signing_keys(worker.store, "local.example.org"));
            auto const row =
                merovingian::database::find_server_signing_key(worker.store, "local.example.org", "ed25519:own");

            THEN("the public key is mirrored, and the secret stays empty")
            {
                REQUIRE(row.has_value());
                REQUIRE(row->public_key == "cHVibGljLWtleQ");
                REQUIRE(row->secret_key.empty());
            }
        }

        WHEN("an in-memory store, which has no database to read, is refreshed")
        {
            auto memory = merovingian::database::open_persistent_store();
            REQUIRE(memory.ok);

            THEN("the refresh is a successful no-op")
            {
                REQUIRE(merovingian::database::refresh_remote_signing_keys(memory.store, "remote.example.org"));
            }
        }
    }
}

SCENARIO("Only a federation worker's runtime reads signing keys through to the database",
         "[federation][remote-key-cache][worker-key-cache][worker-key-read-through]")
{
    GIVEN("a runtime started as main and another started with the federation worker load profile")
    {
        REQUIRE(sodium_init() >= 0);
        auto const main = merovingian::homeserver::start_runtime(merovingian::homeserver::RuntimeStartOptions{
            .config = runtime_config(),
        });
        auto const worker = merovingian::homeserver::start_runtime(merovingian::homeserver::RuntimeStartOptions{
            .config = runtime_config(),
            .signing_disabled = true,
            .database_load_profile = merovingian::database::TableLoadProfile::federation_worker,
        });

        WHEN("each runtime's database state is inspected")
        {
            THEN("main's mirror stays authoritative and the worker's re-reads on a miss")
            {
                REQUIRE(main.started);
                REQUIRE(worker.started);
                REQUIRE_FALSE(main.runtime.database.remote_signing_keys_read_through);
                REQUIRE(worker.runtime.database.remote_signing_keys_read_through);
            }
        }
    }
}
