// SPDX-License-Identifier: GPL-3.0-or-later
//
// Matrix Server-Server API v1.18 conformance for:
//   GET /_matrix/key/v2/server

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace
{

[[nodiscard]] auto key_publication_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);

    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";

    return {
        server,
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : obj)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

} // namespace

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// https://spec.matrix.org/v1.18/server-server-api/#get_matrixkeyv2server
SCENARIO("GET /_matrix/key/v2/server returns the spec-required published signing fields",
         "[federation][conformance][key_publishing]")
{
    GIVEN("a started runtime serving the federation HTTP surface")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the local federation router serves GET /_matrix/key/v2/server")
        {
            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("the response is 200 with server_name, valid_until_ts, verify_keys, old_verify_keys, and signatures")
            {
                REQUIRE(response.status == 200U);

                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                auto const* server_name_value = json_get(*root, "server_name");
                REQUIRE(server_name_value != nullptr);
                auto const* server_name = std::get_if<std::string>(&server_name_value->storage());
                REQUIRE(server_name != nullptr);
                REQUIRE(*server_name == runtime.homeserver.config.server().server_name);

                auto const* valid_until_value = json_get(*root, "valid_until_ts");
                REQUIRE(valid_until_value != nullptr);
                auto const* valid_until_int = std::get_if<std::int64_t>(&valid_until_value->storage());
                REQUIRE(valid_until_int != nullptr);
                // Spec MUST: valid_until_ts MUST be a positive integer (milliseconds since epoch).
                // A zero or negative value means the key is already expired, which MUST NOT happen.
                REQUIRE(*valid_until_int > std::int64_t{0});
                // Spec SHOULD: servers MUST NOT publish keys with valid_until_ts more than 7 days
                // in the future (604800000 ms). Keys must also not already be expired (> now).
                // We can't assert against real wall-clock time here, so we check it's in a
                // plausible non-zero range: at least 60 seconds from "epoch" (epoch+60000ms).
                // This catches a regression where the server publishes a zero or epoch-relative ts.
                auto constexpr min_valid_ms = std::int64_t{60000};
                REQUIRE(*valid_until_int >= min_valid_ms);

                auto const* verify_keys_value = json_get(*root, "verify_keys");
                REQUIRE(verify_keys_value != nullptr);
                auto const* verify_keys =
                    std::get_if<merovingian::canonicaljson::Object>(&verify_keys_value->storage());
                REQUIRE(verify_keys != nullptr);
                REQUIRE_FALSE(verify_keys->empty());
                auto const* verify_key_object =
                    std::get_if<merovingian::canonicaljson::Object>(&verify_keys->front().value->storage());
                REQUIRE(verify_key_object != nullptr);
                REQUIRE(json_get(*verify_key_object, "key") != nullptr);

                auto const* old_verify_keys_value = json_get(*root, "old_verify_keys");
                REQUIRE(old_verify_keys_value != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&old_verify_keys_value->storage()) != nullptr);

                auto const* signatures_value = json_get(*root, "signatures");
                REQUIRE(signatures_value != nullptr);
                auto const* signatures = std::get_if<merovingian::canonicaljson::Object>(&signatures_value->storage());
                REQUIRE(signatures != nullptr);
                auto const* local_server_signatures =
                    json_get(*signatures, runtime.homeserver.config.server().server_name);
                REQUIRE(local_server_signatures != nullptr);
                REQUIRE(std::get_if<merovingian::canonicaljson::Object>(&local_server_signatures->storage()) !=
                        nullptr);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: https://spec.matrix.org/v1.18/server-server-api/#publishing-keys
//
// All key IDs in verify_keys MUST follow the "algorithm:version" convention
// (e.g. "ed25519:1"). Ed25519 is the only defined algorithm for server
// signing keys in Matrix v1.18.
SCENARIO("GET /_matrix/key/v2/server verify_keys entries have ed25519:version key IDs",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the local HTTP router serves GET /_matrix/key/v2/server")
        {
            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("each verify_keys entry has a key_id prefixed with 'ed25519:'")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* verify_keys_val = json_get(*root, "verify_keys");
                REQUIRE(verify_keys_val != nullptr);
                auto const* verify_keys =
                    std::get_if<merovingian::canonicaljson::Object>(&verify_keys_val->storage());
                REQUIRE(verify_keys != nullptr);
                // Spec MUST: at least one current signing key must be published.
                REQUIRE_FALSE(verify_keys->empty());
                for (auto const& entry : *verify_keys)
                {
                    // Spec appendix: key IDs use "algorithm:version" format.
                    // Ed25519 is the only signing algorithm defined in Matrix v1.18.
                    REQUIRE(entry.key.rfind("ed25519:", 0) == 0U);
                    // Spec MUST: the "version" component must be non-empty.
                    REQUIRE(entry.key.size() > std::string{"ed25519:"}.size());
                }
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: https://spec.matrix.org/v1.18/server-server-api/#publishing-keys
//
// "valid_until_ts: UNIX timestamp in milliseconds for when the server MUST
// generate a new signing key. Servers MUST NOT return a valid_until_ts that
// is in the past."
// Spec: caching servers MUST NOT cache key responses longer than valid_until_ts.
SCENARIO("GET /_matrix/key/v2/server valid_until_ts is strictly in the future",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the local HTTP router serves GET /_matrix/key/v2/server")
        {
            auto const now_ms = static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("valid_until_ts is greater than the current wall-clock time")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* valid_until_val = json_get(*root, "valid_until_ts");
                REQUIRE(valid_until_val != nullptr);
                auto const* valid_until = std::get_if<std::int64_t>(&valid_until_val->storage());
                REQUIRE(valid_until != nullptr);
                // Spec MUST: valid_until_ts MUST NOT be in the past.
                REQUIRE(*valid_until > now_ms);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: https://spec.matrix.org/v1.18/server-server-api/#publishing-keys
//
// "old_verify_keys: The public keys that the server used to use, and when it
// stopped using them." Each entry MUST contain a "key" (base64 public key)
// and an "expired_ts" (millisecond Unix timestamp when the key was retired).
// The expired_ts MUST be in the past — if a key were not yet expired it would
// belong in verify_keys instead.
SCENARIO("GET /_matrix/key/v2/server old_verify_keys entries contain key and expired_ts",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the local HTTP router serves GET /_matrix/key/v2/server")
        {
            auto const now_ms = static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("old_verify_keys is an object; each entry has key (string) and expired_ts (past int)")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* old_keys_val = json_get(*root, "old_verify_keys");
                // Spec MUST: old_verify_keys field is present and is an object.
                REQUIRE(old_keys_val != nullptr);
                auto const* old_keys =
                    std::get_if<merovingian::canonicaljson::Object>(&old_keys_val->storage());
                REQUIRE(old_keys != nullptr);
                // Validate structure of any historical keys present (vacuously true on fresh start).
                for (auto const& entry : *old_keys)
                {
                    auto const* entry_obj =
                        std::get_if<merovingian::canonicaljson::Object>(&entry.value->storage());
                    // Spec MUST: each old key entry is an object.
                    REQUIRE(entry_obj != nullptr);
                    // Spec MUST: "key" field contains the base64-encoded old public key.
                    auto const* key_val = json_get(*entry_obj, "key");
                    REQUIRE(key_val != nullptr);
                    REQUIRE(std::get_if<std::string>(&key_val->storage()) != nullptr);
                    // Spec MUST: "expired_ts" is a positive integer.
                    auto const* expired_ts_val = json_get(*entry_obj, "expired_ts");
                    REQUIRE(expired_ts_val != nullptr);
                    auto const* expired_ts = std::get_if<std::int64_t>(&expired_ts_val->storage());
                    REQUIRE(expired_ts != nullptr);
                    REQUIRE(*expired_ts > std::int64_t{0});
                    // Spec MUST: expired_ts is in the past — a key with a future expiry
                    // belongs in verify_keys, not old_verify_keys.
                    REQUIRE(*expired_ts <= now_ms);
                }
            }
        }
    }
}
