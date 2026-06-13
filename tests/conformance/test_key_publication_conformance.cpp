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
#include "merovingian/homeserver/room_service.hpp"

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

// Convenience: fetch a member and narrow it to an Object in one step, returning
// nullptr if the member is absent or not an object. Keeps the rotation scenarios
// readable while preserving strict null-checking before every dereference.
[[nodiscard]] auto get_object(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Object const*
{
    auto const* value = json_get(obj, key);
    return value == nullptr ? nullptr : std::get_if<merovingian::canonicaljson::Object>(&value->storage());
}

} // namespace

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixkeyv2server
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
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
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
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
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
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
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

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
//
// "old_verify_keys: The public keys that the server used to use, and when it
// stopped using them." After rotating its signing key, the server MUST publish
// the newly generated key in verify_keys and move the previously active key into
// old_verify_keys with an expired_ts in the past, so federation peers can still
// verify events signed under the retired key while rejecting it as a current key.
SCENARIO("GET /_matrix/key/v2/server reflects a signing key rotation",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime serving an initial active signing key")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const before = merovingian::homeserver::dispatch_local_http_request(
            runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
            merovingian::homeserver::HttpDispatchMode::federation);
        REQUIRE(before.status == 200U);
        auto const before_parsed = merovingian::canonicaljson::parse_lossless(before.body);
        auto const* before_root = std::get_if<merovingian::canonicaljson::Object>(&before_parsed.value.storage());
        REQUIRE(before_root != nullptr);
        auto const* before_verify_value = json_get(*before_root, "verify_keys");
        REQUIRE(before_verify_value != nullptr);
        auto const* before_verify_keys =
            std::get_if<merovingian::canonicaljson::Object>(&before_verify_value->storage());
        REQUIRE(before_verify_keys != nullptr);
        // Exactly one signing key is active before rotation.
        REQUIRE(before_verify_keys->size() == 1U);
        auto const original_key_id = before_verify_keys->front().key;

        WHEN("the signing key is rotated and the key server is served again")
        {
            auto const rotation = merovingian::homeserver::rotate_server_signing_key(runtime.homeserver);
            REQUIRE(rotation.ok);

            auto const now_ms = static_cast<std::int64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());

            auto const after = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("the new key is active in verify_keys and the previous key is retired in old_verify_keys")
            {
                REQUIRE(after.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(after.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: the current active signing key is published in verify_keys.
                auto const* verify_value = json_get(*root, "verify_keys");
                REQUIRE(verify_value != nullptr);
                auto const* verify_keys = std::get_if<merovingian::canonicaljson::Object>(&verify_value->storage());
                REQUIRE(verify_keys != nullptr);
                REQUIRE(verify_keys->size() == 1U);
                auto const new_key_id = verify_keys->front().key;
                // Rotation MUST activate a new, distinct key id derived from the new key material.
                REQUIRE(new_key_id != original_key_id);
                // Spec appendix: key IDs use the "ed25519:version" format.
                REQUIRE(new_key_id.rfind("ed25519:", 0) == 0U);

                // Spec MUST: the superseded key MUST appear in old_verify_keys.
                auto const* old_value = json_get(*root, "old_verify_keys");
                REQUIRE(old_value != nullptr);
                auto const* old_keys = std::get_if<merovingian::canonicaljson::Object>(&old_value->storage());
                REQUIRE(old_keys != nullptr);
                auto const* retired_value = json_get(*old_keys, original_key_id);
                REQUIRE(retired_value != nullptr);
                auto const* retired = std::get_if<merovingian::canonicaljson::Object>(&retired_value->storage());
                REQUIRE(retired != nullptr);
                // Spec MUST: each old key entry exposes its base64 public key for verifying old events.
                REQUIRE(json_get(*retired, "key") != nullptr);
                // Spec MUST: expired_ts is a positive, past millisecond timestamp (key no longer active).
                auto const* expired_value = json_get(*retired, "expired_ts");
                REQUIRE(expired_value != nullptr);
                auto const* expired_ts = std::get_if<std::int64_t>(&expired_value->storage());
                REQUIRE(expired_ts != nullptr);
                REQUIRE(*expired_ts > std::int64_t{0});
                REQUIRE(*expired_ts <= now_ms);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
//
// End-to-end rotation: the published key document MUST be signed by the server's
// current (post-rotation) key, and the retired key's republished public key MUST
// be byte-identical to the key it had while active, so a federation peer can still
// verify events signed before the rotation.
SCENARIO("GET /_matrix/key/v2/server after rotation is signed by the new key and preserves the retired public key",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime with an initial active signing key")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const before = merovingian::homeserver::dispatch_local_http_request(
            runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
            merovingian::homeserver::HttpDispatchMode::federation);
        REQUIRE(before.status == 200U);
        auto const before_parsed = merovingian::canonicaljson::parse_lossless(before.body);
        auto const* before_root = std::get_if<merovingian::canonicaljson::Object>(&before_parsed.value.storage());
        REQUIRE(before_root != nullptr);
        auto const* before_verify = get_object(*before_root, "verify_keys");
        REQUIRE(before_verify != nullptr);
        REQUIRE(before_verify->size() == 1U);
        auto const original_key_id = before_verify->front().key;
        auto const* original_entry =
            std::get_if<merovingian::canonicaljson::Object>(&before_verify->front().value->storage());
        REQUIRE(original_entry != nullptr);
        auto const* original_key_value = json_get(*original_entry, "key");
        REQUIRE(original_key_value != nullptr);
        auto const* original_public_key = std::get_if<std::string>(&original_key_value->storage());
        REQUIRE(original_public_key != nullptr);
        auto const original_public_key_text = *original_public_key;

        WHEN("the signing key is rotated")
        {
            auto const rotation = merovingian::homeserver::rotate_server_signing_key(runtime.homeserver);
            REQUIRE(rotation.ok);
            // The rotation result carries the new active key id.
            auto const new_key_id = rotation.value;

            auto const after = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("the response is signed by the new key and old_verify_keys preserves the retired public key")
            {
                REQUIRE(after.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(after.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: the key server response is signed by the server's current key.
                auto const* signatures = get_object(*root, "signatures");
                REQUIRE(signatures != nullptr);
                auto const* server_signatures =
                    get_object(*signatures, runtime.homeserver.config.server().server_name);
                REQUIRE(server_signatures != nullptr);
                // Signed under the NEW active key id produced by the rotation.
                REQUIRE(json_get(*server_signatures, new_key_id) != nullptr);
                // The retired key MUST NOT sign new responses.
                REQUIRE(json_get(*server_signatures, original_key_id) == nullptr);

                // Continuity: the retired key's republished public key matches the original.
                auto const* old_keys = get_object(*root, "old_verify_keys");
                REQUIRE(old_keys != nullptr);
                auto const* retired = get_object(*old_keys, original_key_id);
                REQUIRE(retired != nullptr);
                auto const* retired_key_value = json_get(*retired, "key");
                REQUIRE(retired_key_value != nullptr);
                auto const* retired_public_key = std::get_if<std::string>(&retired_key_value->storage());
                REQUIRE(retired_public_key != nullptr);
                REQUIRE(*retired_public_key == original_public_key_text);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.18
// Endpoint: GET /_matrix/key/v2/server
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#publishing-keys
//
// "old_verify_keys: The public keys that the server used to use..." Across multiple
// rotations every superseded key MUST remain in old_verify_keys (peers verify old
// events with them) while only the most recent key stays active in verify_keys.
SCENARIO("Repeated signing-key rotations accumulate every superseded key in old_verify_keys",
         "[federation][conformance][key_publishing][key_rotation]")
{
    GIVEN("a started runtime with an initial active signing key")
    {
        auto started = merovingian::homeserver::start_client_server(key_publication_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const before = merovingian::homeserver::dispatch_local_http_request(
            runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
            merovingian::homeserver::HttpDispatchMode::federation);
        REQUIRE(before.status == 200U);
        auto const before_parsed = merovingian::canonicaljson::parse_lossless(before.body);
        auto const* before_root = std::get_if<merovingian::canonicaljson::Object>(&before_parsed.value.storage());
        REQUIRE(before_root != nullptr);
        auto const* first_verify = get_object(*before_root, "verify_keys");
        REQUIRE(first_verify != nullptr);
        REQUIRE(first_verify->size() == 1U);
        auto const first_key_id = first_verify->front().key;

        WHEN("the signing key is rotated twice")
        {
            auto const first_rotation = merovingian::homeserver::rotate_server_signing_key(runtime.homeserver);
            REQUIRE(first_rotation.ok);
            auto const second_key_id = first_rotation.value;
            auto const second_rotation = merovingian::homeserver::rotate_server_signing_key(runtime.homeserver);
            REQUIRE(second_rotation.ok);
            auto const third_key_id = second_rotation.value;
            // Each rotation must mint a distinct key id.
            REQUIRE(second_key_id != first_key_id);
            REQUIRE(third_key_id != second_key_id);
            REQUIRE(third_key_id != first_key_id);

            auto const after = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("only the newest key is active and both superseded keys remain in old_verify_keys")
            {
                REQUIRE(after.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(after.body);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: exactly the current key is active in verify_keys.
                auto const* verify_keys = get_object(*root, "verify_keys");
                REQUIRE(verify_keys != nullptr);
                REQUIRE(verify_keys->size() == 1U);
                REQUIRE(verify_keys->front().key == third_key_id);

                // Spec: every superseded key is retained in old_verify_keys.
                auto const* old_keys = get_object(*root, "old_verify_keys");
                REQUIRE(old_keys != nullptr);
                REQUIRE(old_keys->size() == 2U);
                REQUIRE(json_get(*old_keys, first_key_id) != nullptr);
                REQUIRE(json_get(*old_keys, second_key_id) != nullptr);
            }
        }
    }
}
