// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         SERVER SIGNING KEY LIFECYCLE TESTS                              |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys |
// |                                                                         |
// |  A homeserver's Ed25519 signing key is its federation identity. It may  |
// |  only change through an explicit rotation. `valid_until_ts` says when   |
// |  peers should REFRESH the published key list - it is not a lifetime     |
// |  after which the server silently adopts a new identity.                 |
// |                                                                         |
// |  Every REQUIRE here encodes that invariant. Fix the implementation, do  |
// |  not weaken the assertions.                                             |
// +-------------------------------------------------------------------------+

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/runtime_multikey_ed25519_provider.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <string>

namespace
{

[[nodiscard]] auto signing_lifecycle_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto now_ms() -> std::uint64_t
{
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
}

// Simulates a server that has been running longer than the published key window:
// every stored key's valid_until_ts is moved into the past. Nothing else about the
// key material changes - the secret is still valid and still the server's identity.
auto lapse_all_signing_key_windows(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    auto const past = now_ms() - std::uint64_t{60U * 1000U};
    for (auto& key : runtime.database.persistent_store.server_signing_keys)
    {
        key.valid_until_ts = past;
    }
}

[[nodiscard]] auto json_string_field(std::string const& body, std::string const& field) -> std::string
{
    auto const key = "\"" + field + "\":\"";
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

// Spec: Matrix Server-Server API v1.19 - Publishing Keys
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys
//
// `valid_until_ts` is "when the list of valid keys should be refreshed". A key whose
// window has lapsed must be republished with a fresh window, NOT replaced: replacing it
// changes the server's federation identity without an old_verify_keys hand-over, and
// every peer that cached the previous key rejects the server's signatures.
SCENARIO("A lapsed publication window refreshes the existing signing key instead of replacing it",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a started runtime whose stored signing key window has lapsed")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
        auto const original_key_id = runtime.database.persistent_store.server_signing_keys.front().key_id;
        auto const original_public_key = runtime.database.persistent_store.server_signing_keys.front().public_key;
        lapse_all_signing_key_windows(runtime);

        WHEN("the signing key is ensured again")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the same key is returned with a future window and no second key is generated")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->key_id == original_key_id);
                REQUIRE(key->public_key == original_public_key);
                REQUIRE(key->valid_until_ts > now_ms());
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
                // The refreshed window is persisted, not just returned to the caller.
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().valid_until_ts ==
                        key->valid_until_ts);
            }
        }
    }
}

// Merovingian invariant (fail-closed signing):
// The key returned by ensure_runtime_server_signing_key is the key every locally
// composed event is signed with. If the runtime's signing provider does not hold that
// key, every send fails with "signing key not held" and the server cannot originate
// any event. The two MUST never diverge.
SCENARIO("The runtime signing provider always holds the key ensure_runtime_server_signing_key returns",
         "[homeserver][signing][security]")
{
    GIVEN("a started runtime whose stored signing key window has lapsed")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        lapse_all_signing_key_windows(runtime);

        WHEN("the signing key is ensured and used to sign a payload")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);
            REQUIRE(key.has_value());
            REQUIRE(runtime.crypto_provider != nullptr);
            auto const signed_payload =
                runtime.crypto_provider->sign(merovingian::crypto::Ed25519SecretKeyHandle{key->key_id}, "payload");

            THEN("the provider signs with that key id rather than reporting it is not held")
            {
                REQUIRE(signed_payload.error.empty());
                REQUIRE(signed_payload.signature.bytes.size() == 64U);
            }
        }
    }
}

// Merovingian invariant (client-visible):
// A server whose uptime exceeds the published key window must keep accepting locally
// composed events. This is the exact failure reported by mobile clients: every
// PUT /rooms/{roomId}/send/... returned 403 "event authorization or signing failed"
// because the preferred key had been silently replaced behind the signing provider.
SCENARIO("Sending a room event still succeeds after the published key window lapses",
         "[homeserver][signing][client-server][rooms]")
{
    GIVEN("a logged-in user in a room on a server whose key window has lapsed")
    {
        auto started = merovingian::homeserver::start_client_server(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                    .response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = json_string_field(login.response.body, "access_token");

        auto const created = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(created.response.status == 200U);
        auto const room = json_string_field(created.response.body, "room_id");

        lapse_all_signing_key_windows(runtime.homeserver);

        WHEN("the user sends a message")
        {
            auto const sent = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/txn-lapsed-1", token,
                          R"({"msgtype":"m.text","body":"hello"})"});

            THEN("the event is accepted and assigned an event id")
            {
                REQUIRE(sent.response.status == 200U);
                REQUIRE(json_string_field(sent.response.body, "event_id").starts_with("$"));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19 - Publishing Keys
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixkeyv2server
//
// The server MUST NOT advertise a `valid_until_ts` it does not itself honour. Peers
// cache the published document until that timestamp; if the server internally treats
// the key as dead sooner, its signatures are rejected for the remainder of the window.
SCENARIO("The published valid_until_ts matches the window the server stores for the key",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a started runtime serving the federation key endpoint")
    {
        auto started = merovingian::homeserver::start_client_server(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the key server document is published")
        {
            auto const published = merovingian::homeserver::publish_server_signing_keys(runtime.homeserver);
            REQUIRE(published.ok);
            auto const stored = merovingian::homeserver::find_active_server_signing_key(runtime.homeserver);

            THEN("the advertised valid_until_ts is the stored window and lies in the future")
            {
                REQUIRE(stored.has_value());
                REQUIRE(stored->valid_until_ts > now_ms());
                REQUIRE(published.value.find("\"valid_until_ts\":" + std::to_string(stored->valid_until_ts)) !=
                        std::string::npos);
            }
        }
    }
}

// Merovingian invariant (multi-key provider bookkeeping):
// runtime.database.signing_secret_keys is documented as "keyed by key_id" and is the
// record of which keys the provider was built from. Entries with an empty key_id make
// every lookup miss, which silently defeats any check that the provider still holds
// the preferred key.
SCENARIO("Loaded signing secrets are keyed by their real key ids", "[homeserver][signing]")
{
    GIVEN("a started runtime with one active signing key")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);
        REQUIRE(key.has_value());

        WHEN("the loaded secrets are inspected")
        {
            auto const& loaded = runtime.database.signing_secret_keys;

            THEN("the preferred key's secret is stored under its own key id")
            {
                REQUIRE(!loaded.empty());
                REQUIRE(loaded.front().first == key->key_id);
                REQUIRE(loaded.front().second.bytes().size() == 64U);
            }
        }
    }
}

// Merovingian invariant (federation worker isolation):
// The out-of-process federation worker signs through an IPC-backed provider so the
// signing secret never enters the child process. Rebuilding the runtime provider from
// local secrets there would silently replace that override with an empty provider.
SCENARIO("Rebuilding the signing provider is a no-op while an external override is active",
         "[homeserver][signing][security][federation]")
{
    GIVEN("a runtime started with an external signing provider override")
    {
        auto override_provider = merovingian::crypto::RuntimeMultiKeyEd25519Provider{{}};
        auto opts = merovingian::homeserver::RuntimeStartOptions{};
        opts.config = signing_lifecycle_config();
        opts.signing_override = &override_provider;
        auto started = merovingian::homeserver::start_runtime(opts);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.crypto_provider == &override_provider);

        WHEN("the runtime signing provider is rebuilt")
        {
            merovingian::homeserver::reset_runtime_crypto_provider(runtime);

            THEN("the override is still the active provider")
            {
                REQUIRE(runtime.crypto_provider == &override_provider);
            }
        }
    }
}

// Merovingian invariant (cache freshness):
// GET /_matrix/key/v2/server is served from a lock-free cache. A cached document is
// only servable while it is fresh; once its refresh deadline passes it must be
// re-published, otherwise long-running servers keep serving a document whose
// valid_until_ts has already gone into the past.
SCENARIO("The key server cache stops serving a document past its refresh deadline",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a cache holding a document with a refresh deadline")
    {
        auto cache = merovingian::homeserver::KeyServerCache{};
        cache.store("{\"published\":true}", 1'000U);

        WHEN("the cache is read before and after the deadline")
        {
            auto const fresh = cache.load(999U);
            auto const stale = cache.load(1'001U);

            THEN("only the fresh read returns the document")
            {
                REQUIRE(fresh.has_value());
                REQUIRE(*fresh == "{\"published\":true}");
                REQUIRE(!stale.has_value());
            }
        }
    }
}
