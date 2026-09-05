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

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/secret_buffer.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/crypto/master_key.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/crypto/secret_box.hpp"
#include "merovingian/crypto/runtime_multikey_ed25519_provider.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <span>
#include <vector>
#include <string>

namespace
{

[[nodiscard]] auto signing_lifecycle_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
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

// Spec: Matrix Server-Server API v1.19 - Publishing Keys
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#publishing-keys
//
// The window must be rolled forward BEFORE it lapses. A server that only
// refreshes once the window has already elapsed spends the gap advertising a
// valid_until_ts in the past, and peers reject its signatures for exactly as
// long as it takes something to touch the key again — the condition that
// produced the original outage. Refreshing once the key is past the halfway
// point of its validity keeps a live server's advertised window permanently in
// the future.
SCENARIO("A signing key past the halfway point of its window is refreshed "
         "before it lapses",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a started runtime whose key window is nearly elapsed but still in the "
          "future")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
        auto const original_key_id = runtime.database.persistent_store.server_signing_keys.front().key_id;
        // One hour left of a seven-day window: not lapsed, but well past halfway.
        auto const nearly_elapsed = now_ms() + std::uint64_t{60U * 60U * 1000U};
        runtime.database.persistent_store.server_signing_keys.front().valid_until_ts = nearly_elapsed;

        WHEN("the signing key is ensured")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the same key is kept and its window is extended well beyond the "
                 "old expiry")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->key_id == original_key_id);
                REQUIRE(key->valid_until_ts > nearly_elapsed);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().valid_until_ts ==
                        key->valid_until_ts);
            }
        }
    }
}

// The other half of the threshold: a key with most of its window still ahead
// must NOT be rewritten on every request. The refresh persists to the database,
// so an unconditional roll-forward would issue a write on every path that needs
// the signing identity.
SCENARIO("A signing key with most of its window remaining is left untouched",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a started runtime whose key was just published with a full window")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
        auto const original = runtime.database.persistent_store.server_signing_keys.front();
        REQUIRE(original.valid_until_ts > now_ms());

        WHEN("the signing key is ensured again")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the stored window is unchanged")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->key_id == original.key_id);
                REQUIRE(key->valid_until_ts == original.valid_until_ts);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().valid_until_ts ==
                        original.valid_until_ts);
            }
        }
    }
}

// Merovingian invariant (served document freshness):
// GET /_matrix/key/v2/server is answered from a lock-free cache. The cached
// document carries a valid_until_ts, so serving one indefinitely means
// eventually advertising a window that has already elapsed. Past its refresh
// deadline the fast path must fall through and re-publish rather than serve
// what it holds.
SCENARIO("The key server fast path re-publishes a cached document past its "
         "refresh deadline",
         "[homeserver][signing][federation][key_publishing]")
{
    GIVEN("a runtime whose cached key document is past its refresh deadline")
    {
        auto started = merovingian::homeserver::start_client_server(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(runtime.homeserver.database.key_server_cache != nullptr);

        auto const stale_document = std::string{R"({"stale":true})"};
        runtime.homeserver.database.key_server_cache->store(stale_document, now_ms() - std::uint64_t{1U});

        WHEN("the federation key endpoint is served")
        {
            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", "/_matrix/key/v2/server", {}, {}},
                merovingian::homeserver::HttpDispatchMode::federation);

            THEN("the stale document is not served and a freshly signed one is "
                 "published")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body != stale_document);
                REQUIRE(response.body.find("\"verify_keys\"") != std::string::npos);
                REQUIRE(response.body.find("\"signatures\"") != std::string::npos);
            }

            AND_THEN("the refreshed document is cached again for subsequent requests")
            {
                auto const cached = runtime.homeserver.database.key_server_cache->load(now_ms());
                REQUIRE(cached.has_value());
                REQUIRE(*cached != stale_document);
            }
        }
    }
}

// --- 0.12.5 security audit, findings 1 and 5 ---------------------------------
//
// Finding 1: with no master key configured the server persisted its Ed25519
// seed as base64 with encrypted='false', so anyone who exfiltrated the database
// held a forgery-capable federation signing key -- the whole threat the column
// exists to defend against. There is no longer a plaintext path, on first
// generation or on rotation, and a server that cannot encrypt refuses to start.
//
// Finding 5: rebuild_signing_provider() staged every active secret through a
// std::vector of plain std::array, leaving a second unlocked, never-zeroised
// copy of each seed in ordinary heap memory on every provider rebuild.

namespace
{

[[nodiscard]] auto config_without_master_key() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    // Deliberately no security.secrets.master_key_file: this is the state
    // finding 1 says must never produce a stored plaintext secret.
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

} // namespace

SCENARIO("A server with no master key refuses to start rather than store a plaintext signing secret",
         "[homeserver][signing][security]")
{
    GIVEN("a runtime configured with no master key file")
    {
        auto started = merovingian::homeserver::start_runtime(config_without_master_key());

        WHEN("the runtime is started")
        {
            THEN("startup is refused")
            {
                REQUIRE_FALSE(started.started);
            }

            THEN("the reason names the missing master key rather than a downstream symptom")
            {
                // The failure used to surface three steps later as an inability
                // to derive an unrelated pagination-token key, which told an
                // operator nothing about what to fix.
                REQUIRE(started.reason.find("signing key") != std::string::npos);
                REQUIRE(started.reason.find("master_key_file") != std::string::npos);
            }

            THEN("no signing-key row was written at all, let alone a plaintext one")
            {
                auto const& keys = started.runtime.database.persistent_store.server_signing_keys;
                REQUIRE(keys.empty());
            }
        }
    }
}

SCENARIO("A generated signing secret is always stored encrypted at rest", "[homeserver][signing][security]")
{
    GIVEN("a runtime with a master key configured")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);

        WHEN("the server's own signing key is inspected in the store")
        {
            auto const& keys = started.runtime.database.persistent_store.server_signing_keys;
            auto const own = std::ranges::find_if(keys, [](auto const& key) {
                return !key.secret_key.empty();
            });

            THEN("its stored secret carries the secret-box envelope, never raw base64")
            {
                REQUIRE(own != keys.end());
                REQUIRE(own->secret_key.starts_with(merovingian::crypto::secret_box_storage_prefix));
            }

            THEN("the raw seed does not appear anywhere in the stored value")
            {
                // A regression that wrote the seed alongside the envelope would
                // still match the prefix check above; this catches it.
                auto const& secret = started.runtime.database.signing_secret_key;
                REQUIRE(secret.bytes().size() == merovingian::crypto::ed25519_secret_key_bytes);
                auto const raw = std::string{reinterpret_cast<char const*>(secret.bytes().data()),
                                             secret.bytes().size()};
                REQUIRE(own->secret_key.find(raw) == std::string::npos);
            }
        }
    }
}

// Exactly the shape of a pre-0.12.5 server being upgraded: a legacy plaintext
// signing key in the store, and no master key configured. That combination is
// what reaches the *rotation* encrypt path. An encrypted key could not be loaded
// without the master key at all, so rotation would refuse one step earlier and
// never exercise the fallback this half of the finding is about -- which is why
// the row is rewritten into legacy form here rather than the master key simply
// being taken away.
SCENARIO("Rotating a legacy plaintext signing key refuses rather than minting another one",
         "[homeserver][signing][security]")
{
    GIVEN("a server holding a legacy plaintext signing key with no master key configured")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Rewrite the active row into the pre-encryption storage format, using
        // the raw seed the running server already holds in memory.
        auto& keys = runtime.database.persistent_store.server_signing_keys;
        auto const active = std::ranges::find_if(keys, [](auto const& key) {
            return !key.secret_key.empty();
        });
        REQUIRE(active != keys.end());
        auto const& raw = runtime.database.signing_secret_key;
        REQUIRE(raw.bytes().size() == merovingian::crypto::ed25519_secret_key_bytes);
        active->secret_key = merovingian::events::matrix_base64_from_bytes(
            std::string_view{reinterpret_cast<char const*>(raw.bytes().data()), raw.bytes().size()});
        REQUIRE_FALSE(active->secret_key.starts_with(merovingian::crypto::secret_box_storage_prefix));

        // Now take the master key away, as an un-migrated deployment has it.
        runtime.config = config_without_master_key();
        auto const keys_before = keys.size();

        WHEN("a rotation is requested")
        {
            // Rotation is precisely what an operator runs after a suspected
            // leak -- the worst possible moment to mint another plaintext key.
            auto const result = merovingian::homeserver::rotate_server_signing_key(runtime);

            THEN("the rotation fails, naming the missing master key")
            {
                // Asserted on the reason, not just on ok: a rotation that failed
                // for some unrelated cause would otherwise satisfy this scenario
                // without the finding being fixed at all.
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason.find("master_key_file") != std::string::npos);
                REQUIRE(result.reason.find("plaintext") != std::string::npos);
            }

            THEN("no new signing-key row was written")
            {
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == keys_before);
            }
        }
    }
}

SCENARIO("Every holder of an active signing secret keeps it in locked memory",
         "[homeserver][signing][security]")
{
    GIVEN("a started runtime with an active signing key")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the crypto provider is rebuilt from the active secrets")
        {
            merovingian::homeserver::reset_runtime_crypto_provider(runtime);

            THEN("the preferred single secret is held in a locked buffer")
            {
                // Finding 5: the rebuild used to copy each seed into a plain
                // std::array first. Asserting that every surviving holder is a
                // locked SecretBuffer is the observable half of "no copy remains
                // in unprotected memory".
                REQUIRE(runtime.database.signing_secret_key.bytes().size() ==
                        merovingian::crypto::ed25519_secret_key_bytes);
                REQUIRE(runtime.database.signing_secret_key.is_locked());
            }

            THEN("every per-key secret is held in a locked buffer with a non-empty key id")
            {
                REQUIRE_FALSE(runtime.database.signing_secret_keys.empty());
                for (auto const& entry : runtime.database.signing_secret_keys)
                {
                    REQUIRE_FALSE(entry.first.empty());
                    REQUIRE(entry.second.bytes().size() == merovingian::crypto::ed25519_secret_key_bytes);
                    REQUIRE(entry.second.is_locked());
                }
            }

            THEN("the rebuilt provider can still sign, so the rebuild did not lose the key")
            {
                REQUIRE(runtime.crypto_provider != nullptr);
                auto const key_id = runtime.database.signing_secret_keys.front().first;
                auto const signed_result =
                    runtime.crypto_provider->sign(merovingian::crypto::Ed25519SecretKeyHandle{key_id}, "payload");
                REQUIRE(signed_result.error.empty());
                REQUIRE_FALSE(signed_result.signature.bytes.empty());
            }
        }
    }
}

// --- 0.12.5 audit: the fail-closed branches on the stored-secret path ---------
//
// Every one of these refuses to produce a signing identity rather than
// proceeding with material it cannot vouch for. They are the branches that
// decide whether a server signs with a key it has actually authenticated, so
// each is pinned separately: a regression that silently downgraded any of them
// would otherwise show up only as forged-signature acceptance in the field.

namespace
{

// Build the at-rest form of a secret exactly as room_service stores it:
// "secretbox:v1:" + base64(nonce || mac || ciphertext), sealed under the
// secret-box key derived from `master_key_path`.
[[nodiscard]] auto sealed_secret_under(std::string const& master_key_path, std::span<std::uint8_t const> plaintext)
    -> std::string
{
    auto const key = merovingian::crypto::signing_secret_box_key(master_key_path);
    REQUIRE(key.has_value());
    auto const sealed = merovingian::crypto::secret_box_encrypt(plaintext, *key);
    REQUIRE(sealed.has_value());
    return std::string{merovingian::crypto::secret_box_storage_prefix} +
           merovingian::events::matrix_base64_from_bytes(
               std::string_view{reinterpret_cast<char const*>(sealed->bytes.data()), sealed->bytes.size()});
}

// Replace the server's stored signing secret, leaving the rest of the row as
// the running server wrote it.
auto overwrite_stored_secret(merovingian::homeserver::HomeserverRuntime& runtime, std::string secret) -> void
{
    auto& keys = runtime.database.persistent_store.server_signing_keys;
    auto const own = std::ranges::find_if(keys, [](auto const& key) {
        return !key.secret_key.empty();
    });
    REQUIRE(own != keys.end());
    own->secret_key = std::move(secret);
}

} // namespace

SCENARIO("An encrypted signing secret is refused when no master key is configured",
         "[homeserver][signing][security]")
{
    GIVEN("a server whose stored secret is encrypted, started without a master key")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // The row is already `secretbox:v1:` from startup; only the config changes.
        runtime.config = config_without_master_key();

        WHEN("the runtime tries to load its signing key")
        {
            auto const loaded = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("it refuses rather than treating the ciphertext as key material")
            {
                // Reading the envelope as raw bytes would produce a
                // wrong-length "secret" and, worse, a signing identity nobody
                // can verify. Refusing is the only safe answer.
                REQUIRE_FALSE(loaded.has_value());
            }
        }
    }
}

SCENARIO("A signing secret sealed under a different master key is refused",
         "[homeserver][signing][security]")
{
    GIVEN("a stored secret sealed under one master key and a server holding another")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const other_master_key = merovingian::tests::master_key_file();
        auto const seed = std::vector<std::uint8_t>(merovingian::crypto::ed25519_secret_key_bytes, 0x5aU);
        overwrite_stored_secret(runtime, sealed_secret_under(other_master_key, seed));

        WHEN("the runtime tries to load its signing key")
        {
            auto const loaded = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the authentication tag failure is fatal, not ignored")
            {
                // secret_box is authenticated: a tag mismatch means the row was
                // written under a different key or has been tampered with.
                // Either way it must not yield a signing identity.
                REQUIRE_FALSE(loaded.has_value());
            }
        }
    }
}

SCENARIO("A stored secret that decrypts to the wrong length is refused", "[homeserver][signing][security]")
{
    GIVEN("a correctly sealed secret whose plaintext is not an Ed25519 secret key")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Sealed under the *right* master key, so it decrypts cleanly -- the
        // only thing wrong with it is its length.
        auto const truncated = std::vector<std::uint8_t>(16U, 0x11U);
        overwrite_stored_secret(runtime,
                                sealed_secret_under(runtime.config.security().secrets.master_key_file, truncated));

        WHEN("the runtime tries to load its signing key")
        {
            auto const loaded = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("it is refused rather than used to produce corrupt signatures")
            {
                // Signing with wrong-length material does not fail loudly; it
                // produces signatures no peer can verify, which surfaces as
                // unexplained federation rejection rather than as an error here.
                REQUIRE_FALSE(loaded.has_value());
            }
        }

        WHEN("the active signing secrets are collected for the crypto provider")
        {
            auto const secrets = merovingian::homeserver::active_server_signing_key_secrets(runtime);

            THEN("the wrong-length row is skipped rather than handed to the provider")
            {
                REQUIRE(secrets.empty());
            }
        }
    }
}

SCENARIO("A legacy row holding undecodable base64 yields no signing secret", "[homeserver][signing][security]")
{
    GIVEN("a legacy plaintext row whose contents are not valid base64")
    {
        auto started = merovingian::homeserver::start_runtime(signing_lifecycle_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // No secretbox prefix, so this takes the legacy decode path.
        overwrite_stored_secret(runtime, "!!!not-base64!!!");

        WHEN("the runtime tries to load its signing key")
        {
            auto const loaded = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("it is refused rather than yielding an empty or partial key")
            {
                REQUIRE_FALSE(loaded.has_value());
            }
        }
    }
}
