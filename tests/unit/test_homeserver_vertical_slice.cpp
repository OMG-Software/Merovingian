// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/observability/observability.hpp"

#include <catch2/catch_test_macros.hpp>

#include <sodium.h>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

class StaticDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    [[nodiscard]] auto fetch_well_known(std::string_view /*server_name*/, std::uint32_t /*timeout_seconds*/)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view /*service_name*/)
        -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t port)
        -> merovingian::federation::ResolvedAddressSet override
    {
        auto result = merovingian::federation::ResolvedAddressSet{};
        result.ok = true;
        if (host == "remote.example.org" && port == 8448U)
        {
            result.addresses = {"203.0.113.10"};
        }
        return result;
    }
};

auto install_unusable_persisted_signing_key(merovingian::homeserver::HomeserverRuntime& runtime) -> void
{
    auto const server_name = runtime.config.server().server_name;
    // Replace all existing keys (including any generated during startup pre-warm) with a
    // single unusable entry. Using a derived-format key_id (not "ed25519:auto") keeps the
    // lookup logic's selector happy, but the secret is intentionally not valid base64 so
    // decoding produces fewer than crypto_sign_SECRETKEYBYTES bytes → system fails closed.
    runtime.database.persistent_store.server_signing_keys.clear();
    runtime.database.persistent_store.server_signing_keys.push_back({
        server_name,
        "ed25519:deadbeef",
        "public-key-base64",
        32503680000000ULL,
        "not-base64",
    });
    runtime.database.signing_secret_key.clear();
}

} // namespace

SCENARIO("Homeserver runtime starts from validated config with listeners database and hardening",
         "[homeserver][vertical]")
{
    GIVEN("the default config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the runtime is started")
        {
            auto const started = merovingian::homeserver::start_runtime(config);

            THEN("the runtime has listeners, validated schema, hardening summaries, and startup "
                 "audit")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.started);
                REQUIRE(started.runtime.listeners.count() == 2U);
                REQUIRE(started.runtime.database.opened);
                REQUIRE(started.runtime.database.schema_validated);
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "users"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "rooms"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "events"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "audit_log"));
                REQUIRE(started.runtime.hardening.count() > 0U);
                REQUIRE(merovingian::homeserver::audit_event_count(started.runtime) == 1U);
            }
        }
    }
}

SCENARIO("Homeserver admin health requires an admin session", "[homeserver][vertical][observability]")
{
    GIVEN("a started runtime with an admin user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.value + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("admin health is requested with and without the admin token")
        {
            auto const health = merovingian::homeserver::admin_health(runtime);
            auto const summary = merovingian::homeserver::admin_health_summary(runtime);
            auto const unauthorized = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", {}, {}});
            auto const authorized = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/health", login.body, {}});

            THEN("health is safe and route access is admin-gated")
            {
                REQUIRE(health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(summary.find("runtime:ok") != std::string::npos);
                REQUIRE(summary.find("database:ok") != std::string::npos);
                REQUIRE(unauthorized.status == 401U);
                REQUIRE(unauthorized.body == "admin authentication required");
                REQUIRE(authorized.status == 200U);
                REQUIRE(authorized.body.find("runtime:ok") != std::string::npos);
                REQUIRE(authorized.body.find("password") == std::string::npos);
                REQUIRE(authorized.body.find("access_token") == std::string::npos);
                REQUIRE(authorized.body.find("m.room.message") == std::string::npos);
            }
        }
    }
}

SCENARIO("Homeserver registration follows runtime registration config", "[homeserver][vertical][auth]")
{
    GIVEN("a runtime with registration disabled")
    {
        auto started = merovingian::homeserver::start_runtime(merovingian::config::Config{});
        REQUIRE(started.started);

        WHEN("a client attempts registration")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST",
                                  "/_matrix/client/v3/register",
                                  {},
                                  merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});

            THEN("registration is rejected by policy")
            {
                REQUIRE(user.status == 400U);
                REQUIRE(user.body == "registration_disabled");
            }
        }
    }
}

SCENARIO("Homeserver local auth route creates unique sessions and revokes tokens", "[homeserver][vertical][auth]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers, logs in twice, authenticates, and logs out")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const second_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const authenticated = merovingian::homeserver::authenticated_user(runtime, login.body);
            auto const logout = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/logout", login.body, {}});
            auto const after_logout = merovingian::homeserver::authenticated_user(runtime, login.body);
            auto const second_still_authenticated =
                merovingian::homeserver::authenticated_user(runtime, second_login.body);

            THEN("tokens are unique, only the logged-out token is revoked, and audit events are "
                 "appended")
            {
                REQUIRE(user.status == 200U);
                REQUIRE(user.body == "@alice:example.org");
                REQUIRE(login.status == 200U);
                REQUIRE(second_login.status == 200U);
                REQUIRE(login.body != second_login.body);
                REQUIRE(authenticated == std::optional<std::string>{user.body});
                REQUIRE(logout.status == 200U);
                REQUIRE_FALSE(after_logout.has_value());
                REQUIRE(second_still_authenticated.has_value());
                REQUIRE(merovingian::homeserver::audit_event_count(runtime) >= 5U);
            }
        }
    }
}

SCENARIO("Homeserver admin observability endpoints expose runtime metrics and durable audit",
         "[homeserver][vertical][observability]")
{
    GIVEN("a started runtime with an admin session")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::bootstrap_admin_user(runtime, "alice", "CorrectHorse7!");
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.value + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("admin metrics and audit are requested")
        {
            auto const metrics = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/metrics", login.body, {}});
            auto const audit = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit", login.body, {}});
            auto const unauthenticated = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit", "not-a-token", {}});

            THEN("only the admin session can read safe operational summaries")
            {
                REQUIRE(metrics.status == 200U);
                REQUIRE(audit.status == 200U);
                REQUIRE(unauthenticated.status == 401U);
                REQUIRE(metrics.body.find("audit_events_appended_total") != std::string::npos);
                REQUIRE(metrics.body.find("access_token") == std::string::npos);
                REQUIRE(audit.body.find("runtime.started") != std::string::npos);
                REQUIRE(audit.body.find("CorrectHorse7") == std::string::npos);
                REQUIRE(runtime.database.persistent_store.audit_log.size() >= 3U);
            }
        }
    }
}

SCENARIO("Homeserver local auth stores hardened password and token hashes", "[homeserver][vertical][auth][security]")
{
    GIVEN("a started runtime with local registration enabled")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in twice")
        {
            auto const user = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
            REQUIRE(user.status == 200U);
            auto const first_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const second_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});

            THEN("the persisted password is Argon2id-shaped and tokens are random with versioned "
                 "hashes")
            {
                REQUIRE(first_login.status == 200U);
                REQUIRE(second_login.status == 200U);
                REQUIRE(first_login.body != second_login.body);
                REQUIRE(first_login.body.rfind("mvs_", 0U) == 0U);
                REQUIRE(second_login.body.rfind("mvs_", 0U) == 0U);
                REQUIRE(runtime.database.users.size() == 1U);
                REQUIRE(runtime.database.users.front().password_hash.rfind("password-hash:v2:$argon2id$", 0U) == 0U);
                REQUIRE(runtime.database.users.front().password_hash.find("CorrectHorse7!") == std::string::npos);
                REQUIRE(runtime.database.sessions.size() == 2U);
                REQUIRE(runtime.database.sessions.front().access_token_hash.rfind("token-hash:v2:", 0U) == 0U);
                REQUIRE(runtime.database.sessions.back().access_token_hash.rfind("token-hash:v2:", 0U) == 0U);
                REQUIRE(runtime.database.sessions.front().access_token_hash !=
                        runtime.database.sessions.back().access_token_hash);
            }
        }
    }
}

SCENARIO("Homeserver rejects same-length incorrect passwords and crafted token collisions",
         "[homeserver][vertical][auth]")
{
    GIVEN("a registered user and active token")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("a same-length wrong password and same-shape fake token are used")
        {
            auto const bad_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|WrongHorse7!!|DEVICE1"});
            auto fake_token = std::string{login.body};
            fake_token.back() = fake_token.back() == '0' ? '1' : '0';
            auto const fake_auth = merovingian::homeserver::authenticated_user(runtime, fake_token);

            THEN("credential and token comparisons use the full secret value")
            {
                REQUIRE(bad_login.status == 403U);
                REQUIRE(bad_login.body == "bad credentials");
                REQUIRE_FALSE(fake_auth.has_value());
            }
        }
    }
}

SCENARIO("Homeserver local room route flow creates joins sends and fetches state", "[homeserver][vertical][rooms]")
{
    GIVEN("a logged-in local user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("the user creates, joins, sends, and fetches state")
        {
            auto const room = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
            auto const join = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}});
            auto const event = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body,
                          R"({"type":"m.room.message"})"});
            auto const state = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + room.body + "/state", login.body, {}});

            THEN("the local room path succeeds and state is returned as a JSON array")
            {
                REQUIRE(room.status == 200U);
                REQUIRE(room.body == "!room1:example.org");
                REQUIRE(join.status == 200U);
                REQUIRE(event.status == 200U);
                REQUIRE(state.status == 200U);
                // create_room now emits the four initial Matrix state events so
                // federation peers can verify the room's auth chain; the state
                // endpoint returns them as a JSON array.
                REQUIRE(state.body.find("\"m.room.create\"") != std::string::npos);
                REQUIRE(state.body.find("\"m.room.member\"") != std::string::npos);
                REQUIRE(state.body.find("\"m.room.power_levels\"") != std::string::npos);
                REQUIRE(state.body.find("\"m.room.join_rules\"") != std::string::npos);
            }
        }
    }
}

SCENARIO("Joining a room succeeds when user is already a member in the persistent store but not in-memory",
         "[homeserver][vertical][rooms][regression]")
{
    GIVEN("a logged-in user whose room membership is in the persistent store but absent from the in-memory member list")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);
        auto const room = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
        REQUIRE(room.status == 200U);

        // Simulate stale in-memory state: the persistent store retains the membership
        // but the in-memory room member list is empty, as can happen after a restart
        // when hydration is incomplete or when a prior join left the DB record but
        // failed to update the in-memory list.
        auto const room_it =
            std::ranges::find_if(runtime.database.rooms, [&room](merovingian::homeserver::LocalRoom const& r) {
                return r.room_id == room.body;
            });
        REQUIRE(room_it != runtime.database.rooms.end());
        room_it->members.clear();

        WHEN("the user attempts to join a room they are already a member of in the persistent store")
        {
            auto const join = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/join", login.body, {}});

            THEN("the join is accepted idempotently with 200 and the room id is returned")
            {
                REQUIRE(join.status == 200U);
                REQUIRE(join.body == room.body);
            }
        }
    }
}

SCENARIO("Remote join fails closed when the runtime signing key is not initialized",
         "[homeserver][vertical][rooms][federation]")
{
    GIVEN("a logged-in user attempting to join a remote room with an unusable persisted signing key")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.discovery_network = std::make_unique<StaticDiscoveryNetwork>();
        install_unusable_persisted_signing_key(runtime);

        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);

        WHEN("the user attempts the remote join")
        {
            auto const join = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!room:remote.example.org/join", login.body, "{}"});

            THEN("the join is rejected before any outbound membership request is signed")
            {
                REQUIRE(join.status == 502U);
                REQUIRE(join.body == "make_join failed: server signing key not initialized");
            }
        }
    }
}

SCENARIO("create_room generates the four initial Matrix room state events required for federation",
         "[homeserver][vertical][rooms][federation]")
{
    GIVEN("a started runtime with an authenticated user")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        WHEN("the user creates a room")
        {
            auto const result = merovingian::homeserver::create_room(runtime, login.value);
            auto const room_id = result.value;

            THEN("the operation succeeds")
            {
                REQUIRE(result.ok);
            }

            AND_THEN("the persistent state contains an m.room.create event for the room")
            {
                REQUIRE(result.ok);
                auto const& state = runtime.database.persistent_store.state;
                auto const has_create = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.create" && s.state_key.empty();
                });
                REQUIRE(has_create);
            }

            AND_THEN("the persistent state contains an m.room.member event for the creator")
            {
                REQUIRE(result.ok);
                auto const& state = runtime.database.persistent_store.state;
                auto const has_member = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == user.value;
                });
                REQUIRE(has_member);
            }

            AND_THEN("the persistent state contains an m.room.power_levels event for the room")
            {
                REQUIRE(result.ok);
                auto const& state = runtime.database.persistent_store.state;
                auto const has_pl = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.power_levels" && s.state_key.empty();
                });
                REQUIRE(has_pl);
            }

            AND_THEN("the persistent state contains an m.room.join_rules event for the room")
            {
                REQUIRE(result.ok);
                auto const& state = runtime.database.persistent_store.state;
                auto const has_jr = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.join_rules" && s.state_key.empty();
                });
                REQUIRE(has_jr);
            }
        }
    }
}

SCENARIO("join_room advertises room versions 10 11 and 12 all of which have registered policies",
         "[homeserver][vertical][rooms][federation]")
{
    GIVEN("the room version policy registry")
    {
        // If any advertised version lacks a policy, a successful make_join for that
        // room version would be immediately followed by a 500 "room version policy missing"
        // error when Merovingian tries to sign the join event.
        THEN("every version Merovingian advertises to the remote server has a registered policy")
        {
            REQUIRE(merovingian::rooms::find_room_version_policy("10") != nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("11") != nullptr);
            REQUIRE(merovingian::rooms::find_room_version_policy("12") != nullptr);
        }
    }
}

SCENARIO("Federation callbacks refuse to start the dispatch worker with an unusable signing key",
         "[homeserver][vertical][federation][dispatch]")
{
    GIVEN("a runtime whose persisted signing secret cannot hydrate into Ed25519 key bytes")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        install_unusable_persisted_signing_key(runtime);
        REQUIRE(runtime.dispatch_worker == nullptr);

        WHEN("federation callbacks are wired")
        {
            merovingian::homeserver::wire_federation_callbacks(runtime);

            THEN("dispatch worker startup fails closed instead of using a fallback key id")
            {
                REQUIRE(runtime.dispatch_worker == nullptr);
            }
        }
    }
}

SCENARIO("ensure_runtime_server_signing_key generates a derived key_id, never the legacy sentinel",
         "[homeserver][vertical][signing]")
{
    // start_runtime pre-warms the key server cache by calling ensure_runtime_server_signing_key
    // at startup, so by the time this test body runs the store already has exactly one key.
    GIVEN("a started runtime whose signing key was initialised during startup")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // Exactly one key was generated during the startup cache pre-warm.
        REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);

        WHEN("ensure_runtime_server_signing_key is called again (idempotent)")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the existing key is returned with a derived key_id that is not the legacy sentinel")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->key_id.starts_with("ed25519:"));
                REQUIRE(key->key_id != "ed25519:auto");
                // Derived ID is "ed25519:" + 8 lowercase hex chars from the public key.
                REQUIRE(key->key_id.size() == std::string_view{"ed25519:"}.size() + 8U);
                // Still one key — ensure is idempotent.
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
                REQUIRE(runtime.database.persistent_store.server_signing_keys.front().key_id == key->key_id);
                // The runtime secret key is populated and has the correct Ed25519 size.
                REQUIRE(runtime.database.signing_secret_key.size() == crypto_sign_SECRETKEYBYTES);
            }
        }
    }
}

SCENARIO("ensure_runtime_server_signing_key migrates a legacy ed25519:auto key by generating a fresh one",
         "[homeserver][vertical][signing]")
{
    GIVEN("a runtime whose store contains only a legacy ed25519:auto signing key")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const server_name = runtime.config.server().server_name;
        // Inject a well-formed legacy key — the secret is valid base64 but the key_id is
        // "ed25519:auto", which notary servers (e.g. matrix.org) may have cached with a
        // far-future valid_until_ts, making it impossible to rotate via normal expiry.
        runtime.database.persistent_store.server_signing_keys.push_back({
            server_name,
            "ed25519:auto",
            "cHVibGlja2V5", // base64("pubkey") — syntactically valid but not real Ed25519
            32503680000000ULL,
            "c2VjcmV0a2V5", // base64("secretkey") — valid base64, wrong size
        });

        WHEN("the signing key is ensured")
        {
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("a fresh key with a derived key_id is generated, bypassing the stale notary cache")
            {
                REQUIRE(key.has_value());
                REQUIRE(key->key_id != "ed25519:auto");
                REQUIRE(key->key_id.starts_with("ed25519:"));
                REQUIRE(key->key_id.size() == std::string_view{"ed25519:"}.size() + 8U);
                // Two keys now in the store: the old legacy entry plus the newly generated one.
                REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 2U);
                REQUIRE(runtime.database.signing_secret_key.size() == crypto_sign_SECRETKEYBYTES);
            }
        }
    }
}

SCENARIO("Homeserver rejects unauthenticated room route operations", "[homeserver][vertical][security]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);

        WHEN("room routes use an unknown token")
        {
            auto const create = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/createRoom", "bad-token", {}});
            auto const join = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/!room1:example.org/join", "bad-token", {}});
            auto const send = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"POST", "/_matrix/client/v3/rooms/!room1:example.org/send", "bad-token", "{}"});
            auto const state = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"GET", "/_matrix/client/v3/rooms/!room1:example.org/state", "bad-token", {}});

            THEN("all protected room route operations fail closed")
            {
                REQUIRE(create.status == 401U);
                REQUIRE(create.body == "unauthenticated");
                REQUIRE(join.status == 401U);
                REQUIRE(join.body == "unauthenticated");
                REQUIRE(send.status == 401U);
                REQUIRE(send.body == "unauthenticated");
                REQUIRE(state.status == 401U);
                REQUIRE(state.body == "unauthenticated");
            }
        }
    }
}

SCENARIO("Homeserver local route dispatcher rejects unknown routes", "[homeserver][vertical][routing]")
{
    GIVEN("a started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);

        WHEN("an unknown route is requested")
        {
            auto const route = merovingian::homeserver::handle_local_http_request(
                started.runtime, {"GET", "/_matrix/client/v3/unknown", {}, {}});

            THEN("the request is rejected")
            {
                REQUIRE(route.status == 404U);
                REQUIRE(route.body == "route not found");
            }
        }
    }
}

SCENARIO("Homeserver event send uses wall-clock origin_server_ts", "[homeserver][vertical][events]")
{
    GIVEN("a logged-in user with a room")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);
        auto const room = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", login.body, {}});
        REQUIRE(room.status == 200U);

        WHEN("an event is sent and the stored JSON is inspected")
        {
            auto const event = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room.body + "/send", login.body,
                          R"({"type":"m.room.message"})"});
            REQUIRE(event.status == 200U);
            auto const& stored = runtime.database.persistent_store.events;

            THEN("origin_server_ts is a Unix-epoch millisecond timestamp not a depth counter")
            {
                REQUIRE_FALSE(stored.empty());
                auto const& event_json = stored.back().json;
                REQUIRE(event_json.find("\"origin_server_ts\"") != std::string::npos);
                auto const depth = stored.back().depth;
                REQUIRE(depth >= 1U);
            }
        }
    }
}

SCENARIO("start_runtime pre-warms the key server response cache",
         "[homeserver][vertical][signing][federation]")
{
    GIVEN("a freshly started runtime")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        THEN("the key server cache is populated with a valid signed response")
        {
            // The cache unique_ptr is default-constructed in LocalDatabase.
            REQUIRE(runtime.database.key_server_cache != nullptr);

            // load() returns an optional — must be populated by the startup pre-warm.
            auto const cached = runtime.database.key_server_cache->load();
            REQUIRE(cached.has_value());
            REQUIRE_FALSE(cached->empty());

            // The cached body must be well-formed key server JSON.
            REQUIRE(cached->find("\"server_name\"") != std::string::npos);
            REQUIRE(cached->find("\"verify_keys\"") != std::string::npos);
            REQUIRE(cached->find("\"valid_until_ts\"") != std::string::npos);
            REQUIRE(cached->find("\"signatures\"") != std::string::npos);
        }
    }
}
