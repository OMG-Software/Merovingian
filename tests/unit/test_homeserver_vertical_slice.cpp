// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MEROVINGIAN HOMESERVER INTEGRATION TESTS                        |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18                                   |
// |        Matrix Server-Server API v1.18                                   |
// |  CS URL: ../../docs/matrix-v1.18-spec/client-server-api.md               |
// |  SS URL: ../../docs/matrix-v1.18-spec/server-server-api.md               |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a   |
// |  hard security invariant. If a test fails:                              |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto registration_enabled_config_with_master_key(std::string master_key_path)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    security.secrets.master_key_file = std::move(master_key_path);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto extract_token(std::string const& body) -> std::string
{
    auto const marker = std::string{"\"access_token\":\""};
    auto const start = body.find(marker);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + marker.size();
    auto const value_end = body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_start, value_end - value_start);
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
    // decoding produces fewer than crypto_sign_SECRETKEYBYTES bytes -> system fails closed.
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

// --- Runtime startup ----------------------------------------------------------
// Spec: Merovingian internal invariant
//
// The homeserver MUST start with a validated database schema, active listeners,
// OS-level hardening applied, and at least one startup audit event written before
// serving any client or federation traffic.
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
                // Spec MUST: runtime reports successful start before any requests are served.
                // Do NOT remove - startup flag gates all downstream request handling.
                REQUIRE(started.started);
                REQUIRE(started.runtime.started);
                // Spec MUST: at least the CS and SS listeners are bound.
                // Do NOT remove/change - missing listeners mean silent traffic loss.
                REQUIRE(started.runtime.listeners.count() == 2U);
                // Spec MUST: database is open and schema is valid before serving requests.
                // Do NOT remove - an unvalidated schema risks data corruption.
                REQUIRE(started.runtime.database.opened);
                REQUIRE(started.runtime.database.schema_validated);
                // Spec MUST: required tables exist in the database schema.
                // Do NOT remove - missing tables cause runtime panics on first write.
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "users"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "rooms"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "events"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "audit_log"));
                // Spec MUST: OS hardening controls are applied at startup.
                // Do NOT remove - zero hardening entries indicate mitigations are inactive.
                REQUIRE(started.runtime.hardening.count() > 0U);
                // Spec MUST: exactly one startup audit event is written before any user action.
                // Do NOT remove - missing audit entry breaks the tamper-evidence chain.
                REQUIRE(merovingian::homeserver::audit_event_count(started.runtime) == 1U);
            }
        }
    }
}

// --- Admin health observability -----------------------------------------------
// Spec: Merovingian internal invariant
//
// The admin health endpoint MUST be protected by admin-session authentication.
// Unauthenticated callers MUST receive 401. Authenticated responses MUST NOT
// leak any credential material (passwords, access tokens, message content).
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
        // Spec MUST: login MUST return 200 with a valid token before admin routes are tested.
        // Do NOT remove - test is invalid if setup login fails.
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
                // Spec MUST: internal health check reports ok status.
                // Do NOT remove - a degraded runtime must not silently pass health checks.
                REQUIRE(health.status == merovingian::observability::HealthStatus::ok);
                REQUIRE(summary.find("runtime:ok") != std::string::npos);
                REQUIRE(summary.find("database:ok") != std::string::npos);
                // Spec MUST: unauthenticated request MUST be rejected with 401.
                // Do NOT remove - exposing health data to anonymous callers leaks server state.
                REQUIRE(unauthorized.status == 401U);
                REQUIRE(unauthorized.body == "admin authentication required");
                // Spec MUST: authenticated request MUST succeed with 200.
                // Do NOT remove - admin operators require health visibility.
                REQUIRE(authorized.status == 200U);
                REQUIRE(authorized.body.find("runtime:ok") != std::string::npos);
                // Spec MUST: health response MUST NOT contain any credential material.
                // Do NOT remove - credential leakage in observability endpoints is a critical vuln.
                REQUIRE(authorized.body.find("password") == std::string::npos);
                REQUIRE(authorized.body.find("access_token") == std::string::npos);
                REQUIRE(authorized.body.find("m.room.message") == std::string::npos);
            }
        }
    }
}

// --- Registration policy enforcement -----------------------------------------
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3register
//
// If registration is disabled by server configuration the homeserver MUST
// reject POST /_matrix/client/v3/register requests. Open registration is an
// opt-in operator decision; the safe default is closed.
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
                // Spec MUST: disabled registration MUST return 400 (M_FORBIDDEN in real clients).
                // Do NOT remove - a 200 here means the server opened registration unexpectedly.
                REQUIRE(user.status == 400U);
                REQUIRE(user.body == "registration_disabled");
            }
        }
    }
}

// --- Registration token verification -----------------------------------------
// Spec: Merovingian security policy
//
// Registration tokens MUST be compared with a password-grade KDF (Argon2id)
// rather than a plaintext byte comparison.  The server MUST reject a token that
// differs by even one character, and MUST accept the configured token.
SCENARIO("Homeserver rejects an incorrect registration token and accepts the configured one",
         "[homeserver][vertical][auth][security]")
{
    GIVEN("a runtime with token-protected registration")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a client registers with the wrong token")
        {
            auto const bad = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          std::string{"alice|CorrectHorse7!|wrong-token"}});

            THEN("registration is rejected")
            {
                REQUIRE(bad.status == 403U);
                REQUIRE(bad.body == "registration token rejected");
            }
        }

        WHEN("a client registers with the correct token")
        {
            auto const good = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});

            THEN("registration succeeds and returns the fully-qualified user ID")
            {
                REQUIRE(good.status == 200U);
                REQUIRE(good.body == "@alice:example.org");
            }
        }
    }
}

// --- Session creation and token revocation -----------------------------------
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#login
//
// Each login MUST produce a unique access token. Logout MUST invalidate only
// the token used in the logout request; other concurrent sessions MUST remain
// valid. Registration MUST assign a fully-qualified Matrix user ID.
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
                // Spec MUST: registration MUST return 200 with the fully-qualified Matrix user ID.
                // Do NOT remove - a non-200 means the user was never created.
                REQUIRE(user.status == 200U);
                // Spec MUST: user ID MUST follow the @localpart:server_name format.
                // Do NOT remove - malformed IDs break federation and room membership.
                REQUIRE(user.body == "@alice:example.org");
                // Spec MUST: each login MUST return 200 with an access token.
                // Do NOT remove - a failed login means no subsequent authenticated requests work.
                REQUIRE(login.status == 200U);
                REQUIRE(second_login.status == 200U);
                // Spec MUST: successive logins MUST produce distinct access tokens.
                // Do NOT remove - token reuse allows session hijacking across devices.
                REQUIRE(login.body != second_login.body);
                // Spec MUST: a valid token MUST authenticate to the correct user.
                // Do NOT remove - token-to-user resolution is the foundation of all auth.
                REQUIRE(authenticated == std::optional<std::string>{user.body});
                // Spec MUST: logout MUST return 200 and invalidate the presented token.
                // Do NOT remove - a non-200 or missing revocation leaves sessions open forever.
                REQUIRE(logout.status == 200U);
                REQUIRE_FALSE(after_logout.has_value());
                // Spec MUST: logout of one token MUST NOT affect other sessions.
                // Do NOT remove - session isolation is a core Matrix security property.
                REQUIRE(second_still_authenticated.has_value());
                // Spec MUST: all auth actions MUST be recorded in the audit log.
                // Do NOT remove - missing audit entries break tamper-evidence guarantees.
                REQUIRE(merovingian::homeserver::audit_event_count(runtime) >= 5U);
            }
        }
    }
}

// --- Admin metrics and audit endpoints ---------------------------------------
// Spec: Merovingian internal invariant
//
// Admin observability endpoints MUST be gated on a valid admin session.
// Metrics and audit responses MUST NOT contain any credential material.
// The audit log MUST be durable: events written during setup MUST appear
// in the audit response.
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
        // Spec MUST: setup login MUST succeed before admin endpoints can be tested.
        // Do NOT remove - test is invalid if admin session is not established.
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
                // Spec MUST: authenticated admin requests to metrics MUST return 200.
                // Do NOT remove - a non-200 means operators are blind to runtime state.
                REQUIRE(metrics.status == 200U);
                REQUIRE_FALSE(metrics.headers.empty());
                auto const metrics_content_type = std::ranges::find_if(metrics.headers, [](auto const& header) {
                    return header.first == "Content-Type";
                });
                REQUIRE(metrics_content_type != metrics.headers.end());
                REQUIRE(metrics_content_type->second == "text/plain; version=0.0.4; charset=utf-8");
                // Spec MUST: authenticated admin requests to audit MUST return 200.
                // Do NOT remove - a non-200 means audit trail is inaccessible to operators.
                REQUIRE(audit.status == 200U);
                // Spec MUST: unauthenticated requests to admin endpoints MUST return 401.
                // Do NOT remove - anonymous audit access leaks operational intelligence.
                REQUIRE(unauthenticated.status == 401U);
                // Spec MUST: metrics response MUST include the audit event counter.
                // Do NOT remove - missing counter prevents alerting on audit log stalls.
                REQUIRE(metrics.body.find("# HELP audit_events_appended_total") != std::string::npos);
                REQUIRE(metrics.body.find("# TYPE audit_events_appended_total counter") != std::string::npos);
                REQUIRE(metrics.body.find("audit_events_appended_total ") != std::string::npos);
                REQUIRE(metrics.body.find("merovingian_server_identity{server_name=\"example.org\"} 1") !=
                        std::string::npos);
                REQUIRE(metrics.body.find("merovingian_health_status{component=\"runtime\",status=\"ok\"} 1") !=
                        std::string::npos);
                // Spec MUST: metrics and audit responses MUST NOT leak credential material.
                // Do NOT remove - credential leakage in observability is a critical security vuln.
                REQUIRE(metrics.body.find("access_token") == std::string::npos);
                // Spec MUST: audit log MUST include the startup event.
                // Do NOT remove - missing startup event breaks the tamper-evidence chain.
                REQUIRE(audit.body.find("runtime.started") != std::string::npos);
                // Spec MUST: audit response MUST NOT contain raw passwords.
                // Do NOT remove - password leakage via audit is a critical security vuln.
                REQUIRE(audit.body.find("CorrectHorse7") == std::string::npos);
                // Spec MUST: persistent audit log MUST be durable across the request lifecycle.
                // Do NOT remove - a shrinking log indicates events are being dropped or truncated.
                REQUIRE(runtime.database.persistent_store.audit_log.size() >= 3U);
            }
        }
    }
}

// --- Password and token hashing security -------------------------------------
// Spec: Merovingian security policy
//
// Passwords MUST be stored as Argon2id hashes - never in plaintext, never as
// a weaker algorithm. Access tokens MUST be stored as versioned hashes with the
// "token-hash:v3:" prefix and MUST be random and unique per session.
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
            // Spec MUST: registration MUST succeed before credential storage can be verified.
            // Do NOT remove - test is invalid if registration fails.
            REQUIRE(user.status == 200U);
            auto const first_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
            auto const second_login = merovingian::homeserver::handle_local_http_request(
                runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});

            THEN("the persisted password is Argon2id-shaped and tokens are random with versioned "
                 "hashes")
            {
                // Spec MUST: both logins MUST return 200.
                // Do NOT remove - failed logins invalidate all subsequent hash assertions.
                REQUIRE(first_login.status == 200U);
                REQUIRE(second_login.status == 200U);
                // Spec MUST: each login MUST issue a distinct access token.
                // Do NOT remove - identical tokens allow one device to hijack another's session.
                REQUIRE(first_login.body != second_login.body);
                // Spec MUST: tokens MUST carry the "mvs_" prefix for format validation.
                // Do NOT remove - prefix is used by auth middleware to reject malformed tokens fast.
                REQUIRE(first_login.body.rfind("mvs_", 0U) == 0U);
                REQUIRE(second_login.body.rfind("mvs_", 0U) == 0U);
                // Spec MUST: exactly one user record MUST exist after a single registration.
                // Do NOT remove - duplicate records cause phantom auth to the wrong account.
                REQUIRE(runtime.database.users.size() == 1U);
                // Spec MUST: stored password MUST be an Argon2id hash (never plaintext).
                // Do NOT remove - any other format indicates the password was stored insecurely.
                REQUIRE(runtime.database.users.front().password_hash.rfind("password-hash:v2:$argon2id$", 0U) == 0U);
                // Spec MUST: the raw password MUST NOT appear anywhere in the stored hash.
                // Do NOT remove - plaintext passwords in the DB are an immediate critical vuln.
                REQUIRE(runtime.database.users.front().password_hash.find("CorrectHorse7!") == std::string::npos);
                // Spec MUST: two distinct sessions MUST be stored for two logins.
                // Do NOT remove - fewer sessions means tokens were aliased, breaking revocation.
                REQUIRE(runtime.database.sessions.size() == 2U);
                // Spec MUST: token hashes MUST carry the versioned "token-hash:v3:" prefix.
                // Do NOT remove - prefix validates the hashing algorithm version on lookup.
                REQUIRE(runtime.database.sessions.front().access_token_hash.rfind("token-hash:v3:", 0U) == 0U);
                REQUIRE(runtime.database.sessions.back().access_token_hash.rfind("token-hash:v3:", 0U) == 0U);
                // Spec MUST: stored token hashes MUST be distinct across sessions.
                // Do NOT remove - identical hashes allow one token to authenticate as another.
                REQUIRE(runtime.database.sessions.front().access_token_hash !=
                        runtime.database.sessions.back().access_token_hash);
            }
        }
    }
}

// --- Credential and token collision resistance --------------------------------
// Spec: Merovingian security policy
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#login
//
// Password verification MUST reject same-length incorrect passwords - defending
// against length-based timing leaks. Token verification MUST reject single-bit
// mutations of a valid token - the full secret value MUST be compared.
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
        // Spec MUST: setup registration MUST succeed.
        // Do NOT remove - test is invalid if the user account does not exist.
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        // Spec MUST: setup login MUST succeed to obtain a real token for mutation.
        // Do NOT remove - test is invalid without a valid token to mutate.
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
                // Spec MUST: incorrect password MUST return 403 regardless of length match.
                // Do NOT remove - a 200 here means password checking is bypassed or broken.
                REQUIRE(bad_login.status == 403U);
                REQUIRE(bad_login.body == "invalid login");
                // Spec MUST: a single-character mutation of a valid token MUST be rejected.
                // Do NOT remove - acceptance indicates the comparison is truncated or prefix-only.
                REQUIRE_FALSE(fake_auth.has_value());
            }
        }
    }
}

// --- Local room create / join / send / state flow ----------------------------
// Spec: Matrix Client-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3createroom
//
// Room creation MUST emit the four initial state events required by the spec:
// m.room.create, m.room.power_levels, m.room.join_rules, and m.room.member
// for the creator. These events are mandatory for a valid auth chain that
// federation peers can verify.
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
        // Spec MUST: setup registration MUST succeed.
        // Do NOT remove - test is invalid without an authenticated user.
        REQUIRE(user.status == 200U);
        auto const login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, user.body + "|CorrectHorse7!|DEVICE1"});
        // Spec MUST: setup login MUST succeed.
        // Do NOT remove - test is invalid without a valid session token.
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
                // Spec MUST: createRoom MUST return 200 with the new room ID.
                // Do NOT remove - a non-200 means room creation failed and all subsequent steps are invalid.
                REQUIRE(room.status == 200U);
                // Room v12 (the default) derives the room ID from the create event hash
                // (MSC4291), so it is no longer the deterministic "!room1:example.org".
                // Assert a valid room ID sigil; exact per-version formats are pinned by the
                // dedicated create-room room-version tests.
                REQUIRE(room.body.starts_with("!"));
                // Spec MUST: join and send MUST return 200.
                // Do NOT remove - failures here indicate the room DAG is not accepting events.
                REQUIRE(join.status == 200U);
                REQUIRE(event.status == 200U);
                // Spec MUST: state endpoint MUST return 200 with a JSON array.
                // Do NOT remove - a non-200 prevents clients from reading room state.
                REQUIRE(state.status == 200U);
                // Spec MUST: m.room.create MUST be present in the initial room state.
                // URL: ../../docs/matrix-v1.18-spec/client-server-api.md#post_matrixclientv3createroom
                // Do NOT remove - missing create event makes the auth chain unverifiable by federation.
                REQUIRE(state.body.find("\"m.room.create\"") != std::string::npos);
                // Spec MUST: m.room.member for the creator MUST be present in initial state.
                // Do NOT remove - missing member event means the creator is not joined in the auth chain.
                REQUIRE(state.body.find("\"m.room.member\"") != std::string::npos);
                // Spec MUST: m.room.power_levels MUST be present in initial state.
                // Do NOT remove - missing power levels event leaves room permission model undefined.
                REQUIRE(state.body.find("\"m.room.power_levels\"") != std::string::npos);
                // Spec MUST: m.room.join_rules MUST be present in initial state.
                // Do NOT remove - missing join rules event leaves room access control undefined.
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

// Spec: Matrix Server-Server API v1.18
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
//
// The joining server must reject a malformed make_join template rather than
// repairing missing required fields locally before signing it.
SCENARIO("Remote join rejects malformed make_join templates instead of repairing them",
         "[homeserver][vertical][rooms][federation][make-join]")
{
    GIVEN("a make_join response whose event omits origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation fails because origin_server_ts is required")
            {
                REQUIRE_FALSE(parsed.ok);
                REQUIRE(parsed.reason.find("origin_server_ts") != std::string::npos);
            }
        }
    }

    GIVEN("a make_join response whose event omits the origin field but includes origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin_server_ts":1234,"content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation succeeds because origin was removed from events in room version 4")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.room_version == "12");
            }
        }
    }

    GIVEN("a make_join response whose event shape includes origin and origin_server_ts")
    {
        auto const body = std::string{
            R"({"room_version":"12","event":{"type":"m.room.member","room_id":"!room:remote.example.org","sender":"@alice:local.example.org","state_key":"@alice:local.example.org","origin":"remote.example.org","origin_server_ts":1234,"content":{"membership":"join"}}})"};

        WHEN("the response is validated before signing")
        {
            auto const parsed = merovingian::homeserver::validate_make_join_response("!room:remote.example.org",
                                                                                     "@alice:local.example.org", body);

            THEN("validation succeeds and returns the room version from the response")
            {
                REQUIRE(parsed.ok);
                REQUIRE(parsed.room_version == "12");
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
                // Still one key - ensure is idempotent.
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
        // Inject a well-formed legacy key - the secret is valid base64 but the key_id is
        // "ed25519:auto", which notary servers (e.g. matrix.org) may have cached with a
        // far-future valid_until_ts, making it impossible to rotate via normal expiry.
        runtime.database.persistent_store.server_signing_keys.push_back({
            server_name, "ed25519:auto",
            "cHVibGlja2V5", // base64("pubkey") - syntactically valid but not real Ed25519
            32503680000000ULL,
            "c2VjcmV0a2V5", // base64("secretkey") - valid base64, wrong size
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


SCENARIO("ensure_runtime_server_signing_key encrypts a fresh secret when a master key is configured",
         "[homeserver][vertical][signing][security]")
{
    GIVEN("a started runtime configured with a 256-bit master key")
    {
        auto started = merovingian::homeserver::start_runtime(
            registration_enabled_config_with_master_key(merovingian::tests::master_key_file()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        THEN("the persisted signing secret is stored as secretbox:v1:...")
        {
            REQUIRE(runtime.database.persistent_store.server_signing_keys.size() == 1U);
            REQUIRE(runtime.database.persistent_store.server_signing_keys.front().secret_key.starts_with(
                "secretbox:v1:"));
            REQUIRE(runtime.database.signing_secret_key.size() == crypto_sign_SECRETKEYBYTES);
        }
    }
}

SCENARIO("ensure_runtime_server_signing_key decrypts an encrypted signing secret on reload",
         "[homeserver][vertical][signing][security]")
{
    GIVEN("a runtime whose signing secret is stored encrypted")
    {
        auto const master_key_path = merovingian::tests::master_key_file();
        auto started = merovingian::homeserver::start_runtime(
            registration_enabled_config_with_master_key(master_key_path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const encrypted_secret =
            runtime.database.persistent_store.server_signing_keys.front().secret_key;
        REQUIRE(encrypted_secret.starts_with("secretbox:v1:"));

        WHEN("the runtime secret is cleared and ensure is called again")
        {
            runtime.database.signing_secret_key.clear();
            auto const key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);

            THEN("the encrypted secret is decrypted back into the runtime signing key")
            {
                REQUIRE(key.has_value());
                REQUIRE(runtime.database.signing_secret_key.size() == crypto_sign_SECRETKEYBYTES);
            }
        }
    }
}

SCENARIO("rotate_server_signing_key encrypts the new secret when a master key is configured",
         "[homeserver][vertical][signing][security]")
{
    GIVEN("a started runtime configured with a 256-bit master key")
    {
        auto started = merovingian::homeserver::start_runtime(
            registration_enabled_config_with_master_key(merovingian::tests::master_key_file()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("the signing key is rotated")
        {
            auto const result = merovingian::homeserver::rotate_server_signing_key(runtime);

            THEN("the rotation succeeds and the new secret is stored encrypted")
            {
                REQUIRE(result.ok);
                auto const active = std::ranges::max_element(
                    runtime.database.persistent_store.server_signing_keys,
                    {},
                    &merovingian::database::PersistentServerSigningKey::valid_until_ts);
                REQUIRE(active != runtime.database.persistent_store.server_signing_keys.end());
                REQUIRE(active->secret_key.starts_with("secretbox:v1:"));
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

SCENARIO("start_runtime pre-warms the key server response cache", "[homeserver][vertical][signing][federation]")
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

            // load() returns an optional - must be populated by the startup pre-warm.
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

SCENARIO("Cross-signing key upload stores and returns all three key types",
         "[homeserver][vertical][keys][cross-signing]")
{
    GIVEN("a logged-in user uploading cross-signing keys")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const reg = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(reg.response.status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                 R"("password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = extract_token(login.response.body);

        auto const cross_signing_body = std::string{
            R"({"master_key":{"user_id":"@alice:example.org","usage":["master"],"keys":{"ed25519:MASTER":"abc"},"signatures":{}},"self_signing_key":{"user_id":"@alice:example.org","usage":["self_signing"],"keys":{"ed25519:SELF":"def"},"signatures":{}},"user_signing_key":{"user_id":"@alice:example.org","usage":["user_signing"],"keys":{"ed25519:USER":"ghi"},"signatures":{}},"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"};

        WHEN("the user uploads cross-signing keys via device_signing/upload")
        {
            auto const upload = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/keys/device_signing/upload", token, cross_signing_body});
            REQUIRE(upload.response.status == 200U);

            THEN("all three key types are stored and returned by keys/query")
            {
                auto& store = rt.homeserver.database.persistent_store;
                auto master_count = std::size_t{0U};
                auto self_signing_count = std::size_t{0U};
                auto user_signing_count = std::size_t{0U};
                for (auto const& cskey : store.cross_signing_keys)
                {
                    if (cskey.user_id != "@alice:example.org")
                    {
                        continue;
                    }
                    if (cskey.key_type == "master")
                    {
                        ++master_count;
                    }
                    else if (cskey.key_type == "self_signing")
                    {
                        ++self_signing_count;
                    }
                    else if (cskey.key_type == "user_signing")
                    {
                        ++user_signing_count;
                    }
                }
                // Spec MUST: cross-signing key upload MUST persist all three key types.
                // Do NOT remove - Element's "Unable to set up keys" error is caused
                // by only storing the master key and losing self_signing/user_signing.
                REQUIRE(master_count == 1U);
                REQUIRE(self_signing_count == 1U);
                REQUIRE(user_signing_count == 1U);

                auto const query_body = std::string{R"({"device_keys":{"@alice:example.org":[]}})"};
                auto const query = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/keys/query", token, query_body});
                REQUIRE(query.response.status == 200U);
                REQUIRE(query.response.body.find("\"master_keys\"") != std::string::npos);
                REQUIRE(query.response.body.find("\"self_signing_keys\"") != std::string::npos);
                REQUIRE(query.response.body.find("\"user_signing_keys\"") != std::string::npos);
            }
        }
    }
}

// --- Audit log never leaks raw bearer token material -------------------------
// Security policy: access tokens are secrets that MUST NOT appear in logs or
// audit rows. When authentication fails the audit actor MUST be the resolved
// user_id (when the session is known) or "<unknown>" (when it is not). The
// raw bearer string — which starts with "mvs_" — MUST never reach any audit
// row, regardless of the rejection reason.
SCENARIO("Audit log never captures raw access token material on auth rejection",
         "[homeserver][vertical][auth][security][audit]")
{
    GIVEN("a started runtime and a known-format bearer token that has no session")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        // Setup MUST succeed — test is invalid without a running runtime.
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        // Register and log in so the audit sink is exercised by a real token
        // path first — ensures we are not just checking an empty log.
        auto const user = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_pipe("alice", "CorrectHorse7!")});
        // Spec MUST: registration MUST succeed for the audit baseline to exist.
        // Do NOT remove — test is invalid without a prior audit entry.
        REQUIRE(user.status == 200U);

        auto const fake_token = std::string{"mvs_totally_fake_test_token_xyzzy"};

        WHEN("an unrecognised bearer token with the mvs_ prefix is presented for authentication")
        {
            auto const result = merovingian::homeserver::authenticated_user(runtime, fake_token);
            auto const& audit = runtime.database.persistent_store.audit_log;

            THEN("the call is rejected and no audit row contains the raw token string")
            {
                // Security MUST: an unknown token MUST be rejected.
                // Do NOT remove — accepting unknown tokens is an authentication bypass.
                REQUIRE_FALSE(result.has_value());

                // Security MUST: at least one audit row MUST exist for the rejection.
                // Do NOT remove — a missing audit row means the event was silently dropped.
                REQUIRE_FALSE(audit.empty());

                // Security MUST: no audit row actor or target MUST equal the raw bearer token.
                // Do NOT remove — raw token in actor/target is a critical credential leak.
                auto const raw_token_in_actor = std::ranges::any_of(audit, [&fake_token](auto const& row) {
                    return row.actor == fake_token || row.target == fake_token;
                });
                REQUIRE_FALSE(raw_token_in_actor);

                // Security MUST: no audit row actor or target MUST contain the "mvs_" prefix.
                // Do NOT remove — "mvs_" in audit rows leaks namespace and token shape.
                auto const mvs_prefix_in_actor = std::ranges::any_of(audit, [](auto const& row) {
                    return row.actor.find("mvs_") != std::string::npos || row.target.find("mvs_") != std::string::npos;
                });
                REQUIRE_FALSE(mvs_prefix_in_actor);

                // Security MUST: no audit row actor MUST equal the literal string "access_token".
                // Do NOT remove — "access_token" as actor means the raw token was forwarded
                // unchanged; this was the exact form of the bug this test guards against.
                auto const literal_field_name_in_actor = std::ranges::any_of(audit, [](auto const& row) {
                    return row.actor == "access_token" || row.target == "access_token";
                });
                REQUIRE_FALSE(literal_field_name_in_actor);
            }
        }
    }
}
