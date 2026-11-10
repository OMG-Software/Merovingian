// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/TempDirectory.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/Random.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentStoreBackend.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/http/RateLimitPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using merovingian::canonicaljson::make_member;
using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;

// Never capture credentials, response bodies, hashes or startup reasons in
// diagnostics. Parenthesised comparisons make Catch2 expand only booleans.
[[nodiscard]] auto random_suffix() -> std::string
{
    auto const generated = merovingian::crypto::secure_random_hex(32U);
    // Spec MUST: the access-token flow must run with a successfully prepared fixture.
    REQUIRE(generated.has_value());
    return *generated;
}

class SqliteFixture final
{
public:
    SqliteFixture()
        : m_directory{merovingian::tests::temporary_directory() / ("merovingian-token-expiry-" + random_suffix())}
    {
        auto error = std::error_code{};
        auto const created = std::filesystem::create_directory(m_directory, error);
        // Spec MUST: the access-token flow must run against a usable real store.
        REQUIRE((created && !error));
    }

    SqliteFixture(SqliteFixture const&) = delete;
    auto operator=(SqliteFixture const&) -> SqliteFixture& = delete;
    SqliteFixture(SqliteFixture&&) = delete;
    auto operator=(SqliteFixture&&) -> SqliteFixture& = delete;

    ~SqliteFixture()
    {
        auto error = std::error_code{};
        std::ignore = std::filesystem::remove_all(m_directory, error);
    }

    [[nodiscard]] auto config(std::optional<std::int64_t> lifetime) const -> merovingian::config::Config
    {
        auto database = merovingian::config::DatabaseConfig{};
        database.backend = merovingian::config::DatabaseBackend::sqlite;
        database.sqlite_path = (m_directory / "tokens.sqlite3").string();
        auto security = merovingian::config::SecurityConfig{};
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        if (lifetime.has_value())
        {
            security.access_token_lifetime_ms = *lifetime;
        }
        // The F-08 scenarios refresh dozens of times from one address; the default auth tier (20 a minute per
        // address) would answer 429 to the 21st. The tier is raised for them only.
        auto limits = merovingian::config::ClientRateLimitsConfig{};
        limits.tier["auth_sensitive"] = merovingian::http::RateLimitPolicy{10000U, 60U};
        return {
            merovingian::config::ServerConfig{},    merovingian::config::ListenersConfig{}, database, security, limits,
            merovingian::config::LogModulesConfig{}};
    }

private:
    std::filesystem::path m_directory;
};

[[nodiscard]] auto request_json(Object object) -> std::string
{
    auto const serialized = merovingian::canonicaljson::serialize_canonical(Value{std::move(object)});
    // Spec MUST: authentication requests are valid JSON objects.
    REQUIRE((serialized.error == merovingian::canonicaljson::CanonicalJsonError::none));
    return serialized.output;
}

[[nodiscard]] auto response_object(std::string const& body) -> Object
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(body);
    // Spec MUST: successful authentication responses are JSON objects.
    REQUIRE((parsed.error == merovingian::canonicaljson::ParseError::none));
    // Spec MUST: successful authentication responses are JSON objects.
    REQUIRE(std::holds_alternative<Object>(parsed.value.storage()));
    return std::get<Object>(parsed.value.storage());
}

[[nodiscard]] auto required_member(Object const& object, std::string_view key) -> Value const&
{
    auto const found = std::find_if(object.begin(), object.end(), [key](auto const& member) {
        return member.key == key;
    });
    // Spec MUST: the response includes the required authentication field.
    REQUIRE((found != object.end()));
    // Spec MUST: the required field contains a JSON value.
    REQUIRE((found->value != nullptr));
    return *found->value;
}

[[nodiscard]] auto response_string(Object const& object, std::string_view key) -> std::string
{
    auto const& value = required_member(object, key);
    // Spec MUST: access tokens and the returned user/device identifiers are strings.
    REQUIRE(std::holds_alternative<std::string>(value.storage()));
    auto const& text = std::get<std::string>(value.storage());
    // Spec MUST: an issued token/identifier is usable, not an empty placeholder.
    REQUIRE(!text.empty());
    return text;
}

[[nodiscard]] auto response_lifetime(Object const& object) -> std::int64_t
{
    auto const& value = required_member(object, "expires_in_ms");
    // Spec MUST: expires_in_ms, when advertised, is an integer in milliseconds.
    REQUIRE(std::holds_alternative<std::int64_t>(value.storage()));
    return std::get<std::int64_t>(value.storage());
}

[[nodiscard]] auto password_login(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& user_id,
                                  std::string const& password, std::string const& device_id, bool refresh_support)
    -> Object
{
    auto const body = request_json({
        make_member("type", Value{std::string{"m.login.password"}    }
         ),
        make_member("identifier", Value{Object{
                                      make_member("type", Value{std::string{"m.id.user"}}),
                                      make_member("user", Value{user_id}),
                                  }}
         ),
        make_member("password", Value{password                           }
         ),
        make_member("device_id", Value{device_id                          }
         ),
        make_member("refresh_token", Value{refresh_support                    }
         ),
    });
    auto const result =
        merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, body});
    // Spec MUST: valid password authentication succeeds through the public login endpoint.
    REQUIRE((result.response.status == 200U));
    return response_object(result.response.body);
}

[[nodiscard]] auto refresh(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& refresh_token)
    -> Object
{
    auto const body = request_json({make_member("refresh_token", Value{refresh_token})});
    auto const result = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/refresh", {}, body});
    // Spec MUST: /refresh authenticates using the refresh token, without an access token.
    REQUIRE((result.response.status == 200U));
    return response_object(result.response.body);
}

void require_whoami(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& access_token,
                    std::string const& user_id, std::string const& device_id)
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/account/whoami", access_token, {}});
    // Spec MUST: an issued access token authorises requests for its user/device.
    REQUIRE((result.response.status == 200U));
    auto const body = response_object(result.response.body);
    // Spec MUST: whoami identifies the authenticated user.
    REQUIRE((response_string(body, "user_id") == user_id));
    // Spec MUST: whoami identifies the device associated with the access token.
    REQUIRE((response_string(body, "device_id") == device_id));
}

void require_stored_access(merovingian::database::PersistentStore const& store, std::string const& user_id,
                           std::string const& device_id, bool refreshed, bool finite)
{
    auto const row = std::find_if(store.access_tokens.begin(), store.access_tokens.end(), [&](auto const& candidate) {
        return candidate.user_id == user_id && candidate.device_id == device_id && !candidate.revoked &&
               !candidate.predecessor_refresh_hash.empty() == refreshed;
    });
    // Spec MUST: the successful authentication flow creates a usable access-token session.
    REQUIRE((row != store.access_tokens.end()));
    // Fixture MUST: real master-key-derived v4 hashing, never a fake token/authentication callback.
    REQUIRE(row->token_hash.starts_with("token-hash:v4:"));
    // Spec MUST: advertised expiry agrees with the actual access-token expiry policy.
    REQUIRE((row->expires_at.has_value() == finite));
    if (finite)
    {
        // Spec MUST: a freshly issued finite-lifetime access token has not already expired.
        REQUIRE((*row->expires_at > std::chrono::system_clock::now()));
    }
}

struct AuthenticationResponses final
{
    Object login;
    Object refresh;
};

[[nodiscard]] auto exercise_authentication(std::optional<std::int64_t> lifetime) -> AuthenticationResponses
{
    // Runtime is destroyed before its isolated SQLite directory is removed.
    auto const fixture = SqliteFixture{};
    auto started = merovingian::homeserver::start_client_server(fixture.config(lifetime));
    // Spec MUST: successful controls run against a fully started authentication dispatcher.
    REQUIRE(started.started);
    auto& runtime = started.runtime;
    auto const& store = runtime.homeserver.database.persistent_store;
    // Fixture MUST: use the actual SQLite persistence backend, not the memory test backend.
    REQUIRE(store.open);
    // Fixture MUST: use the actual SQLite persistence backend, not a mock store.
    REQUIRE((store.backend == merovingian::database::PersistentStoreBackend::sqlite));
    auto const configured_lifetime = runtime.homeserver.config.security().access_token_lifetime_ms;
    // Fixture MUST: the finite control retains the healthy one-hour default.
    REQUIRE((configured_lifetime == lifetime.value_or(3600000)));

    auto const localpart = "expiry_" + random_suffix();
    auto const password = std::string{'A', 'a', '9', '!'} + random_suffix();
    // Bootstrap creates a real password-hashed account only; no session is
    // injected, and both logins below must verify that password in the dispatcher.
    auto const account = merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, localpart, password);
    // Spec MUST: login is exercised with an existing account and valid authentication data.
    REQUIRE(account.ok);
    auto const device_id = "refresh_" + random_suffix();
    auto login = password_login(runtime, account.value, password, device_id, true);
    auto const login_access = response_string(login, "access_token");
    auto const login_refresh = response_string(login, "refresh_token");
    // Spec MUST: login identifies the authenticated account and requested device.
    REQUIRE((response_string(login, "user_id") == account.value));
    // Spec MUST: login identifies the requested device.
    REQUIRE((response_string(login, "device_id") == device_id));
    require_whoami(runtime, login_access, account.value, device_id);
    require_stored_access(store, account.value, device_id, false, configured_lifetime > 0);

    auto refreshed = refresh(runtime, login_refresh);
    auto const refreshed_access = response_string(refreshed, "access_token");
    auto const refreshed_refresh = response_string(refreshed, "refresh_token");
    // Spec MUST: /refresh supplies a new access token, not an empty/replayed placeholder.
    REQUIRE((refreshed_access != login_access));
    // Fixture MUST: the dispatcher really rotates its refresh token.
    REQUIRE((refreshed_refresh != login_refresh));
    require_whoami(runtime, refreshed_access, account.value, device_id);
    require_stored_access(store, account.value, device_id, true, configured_lifetime > 0);

    auto const legacy_device = "legacy_" + random_suffix();
    auto const legacy = password_login(runtime, account.value, password, legacy_device, false);
    require_whoami(runtime, response_string(legacy, "access_token"), account.value, legacy_device);
    require_stored_access(store, account.value, legacy_device, false, false);
    // Spec MAY: legacy clients may receive non-expiring access tokens; retain this healthy path.
    REQUIRE((merovingian::tests::object_member(legacy, "expires_in_ms") == nullptr));
    // Spec MAY: the legacy non-refresh login need not issue a refresh token.
    REQUIRE((merovingian::tests::object_member(legacy, "refresh_token") == nullptr));
    return {std::move(login), std::move(refreshed)};
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/login, POST /_matrix/client/v3/refresh;
//                    Refreshing access tokens.
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3login
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3refresh
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#refreshing-access-tokens
// Local response rows: login 4896 (endpoint heading 4810-4812), refresh 5337
// (endpoint heading 5276-5278). Row 5713 belongs to registration, not refresh.
// Both endpoint rows say that omission means the access token will not expire:
// a non-expiring token must not be advertised with a zero-millisecond lifetime.
SCENARIO("Login and refresh omit expiry for non-expiring access tokens while finite controls remain usable",
         "[conformance][client-server][auth][refresh][token-expiry][ops-4]")
{
    GIVEN("isolated real SQLite dispatchers with default and zero access-token lifetimes")
    {
        WHEN("password logins and public refresh requests issue real access and refresh tokens")
        {
            THEN("the finite control advertises its lifetime and both non-expiring responses omit expiry")
            {
                // One complete BDD leaf runs both settings and both endpoints.
                // Complete every success, usability and stored-expiry prerequisite
                // before the independent nonfatal checks, so login RED cannot hide refresh RED.
                auto const finite = exercise_authentication(std::nullopt);
                auto const non_expiring = exercise_authentication(std::int64_t{0});
                auto const finite_login_lifetime = response_lifetime(finite.login);
                auto const finite_refresh_lifetime = response_lifetime(finite.refresh);
                // Spec MUST: advertised finite lifetimes are positive integer milliseconds.
                REQUIRE((finite_login_lifetime > 0 && finite_refresh_lifetime > 0));
                // Spec MUST: login advertises the actual configured access-token lifetime.
                REQUIRE((finite_login_lifetime == 3600000));
                // Spec MUST: refresh advertises the actual configured access-token lifetime.
                REQUIRE((finite_refresh_lifetime == 3600000));

                // Spec MUST: no expiry is advertised when the login access token does not expire.
                CHECK((merovingian::tests::object_member(non_expiring.login, "expires_in_ms") == nullptr));
                // Spec MUST: no expiry is advertised when the refreshed access token does not expire.
                CHECK((merovingian::tests::object_member(non_expiring.refresh, "expires_in_ms") == nullptr));
            }
        }
    }
}

namespace
{

// F-08 (security audit run 4, ADR-0590): a login on a device the user already holds replaces that device's
// credentials, and a refresh keeps a bounded history of retired refresh tokens.

struct HttpAnswer final
{
    unsigned status{0U};
    std::string errcode{};
};

[[nodiscard]] auto errcode_of(std::string const& body) -> std::string
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(body);
    if (parsed.error != merovingian::canonicaljson::ParseError::none ||
        !std::holds_alternative<Object>(parsed.value.storage()))
    {
        return {};
    }
    for (auto const& member : std::get<Object>(parsed.value.storage()))
    {
        if (member.key == "errcode" && member.value != nullptr &&
            std::holds_alternative<std::string>(member.value->storage()))
        {
            return std::get<std::string>(member.value->storage());
        }
    }
    return {};
}

[[nodiscard]] auto whoami_answer(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& access_token)
    -> HttpAnswer
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/account/whoami", access_token, {}});
    return {static_cast<unsigned>(result.response.status), errcode_of(result.response.body)};
}

[[nodiscard]] auto refresh_answer(merovingian::homeserver::ClientServerRuntime& runtime,
                                  std::string const& refresh_token) -> HttpAnswer
{
    auto const body = request_json({make_member("refresh_token", Value{refresh_token})});
    auto const result = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/refresh", {}, body});
    return {static_cast<unsigned>(result.response.status), errcode_of(result.response.body)};
}

[[nodiscard]] auto reuse_audit_rows(merovingian::database::PersistentStore const& store) -> std::ptrdiff_t
{
    return std::count_if(store.audit_log.begin(), store.audit_log.end(), [](auto const& row) {
        return row.event_type == "auth.refresh.reuse_detected";
    });
}

// Refresh times are stamped in milliseconds and the oldest retired row is evicted first, so each rotation in a test
// that checks which row went starts in a new millisecond.
auto next_millisecond() -> void
{
    std::this_thread::sleep_for(std::chrono::milliseconds{2});
}

struct Account final
{
    std::string user_id;
    std::string password;
};

[[nodiscard]] auto make_account(merovingian::homeserver::ClientServerRuntime& runtime) -> Account
{
    auto const password = std::string{'A', 'a', '9', '!'} + random_suffix();
    auto const account =
        merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "rows_" + random_suffix(), password);
    // Spec MUST: login is exercised with an existing account and valid authentication data.
    REQUIRE(account.ok);
    return {account.value, password};
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /_matrix/client/v3/login (`device_id`), POST /_matrix/client/v3/refresh
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3login
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3refresh
// `device_id`: a login with the ID of a known device makes the server invalidate any access token previously
// associated with that device. Another device is untouched.
SCENARIO("A login on a device the user already holds invalidates that device's earlier access token",
         "[conformance][client-server][auth][login][f08-rows]")
{
    GIVEN("a user logged in on two devices")
    {
        auto const fixture = SqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(fixture.config(std::nullopt));
        // Spec MUST: the dispatcher starts against a real store.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const account = make_account(runtime);
        auto const first = password_login(runtime, account.user_id, account.password, "DEVICE_A", false);
        auto const other = password_login(runtime, account.user_id, account.password, "DEVICE_B", false);
        auto const first_token = response_string(first, "access_token");
        auto const other_token = response_string(other, "access_token");
        // Spec MUST: an issued access token authorises requests.
        REQUIRE(whoami_answer(runtime, first_token).status == 200U);

        WHEN("the user logs in again with the first device's ID")
        {
            auto const second = password_login(runtime, account.user_id, account.password, "DEVICE_A", false);
            auto const second_token = response_string(second, "access_token");

            THEN("the earlier token is M_UNKNOWN_TOKEN, the new one works and the other device is untouched")
            {
                auto const stale = whoami_answer(runtime, first_token);
                // Spec MUST: the server invalidates any access token previously associated with that device.
                REQUIRE(stale.status == 401U);
                // Spec MUST: an invalidated token is answered M_UNKNOWN_TOKEN.
                REQUIRE(stale.errcode == "M_UNKNOWN_TOKEN");
                // Spec MUST: the access token the login returned authorises requests.
                REQUIRE(whoami_answer(runtime, second_token).status == 200U);
                // Spec MUST: a login on one device does not invalidate another device's token.
                REQUIRE(whoami_answer(runtime, other_token).status == 200U);
            }
        }
    }
}

SCENARIO("A login on a held device deletes its refresh tokens and a stale client's refresh is a plain 401",
         "[conformance][client-server][auth][login][refresh][f08-rows]")
{
    GIVEN("a device logged in with a refresh token")
    {
        auto const fixture = SqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(fixture.config(std::nullopt));
        // Spec MUST: the dispatcher starts against a real store.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const account = make_account(runtime);
        auto const first = password_login(runtime, account.user_id, account.password, "DEVICE_A", true);
        auto const first_refresh = response_string(first, "refresh_token");

        WHEN("the user logs in again on that device with a refresh token and the stale refresh token is presented")
        {
            auto const second = password_login(runtime, account.user_id, account.password, "DEVICE_A", true);
            auto const second_access = response_string(second, "access_token");
            auto const second_refresh = response_string(second, "refresh_token");
            auto const stale = refresh_answer(runtime, first_refresh);

            THEN("the stale token is 401, the new login is untouched and nothing is audited as reuse")
            {
                // Spec MUST: a refresh token the server no longer holds is refused.
                REQUIRE(stale.status == 401U);
                // Spec MUST: the refused token is answered M_UNKNOWN_TOKEN.
                REQUIRE(stale.errcode == "M_UNKNOWN_TOKEN");
                // Spec MUST: the access token of the login that replaced it keeps working.
                REQUIRE(whoami_answer(runtime, second_access).status == 200U);
                // Spec MUST: the new login's refresh token still refreshes.
                REQUIRE(refresh_answer(runtime, second_refresh).status == 200U);
                // Spec SHOULD: only an old, invalidated refresh token that the server holds counts as compromise.
                REQUIRE(reuse_audit_rows(runtime.homeserver.database.persistent_store) == 0);
            }
        }
    }
}

// The server keeps the last 32 retired refresh tokens of a device (ADR-0590). Spec SHOULD: the session is
// considered compromised if an old, invalidated refresh token is used, and revoked.
SCENARIO("Reuse of a retired refresh token ends the session while it is kept and is a plain 401 once evicted",
         "[conformance][client-server][auth][refresh][f08-rows]")
{
    GIVEN("a device that has refreshed 45 times, remembering every refresh token it held")
    {
        auto const fixture = SqliteFixture{};
        auto started = merovingian::homeserver::start_client_server(fixture.config(std::nullopt));
        // Spec MUST: the dispatcher starts against a real store.
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const account = make_account(runtime);
        auto const login = password_login(runtime, account.user_id, account.password, "DEVICE_A", true);
        auto tokens = std::vector<std::string>{response_string(login, "refresh_token")};
        auto latest_access = response_string(login, "access_token");
        for (auto round = 0; round < 45; ++round)
        {
            next_millisecond();
            auto const rotated = refresh(runtime, tokens.back());
            tokens.push_back(response_string(rotated, "refresh_token"));
            latest_access = response_string(rotated, "access_token");
        }
        auto& store = runtime.homeserver.database.persistent_store;

        WHEN("a token evicted from the history is presented")
        {
            auto const evicted = refresh_answer(runtime, tokens.front());

            THEN("it is a plain 401, the session survives and nothing is audited as reuse")
            {
                // Spec MUST: a refresh token the server no longer holds is refused.
                REQUIRE(evicted.status == 401U);
                // Spec MUST: the refused token is answered M_UNKNOWN_TOKEN.
                REQUIRE(evicted.errcode == "M_UNKNOWN_TOKEN");
                // Spec MUST: the device's current access token keeps working.
                REQUIRE(whoami_answer(runtime, latest_access).status == 200U);
                // Spec SHOULD: no compromise is claimed for a token the server cannot recognise.
                REQUIRE(reuse_audit_rows(store) == 0);
                // Spec MUST: the current refresh token still refreshes.
                REQUIRE(refresh_answer(runtime, tokens.back()).status == 200U);
            }
        }

        WHEN("a retired token still in the history is presented")
        {
            auto const reused = refresh_answer(runtime, tokens[tokens.size() - 10U]);

            THEN("it is refused, the audit records reuse and the device's session is ended")
            {
                // Spec SHOULD: an old, invalidated refresh token is refused.
                REQUIRE(reused.status == 401U);
                // Spec SHOULD: the reuse is recorded.
                REQUIRE(reuse_audit_rows(store) == 1);
                // Spec SHOULD: the session is revoked, so the current access token stops working.
                REQUIRE(whoami_answer(runtime, latest_access).status == 401U);
                // Spec SHOULD: and so does the current refresh token.
                REQUIRE(refresh_answer(runtime, tokens.back()).status == 401U);
            }
        }
    }
}
