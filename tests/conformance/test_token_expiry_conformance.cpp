// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/random.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>

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
        return {
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{}, database, security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
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
