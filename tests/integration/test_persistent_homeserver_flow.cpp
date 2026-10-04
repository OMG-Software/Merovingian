// SPDX-License-Identifier: GPL-3.0-or-later

#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <thread>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto registration_enabled_config_with_master_key(std::string master_key_path)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.secrets.master_key_file = std::move(master_key_path);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto sqlite_registration_enabled_config(std::filesystem::path const& sqlite_path)
    -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = sqlite_path.string();

    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);

    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto token_from_login_body(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_from_body(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() / ("merovingian-restart-flow-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("Programmatic in-memory backend starts an explicitly selected test runtime", "[db-3][database][startup]")
{
    GIVEN("a runtime config with the explicit in-memory test backend")
    {
        auto const baseline = registration_enabled_config();
        auto const config = merovingian::config::Config{
            baseline.server(),   baseline.listeners(),          merovingian::tests::in_memory_database_config(),
            baseline.security(), baseline.client_rate_limits(), baseline.log_modules(),
        };

        WHEN("the homeserver starts")
        {
            auto started = merovingian::homeserver::start_client_server(config);

            THEN("the runtime uses a validated in-memory store")
            {
                REQUIRE(started.started);
                CHECK(started.runtime.homeserver.database.opened);
                CHECK(started.runtime.homeserver.database.persistent_store.backend ==
                      merovingian::database::PersistentStoreBackend::memory);
                CHECK(started.runtime.homeserver.database.schema_validated);
            }
        }
    }
}

SCENARIO("PostgreSQL startup refuses missing or empty connection credentials", "[db-3][database][startup]")
{
    GIVEN("PostgreSQL is selected and the credentials file is absent")
    {
        auto const path = unique_sqlite_path().string() + ".uri";
        auto database = merovingian::config::DatabaseConfig{};
        database.uri_file = path;
        auto const baseline = registration_enabled_config();
        auto const config =
            merovingian::config::Config{baseline.server(),   baseline.listeners(),          database,
                                        baseline.security(), baseline.client_rate_limits(), baseline.log_modules()};
        WHEN("the runtime starts with the missing file")
        {
            auto const started = merovingian::homeserver::start_client_server(config);
            THEN("startup fails rather than silently storing security state in memory")
            {
                CHECK_FALSE(started.started);
                CHECK_FALSE(started.runtime.homeserver.database.opened);
            }
        }
        WHEN("the runtime starts with an empty credentials file")
        {
            {
                auto file = std::ofstream{path};
                REQUIRE(file.is_open());
            }
            auto const started = merovingian::homeserver::start_client_server(config);
            THEN("startup still fails")
            {
                CHECK_FALSE(started.started);
                CHECK_FALSE(started.runtime.homeserver.database.opened);
            }
            std::filesystem::remove(path);
        }
    }
}

SCENARIO("media uploaded after the legacy endpoint freeze stays private across restart", "[med-1][media][restart]")
{
    GIVEN("a SQLite-backed runtime and an authenticated media upload")
    {
        auto const path = unique_sqlite_path();
        auto const config = sqlite_registration_enabled_config(path);
        auto token = std::string{};
        auto media_id = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto const registered = merovingian::homeserver::register_local_user(
                started.runtime.homeserver, "media_restart", "CorrectHorse7!", merovingian::tests::registration_token);
            REQUIRE(registered.ok);
            auto const logged =
                merovingian::homeserver::login_local_user_by_id(started.runtime.homeserver, registered.value, "MEDIA");
            REQUIRE(logged.ok);
            token = logged.value;
            auto const uploaded = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST",
                                  "/_matrix/client/v1/media/upload",
                                  token,
                                  "media-restart-bytes",
                                  {{"Content-Type", "text/plain"}}});
            REQUIRE(uploaded.response.status == 200U);
            auto const& rows = started.runtime.homeserver.database.persistent_store.local_media;
            REQUIRE(rows.size() == 1U);
            REQUIRE_FALSE(rows.front().legacy_endpoint_visible);
            REQUIRE_FALSE(rows.front().quarantined);
            media_id = rows.front().media_id;
        }
        WHEN("the runtime is reopened and both media endpoints are requested")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const legacy = merovingian::homeserver::handle_client_server_request(
                restarted.runtime, {"GET", "/_matrix/media/v3/download/example.org/" + media_id, {}, {}});
            auto const authenticated = merovingian::homeserver::handle_client_server_request(
                restarted.runtime, {"GET", "/_matrix/client/v1/media/download/example.org/" + media_id, token, {}});
            THEN("the unauthenticated endpoint stays frozen and authenticated bytes survive")
            {
                CHECK(legacy.response.status == 404U);
                CHECK(authenticated.response.status == 200U);
                CHECK(authenticated.response.body == "media-restart-bytes");
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("SQLite-backed homeserver runtime survives restart with users sessions rooms and events",
         "[database][sqlite][homeserver][integration]")
{
    GIVEN("a registration-enabled SQLite homeserver config")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);

        WHEN("a user creates a room and the runtime is started again from the same SQLite file")
        {
            auto token = std::string{};
            auto room_id = std::string{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto& runtime = started.runtime;

                auto const registered = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     R"({"username":"restart","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@restart:example.org"},"password":"CorrectHorse7!","device_id":"RESTART1"})"});
                token = token_from_login_body(login.response.body);
                auto const room = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
                room_id = room_from_body(room.response.body);
                auto const send = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token,
                              R"({"type":"m.room.message","body":"persisted"})"});

                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(room.response.status == 200U);
                REQUIRE(send.response.status == 200U);
                REQUIRE(std::filesystem::exists(sqlite_path));
            }

            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& restarted_runtime = restarted.runtime;
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                restarted_runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
            auto const state = merovingian::homeserver::handle_client_server_request(
                restarted_runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});

            THEN("the restarted runtime authenticates the old token and exposes the persisted room state")
            {
                REQUIRE(whoami.response.status == 200U);
                REQUIRE(whoami.response.body.find(R"("@restart:example.org")") != std::string::npos);
                REQUIRE(state.response.status == 200U);
                REQUIRE(state.response.body.find("m.room.create") != std::string::npos);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.users.size() == 1U);
                // Register creates one token (alice_DEVICE); login creates a second (RESTART1).
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.access_tokens.size() == 2U);
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                // createRoom now persists the full preset chain, including
                // guest_access and m.room.encryption (for private_chat preset),
                // before the additional message event is sent.
                REQUIRE(restarted_runtime.homeserver.database.persistent_store.events.size() == 8U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

namespace
{

// Registers `localpart` and logs in with refresh-token consent (so the access
// token carries an expiry); returns the login response body.
[[nodiscard]] auto register_and_login_with_refresh(merovingian::homeserver::ClientServerRuntime& runtime,
                                                   std::string const& localpart) -> std::string
{
    REQUIRE(
        merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/register",
             {},
             std::string{R"({"username":")"} + localpart +
                 R"(","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"})
            .response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                      R"(:example.org"},"password":"CorrectHorse7!","device_id":"LIFE1","refresh_token":true})"});
    REQUIRE(login.response.status == 200U);
    return login.response.body;
}

[[nodiscard]] auto json_string_field(std::string const& body, std::string const& field) -> std::string
{
    auto const key = "\"" + field + "\":\"";
    auto const start = body.find(key);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + key.size();
    auto const end = body.find('"', value_start);
    REQUIRE(end != std::string::npos);
    return body.substr(value_start, end - value_start);
}

} // namespace

// An access token issued with an expiry must still expire after a restart.
// Hydration used to rebuild each in-memory session without its expires_at,
// so after any restart every access token was valid forever (found while
// doing 0.12.13 audit item 6).
SCENARIO("SQLite-backed runtime still expires access tokens after a restart",
         "[database][sqlite][homeserver][integration][session_restart]")
{
    GIVEN("a runtime whose access tokens live for one second")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto config = sqlite_registration_enabled_config(sqlite_path);
        config.security().access_token_lifetime_ms = 1000LL;

        WHEN("a token is issued, the runtime restarts, and the token's lifetime passes")
        {
            auto access_token = std::string{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                access_token =
                    json_string_field(register_and_login_with_refresh(started.runtime, "expiring"), "access_token");
                REQUIRE(merovingian::homeserver::handle_client_server_request(
                            started.runtime, {"GET", "/_matrix/client/v3/account/whoami", access_token, {}})
                            .response.status == 200U);
            }
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            std::this_thread::sleep_for(std::chrono::milliseconds{1500});
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                restarted.runtime, {"GET", "/_matrix/client/v3/account/whoami", access_token, {}});

            THEN("the expired token is refused")
            {
                REQUIRE(whoami.response.status == 401U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

// ADR-0074: a refresh whose response was lost can be retried even across a
// restart, because the new tokens' link to the refresh token they replace is
// persisted (migration 017).
SCENARIO("SQLite-backed runtime lets a lost refresh be retried after a restart",
         "[database][sqlite][homeserver][integration][refresh_rotation]")
{
    GIVEN("a user who refreshed once before the runtime restarted, and never saw the response")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);
        auto refresh_token = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            refresh_token =
                json_string_field(register_and_login_with_refresh(started.runtime, "rotating"), "refresh_token");
            REQUIRE(merovingian::homeserver::handle_client_server_request(
                        started.runtime, {"POST",
                                          "/_matrix/client/v3/refresh",
                                          {},
                                          std::string{R"({"refresh_token":")"} + refresh_token + R"("})"})
                        .response.status == 200U);
        }

        WHEN("the runtime restarts and the client retries the refresh with the same token")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto const retried = merovingian::homeserver::handle_client_server_request(
                restarted.runtime, {"POST",
                                    "/_matrix/client/v3/refresh",
                                    {},
                                    std::string{R"({"refresh_token":")"} + refresh_token + R"("})"});

            THEN("the retry succeeds")
            {
                REQUIRE(retried.response.status == 200U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite-backed runtime restores the event stream watermark so pos tokens survive restart",
         "[database][sqlite][homeserver][integration][sync]")
{
    // Regression: next_stream_ordering was rebuilt from max(events.stream_ordering)
    // alone, but membership stream positions consume orderings without a backing
    // event row. Every restart therefore rebuilt the counter LOWER than the
    // previous lifetime's, putting each client's persisted sliding sync pos ahead
    // of the live stream — all inbound events landed in the gap and were
    // permanently skipped (or, since 0.10.52, every client got M_UNKNOWN_POS and
    // a forced full resync on every server restart).
    GIVEN("a SQLite homeserver where a room join consumed non-event stream orderings")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);

        auto token = std::string{};
        auto pre_restart_next_ordering = std::uint64_t{0U};
        auto pos = std::string{};
        {
            auto started = merovingian::homeserver::start_client_server(config);
            REQUIRE(started.started);
            auto& runtime = started.runtime;

            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 R"({"username":"watermark","password":"CorrectHorse7!","auth":{"type":"m.login.registration_token","token":"test-registration-token"}})"});
            REQUIRE(registered.response.status == 200U);
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@watermark:example.org"},"password":"CorrectHorse7!","device_id":"WATERMARK1"})"});
            REQUIRE(login.response.status == 200U);
            token = token_from_login_body(login.response.body);
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            REQUIRE(room.response.status == 200U);

            // A sliding sync response encodes the live watermark into pos; the
            // client persists it across both app and server restarts.
            auto const sync = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/unstable/org.matrix.msc4186/sync?timeout=0", token,
                 R"({"conn_id":"watermark","lists":{"0":{"ranges":[[0,19]],"required_state":[],"timeline_limit":1}}})"});
            REQUIRE(sync.response.status == 200U);
            auto const pos_key = std::string{"\"pos\":\""};
            auto const pos_begin = sync.response.body.find(pos_key);
            REQUIRE(pos_begin != std::string::npos);
            auto const pos_value_begin = pos_begin + pos_key.size();
            auto const pos_value_end = sync.response.body.find('"', pos_value_begin);
            REQUIRE(pos_value_end != std::string::npos);
            pos = sync.response.body.substr(pos_value_begin, pos_value_end - pos_value_begin);

            pre_restart_next_ordering = runtime.homeserver.database.next_stream_ordering;
            REQUIRE(std::filesystem::exists(sqlite_path));
        }

        WHEN("the runtime is started again from the same SQLite file")
        {
            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& restarted_runtime = restarted.runtime;

            THEN("the stream ordering counter does not regress behind the previous lifetime")
            {
                REQUIRE(restarted_runtime.homeserver.database.next_stream_ordering >= pre_restart_next_ordering);
            }

            THEN("a sliding sync using the pre-restart pos is served, not rejected as unknown")
            {
                auto const resync = merovingian::homeserver::handle_client_server_request(
                    restarted_runtime,
                    {"POST", "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + pos + "&timeout=0", token,
                     R"({"conn_id":"watermark","lists":{"0":{"ranges":[[0,19]],"required_state":[],"timeline_limit":1}}})"});

                REQUIRE(resync.response.status == 200U);
                REQUIRE(resync.response.body.find("M_UNKNOWN_POS") == std::string::npos);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("SQLite-backed client-server runtime persists E2EE key API state across restart",
         "[database][sqlite][homeserver][key-api][integration]")
{
    GIVEN("a registration-enabled SQLite homeserver config")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto const config = sqlite_registration_enabled_config(sqlite_path);

        WHEN("a device uploads device, one-time, and fallback keys before restart")
        {
            auto token = std::string{};
            {
                auto started = merovingian::homeserver::start_client_server(config);
                REQUIRE(started.started);
                auto& runtime = started.runtime;

                auto const registered = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/v3/register",
                              {},
                              merovingian::tests::registration_json("keys", "CorrectHorse7!")});
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@keys:example.org"},"password":"CorrectHorse7!","device_id":"KEYS1"})"});
                token = token_from_login_body(login.response.body);
                // Real Ed25519 keypair required: OTK and fallback signatures
                // are now cryptographically verified server-side.
                auto const keys_kp = merovingian::federation::test::keypair_from_seed("persistent-keys-seed");
                auto const keys_ed25519 = merovingian::federation::test::pubkey_b64(keys_kp);
                auto const otk_json = merovingian::federation::test::make_signed_otk_json("@keys:example.org", "KEYS1",
                                                                                          "otk", keys_kp.secret_key);
                auto const fb_json = merovingian::federation::test::make_signed_fallback_key_json(
                    "@keys:example.org", "KEYS1", "fallback", keys_kp.secret_key);
                auto const keys_upload_body =
                    std::string{
                        R"({"device_keys":{"algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"device_id":"KEYS1","keys":{"curve25519:KEYS1":"curve-key","ed25519:KEYS1":")"} +
                    keys_ed25519 +
                    R"("},"signatures":{},"user_id":"@keys:example.org"},"one_time_keys":{"signed_curve25519:AAA":)" +
                    otk_json + R"(},"fallback_keys":{"signed_curve25519:FB":)" + fb_json + R"(}})";
                auto const upload = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/keys/upload", token, keys_upload_body});

                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(upload.response.status == 200U);
                REQUIRE(std::filesystem::exists(sqlite_path));
            }

            auto restarted = merovingian::homeserver::start_client_server(config);
            REQUIRE(restarted.started);
            auto& runtime = restarted.runtime;
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/keys/query", token, R"({"device_keys":{"@keys:example.org":["KEYS1"]}})"});
            auto const first_claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                          R"({"one_time_keys":{"@keys:example.org":{"KEYS1":"signed_curve25519"}}})"});
            auto const second_claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", token,
                          R"({"one_time_keys":{"@keys:example.org":{"KEYS1":"signed_curve25519"}}})"});

            THEN("device keys survive restart and fallback keys are reused after one-time keys are consumed")
            {
                REQUIRE(query.response.status == 200U);
                REQUIRE(first_claim.response.status == 200U);
                REQUIRE(second_claim.response.status == 200U);
                REQUIRE(query.response.body.find("m.megolm.v1.aes-sha2") != std::string::npos);
                REQUIRE(first_claim.response.body.find("otk") != std::string::npos);
                REQUIRE(second_claim.response.body.find("fallback") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.device_keys.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.one_time_keys.empty());
                REQUIRE(runtime.homeserver.database.persistent_store.fallback_keys.size() == 1U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent homeserver runtime bootstraps a fresh migrated schema", "[database][homeserver][integration]")
{
    GIVEN("registration-enabled config and no existing schema")
    {
        auto const config = registration_enabled_config();

        WHEN("the runtime starts")
        {
            auto const started = merovingian::homeserver::start_runtime(config);

            THEN("startup applies the current migration and validates required tables")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.database.opened);
                REQUIRE(started.runtime.database.schema_validated);
                REQUIRE(started.runtime.database.schema_version == merovingian::database::current_schema_version());
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "schema_migrations"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "access_tokens"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "membership"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "current_state"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "device_keys"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "key_backup_sessions"));
                REQUIRE(merovingian::homeserver::database_has_table(started.runtime.database, "admin_actions"));
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 17U);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.front().direction ==
                        merovingian::database::MigrationDirection::upgrade);
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.front().name ==
                        "initial_schema");
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.back().name ==
                        "token_rotation_lineage");
            }
        }
    }
}

SCENARIO("Persistent homeserver startup is idempotent for an already migrated schema",
         "[database][homeserver][integration]")
{
    GIVEN("an already migrated schema state")
    {
        auto const first = merovingian::database::open_persistent_store();
        REQUIRE(first.ok);

        WHEN("the runtime starts with that state")
        {
            auto const started =
                merovingian::homeserver::start_runtime(registration_enabled_config(), first.store.schema);

            THEN("startup validates compatibility without applying duplicate migrations")
            {
                REQUIRE(started.started);
                REQUIRE(started.runtime.database.persistent_store.schema.version ==
                        merovingian::database::current_schema_version());
                REQUIRE(started.runtime.database.persistent_store.schema.applied_migrations.size() == 17U);
            }
        }
    }
}

SCENARIO("Persistent homeserver startup fails closed on schema mismatch", "[database][homeserver][integration]")
{
    GIVEN("a future incompatible schema state")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto future = opened.store.schema;
        future.version = merovingian::database::current_schema_version() + 1U;

        WHEN("the runtime starts")
        {
            auto const started = merovingian::homeserver::start_runtime(registration_enabled_config(), future);

            THEN("the runtime rejects traffic before serving")
            {
                REQUIRE_FALSE(started.started);
                REQUIRE(started.reason == "database schema validation failed");
            }
        }
    }
}

SCENARIO("Persistent homeserver store records the client-server flow",
         "[database][homeserver][client-server][integration]")
{
    GIVEN("a started client-server runtime with a master key configured")
    {
        auto started = merovingian::homeserver::start_client_server(
            registration_enabled_config_with_master_key(merovingian::tests::master_key_file()));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // AUTH-11: committed statements are not retained unless capture is
        // enabled, and the redaction check below reads the capture buffer.
        merovingian::database::enable_statement_capture(runtime.homeserver.database.persistent_store, 1024U);

        WHEN("a user registers logs in creates a room sends a message and logs out")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")});
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
            auto const token = token_from_login_body(login.response.body);
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const room_id = room_from_body(room.response.body);
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/rooms/" + room_id + "/send", token, R"({"type":"m.room.message"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/rooms/" + room_id + "/state", token, {}});
            auto const logout = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/logout", token, {}});
            auto const valid_store =
                merovingian::database::validate_persistent_store(runtime.homeserver.database.persistent_store);

            THEN("message events are durable without synthetic current-state rows")
            {
                REQUIRE(registered.response.status == 200U);
                REQUIRE(login.response.status == 200U);
                REQUIRE(room.response.status == 200U);
                REQUIRE(send.response.status == 200U);
                REQUIRE(state.response.status == 200U);
                REQUIRE(logout.response.status == 200U);
                REQUIRE(valid_store.valid);
                REQUIRE(runtime.homeserver.database.persistent_store.users.size() == 1U);
                // Spec §5.5.1: /register creates one device (alice_DEVICE) when
                // inhibit_login is absent. /login creates a second device (DEVICE1).
                REQUIRE(runtime.homeserver.database.persistent_store.devices.size() == 2U);
                // Two access tokens: one from the implicit registration session and
                // one from the explicit /login. /logout revokes the login token only.
                auto const& all_tokens = runtime.homeserver.database.persistent_store.access_tokens;
                REQUIRE(all_tokens.size() == 2U);
                // Exactly one token must be revoked (the one used for /logout).
                auto const revoked = std::count_if(all_tokens.begin(), all_tokens.end(), [](auto const& t) {
                    return t.revoked;
                });
                REQUIRE(revoked == 1U);
                // Both tokens must use the master-key-derived v4 hash format. With a master
                // key configured (#322), v3/v4 are available and v4 is preferred; v3 is now
                // master-key-derived (no longer the Ed25519 seed) and is not issued.
                auto const all_v4 = std::all_of(all_tokens.begin(), all_tokens.end(), [](auto const& t) {
                    return t.token_hash.find("token-hash:v4:") == 0U;
                });
                REQUIRE(all_v4);
                REQUIRE(runtime.homeserver.database.persistent_store.rooms.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.memberships.size() == 1U);
                REQUIRE(runtime.homeserver.database.persistent_store.events.size() == 8U);
                REQUIRE(runtime.homeserver.database.persistent_store.state.size() == 7U);
                REQUIRE(runtime.homeserver.database.persistent_store.audit_log.size() >= 6U);
                REQUIRE(
                    merovingian::database::sensitive_values_are_redacted(runtime.homeserver.database.persistent_store));
            }
        }
    }
}

// AUTH-1 follow-up: capping the in-memory audit window must not make moderators
// lose abuse reports. The admin listing reads the audit_log table, not the window.
SCENARIO("Admin safety-report listing keeps earlier reports after unauthenticated traffic fills the audit window",
         "[database][sqlite][homeserver][integration][audit][trust-safety][auth-1]")
{
    GIVEN("a SQLite-backed runtime with an admin and three submitted safety reports")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto started = merovingian::homeserver::start_client_server(sqlite_registration_enabled_config(sqlite_path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "alice", "CorrectHorse7!").ok);
        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEVICE1"})"});
        REQUIRE(login.response.status == 200U);
        auto const token = token_from_login_body(login.response.body);
        for (auto i = 1; i <= 3; ++i)
        {
            auto const report = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/!room:example.org/report/$event" + std::to_string(i), token,
                          R"({"reason":"spam","score":50})"});
            REQUIRE(report.response.status == 200U);
        }

        WHEN("1 100 unauthenticated rejections and 1 100 further audit rows follow, then the admin lists reports")
        {
            for (auto i = 0; i < 1100; ++i)
            {
                std::ignore = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET",
                              "/_matrix/client/v3/account/whoami",
                              "unknown-token-" + std::to_string(i),
                              {},
                              {},
                              "198.51.100." + std::to_string((i % 200) + 1)});
            }
            for (auto i = std::size_t{0U}; i < merovingian::database::max_in_memory_audit_events + 76U; ++i)
            {
                merovingian::homeserver::append_local_audit(
                    runtime.homeserver.database, merovingian::observability::AuditCategory::auth, "login.rejected",
                    "<unknown>", std::to_string(i), "403:unknown user");
            }
            auto const reports = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/admin/safety/reports", token, {}});

            THEN("the in-memory window no longer holds the reports but the listing still returns all three")
            {
                auto const& log = runtime.homeserver.database.persistent_store.audit_log;
                REQUIRE(std::ranges::none_of(log, [](auto const& event) {
                    return event.event_type.starts_with("trust_safety.");
                }));
                REQUIRE(reports.response.status == 200U);
                auto count = std::size_t{0U};
                auto const needle = std::string_view{"trust_safety.room.accept_report"};
                for (auto at = reports.response.body.find(needle); at != std::string::npos;
                     at = reports.response.body.find(needle, at + needle.size()))
                {
                    ++count;
                }
                REQUIRE(count == 3U);
                for (auto i = 1; i <= 3; ++i)
                {
                    REQUIRE(reports.response.body.find("$event" + std::to_string(i)) != std::string::npos);
                }
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}
