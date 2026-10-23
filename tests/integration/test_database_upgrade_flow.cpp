// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Upgrade path across releases (production milestone, "No tested upgrade path
// across releases"). A fresh database migrates from the v1 bootstrap, and a
// restart reopens a database already at the current version, so neither shows
// that rows an older release wrote survive the migrations and are served after
// them. These scenarios build a database at an older schema version, put that
// version's rows in it, and start the current runtime on it.
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/auth/password.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/crypto/ed25519.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/stored_room_version.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ios>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <libpq-fe.h>
#include <sodium.h>
#include <sqlite3.h>

namespace
{

// The schema version of 0.11.13, the last release of the previous minor
// series. Moves to the last 0.12 release's version when 0.13 starts.
constexpr auto previous_series_schema_version = std::uint32_t{11U};

constexpr auto legacy_user_id = std::string_view{"@legacy:example.org"};
constexpr auto legacy_password = std::string_view{"CorrectHorse7!"};

[[nodiscard]] auto unique_sqlite_path(std::string_view label) -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return merovingian::tests::temporary_directory() /
           ("merovingian-upgrade-" + std::string{label} + "-" + std::to_string(now) + ".sqlite3");
}

struct SqliteClose final
{
    auto operator()(sqlite3* connection) const noexcept -> void
    {
        sqlite3_close(connection);
    }
};

struct SqliteFinalize final
{
    auto operator()(sqlite3_stmt* statement) const noexcept -> void
    {
        sqlite3_finalize(statement);
    }
};

// Runs one statement with every value bound as text, so a value with quotes
// or `$` (a password hash) needs no escaping.
[[nodiscard]] auto sqlite_execute(std::filesystem::path const& path, std::string const& sql,
                                  std::vector<std::string> const& values) -> bool
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    if (opened != SQLITE_OK)
    {
        return false;
    }
    auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
    if (sqlite3_prepare_v2(connection.get(), sql.c_str(), -1, &raw_statement, nullptr) != SQLITE_OK)
    {
        return false;
    }
    auto const statement = std::unique_ptr<sqlite3_stmt, SqliteFinalize>{raw_statement};
    // A null destructor is SQLITE_STATIC (whose macro is an old-style cast):
    // `values` outlives the step, so SQLite need not copy them.
    for (auto index = std::size_t{0U}; index < values.size(); ++index)
    {
        if (sqlite3_bind_text(statement.get(), static_cast<int>(index + 1U), values[index].c_str(),
                              static_cast<int>(values[index].size()), nullptr) != SQLITE_OK)
        {
            return false;
        }
    }
    return sqlite3_step(statement.get()) == SQLITE_DONE;
}

struct PgFinish final
{
    auto operator()(PGconn* connection) const noexcept -> void
    {
        PQfinish(connection);
    }
};

struct PgClear final
{
    auto operator()(PGresult* result) const noexcept -> void
    {
        PQclear(result);
    }
};

[[nodiscard]] auto pg_execute(std::string const& conninfo, std::string const& sql,
                              std::vector<std::string> const& values = {}) -> bool
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    if (PQstatus(connection.get()) != CONNECTION_OK)
    {
        return false;
    }
    auto pointers = std::vector<char const*>{};
    std::ranges::transform(values, std::back_inserter(pointers), [](std::string const& value) {
        return value.c_str();
    });
    auto const result = std::unique_ptr<PGresult, PgClear>{
        PQexecParams(connection.get(), sql.c_str(), static_cast<int>(pointers.size()), nullptr,
                     pointers.empty() ? nullptr : pointers.data(), nullptr, nullptr, 0)};
    auto const status = PQresultStatus(result.get());
    return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
}

// Runs a whole SQL script (a pg_dump with no psql meta-commands) through the
// simple query protocol, which accepts many statements in one call.
[[nodiscard]] auto pg_execute_script(std::string const& conninfo, std::string const& script) -> bool
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    if (PQstatus(connection.get()) != CONNECTION_OK)
    {
        return false;
    }
    auto const result = std::unique_ptr<PGresult, PgClear>{PQexec(connection.get(), script.c_str())};
    auto const status = PQresultStatus(result.get());
    return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
}

// The server signing key the old release stored for example.org, read from its
// own database rather than the manifest: what the runtime must keep signing with.
struct FixtureSigningKey final
{
    std::string key_id{};
    std::string public_key{};
};

[[nodiscard]] auto sqlite_fixture_signing_key(std::filesystem::path const& path) -> FixtureSigningKey
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
    if (opened != SQLITE_OK ||
        sqlite3_prepare_v2(connection.get(),
                           "SELECT key_id, public_key FROM server_signing_keys WHERE server_name = 'example.org'", -1,
                           &raw_statement, nullptr) != SQLITE_OK)
    {
        return {};
    }
    auto const statement = std::unique_ptr<sqlite3_stmt, SqliteFinalize>{raw_statement};
    if (sqlite3_step(statement.get()) != SQLITE_ROW)
    {
        return {};
    }
    auto const text = [&statement](int column) {
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        auto const* value = reinterpret_cast<char const*>(sqlite3_column_text(statement.get(), column));
        return value == nullptr ? std::string{} : std::string{value};
    };
    return {text(0), text(1)};
}

[[nodiscard]] auto postgresql_fixture_signing_key(std::string const& conninfo) -> FixtureSigningKey
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    auto const result = std::unique_ptr<PGresult, PgClear>{PQexec(
        connection.get(), "SELECT key_id, public_key FROM server_signing_keys WHERE server_name = 'example.org'")};
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) != 1)
    {
        return {};
    }
    return {PQgetvalue(result.get(), 0, 0), PQgetvalue(result.get(), 0, 1)};
}

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

// The same server, another database. The store only looks for its schema in
// `public`, and the shared test database is already at the current version,
// so an older schema needs a database of its own.
[[nodiscard]] auto conninfo_for_database(std::string const& conninfo, std::string const& database) -> std::string
{
    auto const scheme = conninfo.find("://");
    if (scheme == std::string::npos)
    {
        // Keyword/value form: a later keyword overrides an earlier one.
        return conninfo + " dbname=" + database;
    }
    auto const path = conninfo.find('/', scheme + 3U);
    auto const query = conninfo.find('?', scheme + 3U);
    auto const authority_end = std::min(path, query);
    auto const rest = query == std::string::npos ? std::string{} : conninfo.substr(query);
    return conninfo.substr(0U, authority_end) + "/" + database + rest;
}

// Drops the scenario's database when the scenario ends, however it ends.
class ScratchPostgresqlDatabase final
{
public:
    explicit ScratchPostgresqlDatabase(std::string admin_conninfo)
        : admin_conninfo_{std::move(admin_conninfo)}
        , name_{"merovingian_upgrade_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
        , created_{pg_execute(admin_conninfo_, "CREATE DATABASE " + name_)}
    {
    }
    ScratchPostgresqlDatabase(ScratchPostgresqlDatabase const& other) = delete;
    auto operator=(ScratchPostgresqlDatabase const& other) -> ScratchPostgresqlDatabase& = delete;
    ScratchPostgresqlDatabase(ScratchPostgresqlDatabase&& other) = delete;
    auto operator=(ScratchPostgresqlDatabase&& other) -> ScratchPostgresqlDatabase& = delete;
    ~ScratchPostgresqlDatabase()
    {
        if (created_)
        {
            std::ignore = pg_execute(admin_conninfo_, "DROP DATABASE IF EXISTS " + name_ + " WITH (FORCE)");
        }
    }

    [[nodiscard]] auto created() const noexcept -> bool
    {
        return created_;
    }

    [[nodiscard]] auto conninfo() const -> std::string
    {
        return conninfo_for_database(admin_conninfo_, name_);
    }

private:
    std::string admin_conninfo_{};
    std::string name_{};
    bool created_{false};
};

// The rows a 0.11-series account leaves, in that series' column shapes: no
// `users.deactivated` (migration 14), no token lineage (migration 17). Values
// are bound with `?N` on SQLite and `$N` on PostgreSQL.
struct LegacyRow final
{
    std::string sqlite_sql{};
    std::string postgresql_sql{};
    std::vector<std::string> values{};
};

[[nodiscard]] auto legacy_account_rows(std::string const& password_hash) -> std::vector<LegacyRow>
{
    auto const user = std::string{legacy_user_id};
    return {
        {"INSERT INTO users (user_id, password_hash, locked, suspended, admin) VALUES (?1, ?2, 'false', 'false', "
         "'false')",                                                                              "INSERT INTO users (user_id, password_hash, locked, suspended, admin) VALUES ($1, $2, 'false', 'false', "
         "'false')",                                                          {user, password_hash}                                 },
        {"INSERT INTO devices (user_id, device_id, display_name) VALUES (?1, 'LEGACY1', 'Legacy device')",
         "INSERT INTO devices (user_id, device_id, display_name) VALUES ($1, 'LEGACY1', 'Legacy device')", {user}                                                },
        {"INSERT INTO profiles (user_id, displayname, avatar_url) VALUES (?1, 'Legacy User', '')",
         "INSERT INTO profiles (user_id, displayname, avatar_url) VALUES ($1, 'Legacy User', '')",         {user}                                                },
        {"INSERT INTO account_data (user_id, event_type, json, stream_id) VALUES (?1, ?2, ?3, '1')",
         "INSERT INTO account_data (user_id, event_type, json, stream_id) VALUES ($1, $2, $3, '1')",       {user, "org.merovingian.legacy", R"({"from":"0.11"})"}},
    };
}

[[nodiscard]] auto sqlite_config(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto postgresql_config(std::filesystem::path const& uri_file) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::postgresql;
    database.uri_file = uri_file.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},  database, security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// The runtime reads its database URI only from an owner-read-only file (ISO-7).
[[nodiscard]] auto write_uri_file(std::string const& conninfo) -> std::filesystem::path
{
    auto const path =
        merovingian::tests::temporary_directory() /
        ("merovingian-upgrade-uri-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    {
        auto output = std::ofstream{path};
        output << conninfo << '\n';
    }
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
    return path;
}

[[nodiscard]] auto json_string_field(std::string const& body, std::string_view name) -> std::string
{
    auto const key = "\"" + std::string{name} + "\":\"";
    auto const begin = body.find(key);
    if (begin == std::string::npos)
    {
        return {};
    }
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    return value_end == std::string::npos ? std::string{} : body.substr(value_begin, value_end - value_begin);
}

struct LegacyAccountView final
{
    unsigned login_status{0U};
    std::string login_user_id{};
    unsigned whoami_status{0U};
    std::string whoami_body{};
    unsigned displayname_status{0U};
    std::string displayname_body{};
    unsigned account_data_status{0U};
    std::string account_data_body{};
};

// What a client sees of the legacy account through the Client-Server API.
[[nodiscard]] auto view_legacy_account(merovingian::homeserver::ClientServerRuntime& runtime) -> LegacyAccountView
{
    auto view = LegacyAccountView{};
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")"} +
                      std::string{legacy_user_id} + R"("},"password":")" + std::string{legacy_password} +
                      R"(","device_id":"LEGACY1"})"});
    view.login_status = login.response.status;
    view.login_user_id = json_string_field(login.response.body, "user_id");
    auto const token = json_string_field(login.response.body, "access_token");

    auto const whoami = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/account/whoami", token, {}});
    view.whoami_status = whoami.response.status;
    view.whoami_body = whoami.response.body;

    auto const displayname = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET", "/_matrix/client/v3/profile/" + std::string{legacy_user_id} + "/displayname", token, {}});
    view.displayname_status = displayname.response.status;
    view.displayname_body = displayname.response.body;

    auto const account_data = merovingian::homeserver::handle_client_server_request(
        runtime, {"GET",
                  "/_matrix/client/v3/user/" + std::string{legacy_user_id} + "/account_data/org.merovingian.legacy",
                  token,
                  {}});
    view.account_data_status = account_data.response.status;
    view.account_data_body = account_data.response.body;
    return view;
}

auto require_legacy_account_served(LegacyAccountView const& view) -> void
{
    REQUIRE(view.login_status == 200U);
    REQUIRE(view.login_user_id == legacy_user_id);
    REQUIRE(view.whoami_status == 200U);
    REQUIRE(view.whoami_body.find(std::string{"\""} + std::string{legacy_user_id} + "\"") != std::string::npos);
    REQUIRE(view.displayname_status == 200U);
    REQUIRE(view.displayname_body.find("Legacy User") != std::string::npos);
    REQUIRE(view.account_data_status == 200U);
    REQUIRE(view.account_data_body.find(R"("from":"0.11")") != std::string::npos);
}

[[nodiscard]] auto has_table(merovingian::database::SchemaState const& state, std::string_view table) -> bool
{
    return std::ranges::find(state.tables, table) != state.tables.end();
}

// ---------------------------------------------------------------------------
// The previous release's own database (ADR-0216). tests/fixtures/upgrade/<release>/
// was written over HTTP by that release's server; manifest.json records what it
// was asked to store and the credentials to read it back with. Never regenerate it
// with current code.
// ---------------------------------------------------------------------------

constexpr auto previous_series_fixture_release = std::string_view{"0.11.13"};

[[nodiscard]] auto fixture_directory() -> std::filesystem::path
{
    return std::filesystem::path{MEROVINGIAN_TEST_SOURCE_ROOT} / "tests" / "fixtures" / "upgrade" /
           std::string{previous_series_fixture_release};
}

[[nodiscard]] auto read_binary_file(std::filesystem::path const& path) -> std::string
{
    auto input = std::ifstream{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

[[nodiscard]] auto string_at(merovingian::canonicaljson::Object const& object, std::string_view key) -> std::string
{
    auto const* value = merovingian::tests::string_member(object, key);
    return value == nullptr ? std::string{} : *value;
}

[[nodiscard]] auto object_at(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Object
{
    auto const* value = merovingian::tests::object_member_as_object(object, key);
    return value == nullptr ? merovingian::canonicaljson::Object{} : *value;
}

struct FixtureMessage final
{
    std::string event_id{};
    std::string body{};
};

// What one backend's run of the old release stored, as manifest.json records it.
struct FixtureExpectations final
{
    std::string master_key_hex{};
    std::string alice_user_id{};
    std::string alice_access_token{};
    std::string alice_device_id{};
    std::string bob_user_id{};
    std::string bob_password{};
    std::string displayname{};
    std::string private_room_id{};
    std::string public_room_id{};
    std::string alias{};
    std::vector<FixtureMessage> messages{};
    std::string media_mxc_uri{};
    std::string media_sha256{};
    std::string account_data_type{};
    std::string pushkey{};
    std::string device_ed25519_key{};
    std::string next_batch{};
};

[[nodiscard]] auto load_fixture_expectations(std::string_view backend) -> FixtureExpectations
{
    auto const manifest =
        merovingian::tests::parse_object_json(read_binary_file(fixture_directory() / "manifest.json"));
    auto const run = object_at(manifest, backend);
    auto const users = object_at(run, "users");
    auto const alice = object_at(users, "alice");
    auto const bob = object_at(users, "bob");
    auto expected = FixtureExpectations{};
    expected.master_key_hex = string_at(manifest, "master_key_hex");
    expected.alice_user_id = string_at(alice, "user_id");
    expected.alice_access_token = string_at(alice, "access_token");
    expected.alice_device_id = string_at(alice, "device_id");
    expected.bob_user_id = string_at(bob, "user_id");
    expected.bob_password = string_at(bob, "password");
    expected.displayname = string_at(run, "displayname");
    expected.private_room_id = string_at(run, "private_room_id");
    expected.public_room_id = string_at(run, "public_room_id");
    expected.alias = string_at(run, "alias");
    if (auto const* messages = merovingian::tests::object_member_as_array(run, "messages"); messages != nullptr)
    {
        for (auto const& message : *messages)
        {
            if (auto const* fields = std::get_if<merovingian::canonicaljson::Object>(&message.storage()))
            {
                expected.messages.push_back({string_at(*fields, "event_id"), string_at(*fields, "body")});
            }
        }
    }
    auto const media = object_at(run, "media");
    expected.media_mxc_uri = string_at(media, "mxc_uri");
    expected.media_sha256 = string_at(media, "sha256");
    expected.account_data_type = string_at(object_at(run, "account_data"), "type");
    expected.pushkey = string_at(object_at(run, "pusher"), "pushkey");
    expected.device_ed25519_key = string_at(object_at(run, "device_keys"), "ed25519_public_key");
    expected.next_batch = string_at(run, "next_batch");
    return expected;
}

// The old release encrypted its signing secret under this key, so the current
// runtime needs the same one to read it.
[[nodiscard]] auto write_fixture_master_key(std::string const& hex) -> std::filesystem::path
{
    auto key = std::vector<unsigned char>(crypto_generichash_KEYBYTES);
    auto length = std::size_t{0U};
    REQUIRE(sodium_hex2bin(key.data(), key.size(), hex.c_str(), hex.size(), nullptr, &length, nullptr) == 0);
    REQUIRE(length == key.size());
    auto const path = merovingian::tests::temporary_directory() /
                      ("merovingian-upgrade-fixture-master-" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + ".key");
    {
        auto output = std::ofstream{path, std::ios::binary};
        output.write(reinterpret_cast<char const*>(key.data()), static_cast<std::streamsize>(key.size()));
    }
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
    return path;
}

[[nodiscard]] auto sha256_hex(std::string const& bytes) -> std::string
{
    auto digest = std::vector<unsigned char>(crypto_hash_sha256_BYTES);
    crypto_hash_sha256(digest.data(), reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size());
    auto hex = std::string(digest.size() * 2U + 1U, '\0');
    sodium_bin2hex(hex.data(), hex.size(), digest.data(), digest.size());
    hex.resize(digest.size() * 2U);
    return hex;
}

[[nodiscard]] auto with_master_key(merovingian::config::Config config, std::filesystem::path const& master_key)
    -> merovingian::config::Config
{
    config.security().secrets.master_key_file = master_key.string();
    return config;
}

struct Response final
{
    unsigned status{0U};
    std::string body{};
};

// Everything a client can read back of the old release's data, and one write
// that needs the old signing secret. Not the room directory: 0.11 listed every
// room whose join rule was public and recorded no choice to publish, so an
// upgraded room is unlisted until re-published (owner decision, ADR-0216).
struct FixtureView final
{
    Response alice_whoami{};
    Response bob_login{};
    Response displayname{};
    Response account_data{};
    Response messages{};
    Response alias{};
    Response pushers{};
    Response media{};
    Response device_keys{};
    Response sync_since_old_token{};
    Response replay_old_transaction{};
    Response send_into_old_room{};
    Response read_new_event{};
};

[[nodiscard]] auto request(merovingian::homeserver::ClientServerRuntime& runtime, std::string method,
                           std::string target, std::string token, std::string body = {}) -> Response
{
    auto const handled = merovingian::homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), std::move(token), std::move(body)});
    return {handled.response.status, handled.response.body};
}

[[nodiscard]] auto view_fixture(merovingian::homeserver::ClientServerRuntime& runtime,
                                FixtureExpectations const& expected) -> FixtureView
{
    auto const& alice = expected.alice_access_token;
    auto const media_id = expected.media_mxc_uri.substr(expected.media_mxc_uri.rfind('/') + 1U);
    auto view = FixtureView{};
    view.alice_whoami = request(runtime, "GET", "/_matrix/client/v3/account/whoami", alice);
    view.bob_login = request(runtime, "POST", "/_matrix/client/v3/login", {},
                             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" +
                                 expected.bob_user_id + R"("},"password":")" + expected.bob_password + R"("})");
    view.displayname =
        request(runtime, "GET", "/_matrix/client/v3/profile/" + expected.alice_user_id + "/displayname", alice);
    view.account_data = request(
        runtime, "GET",
        "/_matrix/client/v3/user/" + expected.alice_user_id + "/account_data/" + expected.account_data_type, alice);
    view.messages = request(runtime, "GET",
                            "/_matrix/client/v3/rooms/" + expected.private_room_id + "/messages?dir=b&limit=50", alice);
    view.alias = request(runtime, "GET", "/_matrix/client/v3/directory/room/%23" + expected.alias.substr(1U), alice);
    view.pushers = request(runtime, "GET", "/_matrix/client/v3/pushers", alice);
    view.media = request(runtime, "GET", "/_matrix/client/v1/media/download/example.org/" + media_id, alice);
    view.device_keys = request(runtime, "POST", "/_matrix/client/v3/keys/query", alice,
                               R"({"device_keys":{")" + expected.alice_user_id + R"(":[]}})");
    view.sync_since_old_token =
        request(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&since=" + expected.next_batch, alice);
    // The old release sent the first fixture message as `upgrade-txn-1` from this
    // device, so repeating it must replay that event, not create one.
    view.replay_old_transaction = request(
        runtime, "PUT", "/_matrix/client/v3/rooms/" + expected.private_room_id + "/send/m.room.message/upgrade-txn-1",
        alice, R"({"msgtype":"m.text","body":")" + expected.messages.front().body + R"("})");
    // A transaction ID the old release never saw, so a new event is created and signed.
    view.send_into_old_room =
        request(runtime, "PUT",
                "/_matrix/client/v3/rooms/" + expected.private_room_id + "/send/m.room.message/after-upgrade-txn-1",
                alice, R"({"msgtype":"m.text","body":"sent after the upgrade"})");
    view.read_new_event = request(runtime, "GET",
                                  "/_matrix/client/v3/rooms/" + expected.private_room_id + "/event/" +
                                      json_string_field(view.send_into_old_room.body, "event_id"),
                                  alice);
    return view;
}

auto require_fixture_served(FixtureView const& view, FixtureExpectations const& expected) -> void
{
    // The old release's access token still authenticates: its hash format is read.
    REQUIRE(view.alice_whoami.status == 200U);
    REQUIRE(view.alice_whoami.body.find("\"" + expected.alice_user_id + "\"") != std::string::npos);
    // Its password hashes still verify.
    REQUIRE(view.bob_login.status == 200U);
    REQUIRE(view.displayname.status == 200U);
    REQUIRE(view.displayname.body.find(expected.displayname) != std::string::npos);
    REQUIRE(view.account_data.status == 200U);
    // The old release stored the client's JSON as sent, whitespace and all.
    REQUIRE(string_at(merovingian::tests::parse_object_json(view.account_data.body), "fixture") == "0.11.13");
    REQUIRE(view.messages.status == 200U);
    REQUIRE(expected.messages.size() == 4U);
    for (auto const& message : expected.messages)
    {
        INFO("message " << message.event_id);
        REQUIRE(view.messages.body.find(message.event_id) != std::string::npos);
        REQUIRE(view.messages.body.find(message.body) != std::string::npos);
    }
    REQUIRE(view.alias.status == 200U);
    REQUIRE(view.alias.body.find(expected.public_room_id) != std::string::npos);
    REQUIRE(view.pushers.status == 200U);
    REQUIRE(view.pushers.body.find(expected.pushkey) != std::string::npos);
    REQUIRE(view.media.status == 200U);
    REQUIRE(sha256_hex(view.media.body) == expected.media_sha256);
    REQUIRE(view.device_keys.status == 200U);
    REQUIRE(view.device_keys.body.find(expected.device_ed25519_key) != std::string::npos);
    // A client that synced against the old release carries on from its token.
    REQUIRE(view.sync_since_old_token.status == 200U);
    // The old release's transaction IDs still deduplicate: a retried send replays its event.
    REQUIRE(view.replay_old_transaction.status == 200U);
    REQUIRE(json_string_field(view.replay_old_transaction.body, "event_id") == expected.messages.front().event_id);
    // A new event in an old room needs the old signing secret, decrypted.
    REQUIRE(view.send_into_old_room.status == 200U);
    auto const new_event_id = json_string_field(view.send_into_old_room.body, "event_id");
    REQUIRE_FALSE(new_event_id.empty());
    REQUIRE(std::ranges::none_of(expected.messages, [&new_event_id](FixtureMessage const& message) {
        return message.event_id == new_event_id;
    }));
    REQUIRE(view.read_new_event.status == 200U);
    REQUIRE(view.read_new_event.body.find("sent after the upgrade") != std::string::npos);
}

// The event created after the upgrade carries example.org's signature under the
// old release's key ID, and that signature verifies against the old public key:
// the runtime decrypted the old secret rather than signing with a replacement.
auto require_signed_with_fixture_key(merovingian::homeserver::ClientServerRuntime& runtime,
                                     FixtureExpectations const& expected, FixtureView const& view,
                                     FixtureSigningKey const& key) -> void
{
    REQUIRE_FALSE(key.key_id.empty());
    REQUIRE_FALSE(key.public_key.empty());
    auto const& store = runtime.homeserver.database.persistent_store;
    auto const event_id = json_string_field(view.send_into_old_room.body, "event_id");
    auto const stored = store.events.find(event_id);
    REQUIRE(stored != store.events.end());
    auto const parsed = merovingian::canonicaljson::parse_lossless(stored->json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(event != nullptr);
    auto const* signatures = merovingian::tests::object_member_as_object(*event, "signatures");
    REQUIRE(signatures != nullptr);
    auto const* by_server = merovingian::tests::object_member_as_object(*signatures, "example.org");
    REQUIRE(by_server != nullptr);
    auto const* signature = merovingian::tests::string_member(*by_server, key.key_id);
    INFO("signing key " << key.key_id);
    REQUIRE(signature != nullptr);

    auto const* policy = merovingian::homeserver::stored_room_version_policy(store, expected.private_room_id);
    REQUIRE(policy != nullptr);
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value, *policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const verified = merovingian::crypto::ed25519_verify(
        merovingian::crypto::Ed25519PublicKey{merovingian::events::matrix_bytes_from_base64(key.public_key)},
        payload.output,
        merovingian::crypto::Ed25519Signature{merovingian::events::matrix_bytes_from_base64(*signature)});
    REQUIRE(verified.valid);
}

} // namespace

SCENARIO("A SQLite schema can be built at an older version and stops there", "[database][upgrade][sqlite]")
{
    GIVEN("no database file")
    {
        auto const path = unique_sqlite_path("stop");
        std::filesystem::remove(path);

        WHEN("the schema is migrated to the previous minor series' version")
        {
            auto const migrated =
                merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version);

            THEN("the schema is at that version, with that version's tables and none of a later one's")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == previous_series_schema_version);
                REQUIRE_FALSE(migrated.state.applied_migrations.empty());
                REQUIRE(migrated.state.applied_migrations.back().version == previous_series_schema_version);
                REQUIRE(has_table(migrated.state, "openid_tokens"));      // migration 10
                REQUIRE_FALSE(has_table(migrated.state, "login_tokens")); // migration 12
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite schema is never migrated past this build or backwards", "[database][upgrade][sqlite]")
{
    GIVEN("a database at the previous minor series' version")
    {
        auto const path = unique_sqlite_path("bounds");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version).ok);

        WHEN("it is asked for a version newer than this build knows")
        {
            auto const ahead = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version() + 1U);

            THEN("it refuses and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                auto const again =
                    merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version);
                REQUIRE(again.ok);
                REQUIRE(again.state.version == previous_series_schema_version);
            }
        }

        WHEN("it is asked for an older version than it holds")
        {
            auto const backwards = merovingian::database::migrate_sqlite_schema_to(path.string(), 5U);

            THEN("it refuses and the schema stays where it was")
            {
                REQUIRE_FALSE(backwards.ok);
                auto const again =
                    merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version);
                REQUIRE(again.ok);
                REQUIRE(again.state.version == previous_series_schema_version);
            }
        }

        WHEN("it is asked for version 0, which no schema has")
        {
            auto const zero = merovingian::database::migrate_sqlite_schema_to(path.string(), 0U);

            THEN("it refuses")
            {
                REQUIRE_FALSE(zero.ok);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite database that cannot be opened is refused", "[database][upgrade][sqlite]")
{
    GIVEN("a database path whose parent is a regular file, not a directory")
    {
        auto const parent = unique_sqlite_path("not-a-directory");
        {
            auto output = std::ofstream{parent};
            output << "not a directory" << '\n';
        }
        auto const path = parent / "merovingian.sqlite3";

        WHEN("the schema is migrated to an older version")
        {
            auto const migrated =
                merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version);

            THEN("it refuses and leaves the file as it was")
            {
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(std::filesystem::is_regular_file(parent));
            }
        }
        std::filesystem::remove(parent);
    }
}

// A schema the migrations do not expect (here, a column migration 14 adds that
// is already there) must stop the upgrade where it was: never record a step that
// did not apply, and never serve from a half-migrated schema.
SCENARIO("A SQLite schema the migrations do not expect stops the upgrade where it was", "[database][upgrade][sqlite]")
{
    GIVEN("a database at version 13 that already has the column migration 14 adds")
    {
        auto const path = unique_sqlite_path("unexpected");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), 13U).ok);
        REQUIRE(sqlite_execute(path, "ALTER TABLE users ADD COLUMN deactivated TEXT NOT NULL DEFAULT 'false'", {}));

        WHEN("it is migrated to version 14")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(path.string(), 14U);

            THEN("the migration fails and the schema is still at version 13")
            {
                REQUIRE_FALSE(migrated.ok);
                auto const again = merovingian::database::migrate_sqlite_schema_to(path.string(), 13U);
                REQUIRE(again.ok);
                REQUIRE(again.state.version == 13U);
            }
        }

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());

            THEN("the store refuses to open rather than serve a half-migrated schema")
            {
                REQUIRE_FALSE(opened.ok);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite database at any older schema version opens at the current version", "[database][upgrade][sqlite]")
{
    GIVEN("one database for every schema version older than this build's")
    {
        auto paths = std::vector<std::filesystem::path>{};
        for (auto version = std::uint32_t{1U}; version < merovingian::database::current_schema_version(); ++version)
        {
            auto path = unique_sqlite_path("v" + std::to_string(version));
            std::filesystem::remove(path);
            REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), version).ok);
            paths.push_back(std::move(path));
        }

        WHEN("each is opened as a persistent store")
        {
            auto versions = std::vector<std::uint32_t>{};
            for (auto const& path : paths)
            {
                auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
                versions.push_back(opened.ok ? opened.store.schema.version : 0U);
            }

            THEN("every one is migrated to the current version")
            {
                REQUIRE(versions.size() == paths.size());
                REQUIRE(std::ranges::all_of(versions, [](std::uint32_t version) {
                    return version == merovingian::database::current_schema_version();
                }));
            }
        }
        for (auto const& path : paths)
        {
            std::filesystem::remove(path);
        }
    }
}

SCENARIO("An account written at the previous minor series' SQLite schema is served after the upgrade",
         "[database][upgrade][sqlite][homeserver]")
{
    GIVEN("a SQLite database at the previous minor series' version holding that series' rows for one account")
    {
        auto const path = unique_sqlite_path("account");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), previous_series_schema_version).ok);
        auto const password_hash = merovingian::auth::hash_password(legacy_password);
        REQUIRE(password_hash.has_value());
        for (auto const& row : legacy_account_rows(*password_hash))
        {
            REQUIRE(sqlite_execute(path, row.sqlite_sql, row.values));
        }

        WHEN("the current runtime starts on it")
        {
            auto started = merovingian::homeserver::start_client_server(sqlite_config(path));
            REQUIRE(started.started);
            auto const view = view_legacy_account(started.runtime);

            THEN("the schema is current and the account logs in, with its profile and account data")
            {
                REQUIRE(started.runtime.homeserver.database.schema_version ==
                        merovingian::database::current_schema_version());
                require_legacy_account_served(view);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A PostgreSQL schema can be built at an older version and stops there",
         "[database][upgrade][postgresql][integration]")
{
    GIVEN("an empty PostgreSQL database")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());

        WHEN("the schema is migrated to the previous minor series' version")
        {
            auto const migrated =
                merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), previous_series_schema_version);

            THEN("the schema is at that version, with that version's tables and none of a later one's")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == previous_series_schema_version);
                REQUIRE(has_table(migrated.state, "openid_tokens"));
                REQUIRE_FALSE(has_table(migrated.state, "login_tokens"));
            }
        }
    }
}

SCENARIO("A PostgreSQL schema is never migrated past this build or backwards",
         "[database][upgrade][postgresql][integration]")
{
    GIVEN("a PostgreSQL database at the previous minor series' version")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(
            merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), previous_series_schema_version).ok);

        WHEN("it is asked for a version newer than this build knows, or for version 0")
        {
            auto const ahead = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version() + 1U);
            auto const zero = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 0U);

            THEN("both are refused and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                REQUIRE_FALSE(zero.ok);
                auto const again = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(),
                                                                                       previous_series_schema_version);
                REQUIRE(again.ok);
                REQUIRE(again.state.version == previous_series_schema_version);
            }
        }

        WHEN("it is asked for an older version than it holds")
        {
            auto const backwards = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 5U);

            THEN("it refuses and the schema stays where it was")
            {
                REQUIRE_FALSE(backwards.ok);
                REQUIRE(backwards.state.version == previous_series_schema_version);
            }
        }
    }
}

SCENARIO("A PostgreSQL schema the migrations do not expect stops the upgrade where it was",
         "[database][upgrade][postgresql][integration]")
{
    GIVEN("a PostgreSQL database at version 13 that already has the column migration 14 adds")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 13U).ok);
        REQUIRE(
            pg_execute(scratch.conninfo(), "ALTER TABLE users ADD COLUMN deactivated TEXT NOT NULL DEFAULT 'false'"));

        WHEN("it is migrated to version 14")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 14U);

            THEN("the migration fails and the schema is still at version 13")
            {
                REQUIRE_FALSE(migrated.ok);
                auto const again = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 13U);
                REQUIRE(again.ok);
                REQUIRE(again.state.version == 13U);
            }
        }
    }
}

SCENARIO("A PostgreSQL server that cannot be reached is refused", "[database][upgrade][postgresql]")
{
    GIVEN("a connection string for a loopback port with nothing listening")
    {
        auto const conninfo = std::string{"postgresql://merovingian_test@127.0.0.1:1/merovingian_test?sslmode=disable"};

        WHEN("the schema is migrated to an older version")
        {
            auto const migrated =
                merovingian::database::migrate_postgresql_schema_to(conninfo, previous_series_schema_version);

            THEN("it refuses")
            {
                REQUIRE_FALSE(migrated.ok);
            }
        }
    }
}

SCENARIO("An account written at the previous minor series' PostgreSQL schema is served after the upgrade",
         "[database][upgrade][postgresql][integration]")
{
    GIVEN("a PostgreSQL database at the previous minor series' version holding that series' rows for one account")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(
            merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), previous_series_schema_version).ok);
        auto const password_hash = merovingian::auth::hash_password(legacy_password);
        REQUIRE(password_hash.has_value());
        for (auto const& row : legacy_account_rows(*password_hash))
        {
            REQUIRE(pg_execute(scratch.conninfo(), row.postgresql_sql, row.values));
        }
        auto const uri_file = write_uri_file(scratch.conninfo());

        WHEN("the current runtime starts on it")
        {
            auto started = merovingian::homeserver::start_client_server(postgresql_config(uri_file));
            REQUIRE(started.started);
            auto const view = view_legacy_account(started.runtime);

            THEN("the schema is current and the account logs in, with its profile and account data")
            {
                REQUIRE(started.runtime.homeserver.database.schema_version ==
                        merovingian::database::current_schema_version());
                require_legacy_account_served(view);
            }
        }
        std::filesystem::remove(uri_file);
    }
}

SCENARIO("The previous release's own SQLite database is migrated and served by this build",
         "[database][upgrade][sqlite][homeserver][fixture]")
{
    GIVEN("a copy of the SQLite database the previous minor series' last release wrote, and its master key")
    {
        auto const expected = load_fixture_expectations("sqlite");
        auto const path = unique_sqlite_path("fixture");
        std::filesystem::copy_file(fixture_directory() / "merovingian.sqlite3", path,
                                   std::filesystem::copy_options::overwrite_existing);
        std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        auto const master_key = write_fixture_master_key(expected.master_key_hex);
        auto const signing_key = sqlite_fixture_signing_key(path);

        WHEN("the current runtime starts on it")
        {
            auto started =
                merovingian::homeserver::start_client_server(with_master_key(sqlite_config(path), master_key));
            REQUIRE(started.started);
            auto const view = view_fixture(started.runtime, expected);

            THEN("the schema is current and every account, room, message, media item and setting it held is served")
            {
                REQUIRE(started.runtime.homeserver.database.schema_version ==
                        merovingian::database::current_schema_version());
                require_fixture_served(view, expected);
                require_signed_with_fixture_key(started.runtime, expected, view, signing_key);
            }
        }
        std::filesystem::remove(path);
        std::filesystem::remove(master_key);
    }
}

SCENARIO("The previous release's own PostgreSQL database is migrated and served by this build",
         "[database][upgrade][postgresql][integration][fixture]")
{
    GIVEN("a PostgreSQL database restored from the dump the previous minor series' last release wrote")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const expected = load_fixture_expectations("postgresql");
        auto const scratch = ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(pg_execute_script(scratch.conninfo(), read_binary_file(fixture_directory() / "postgresql.sql")));
        auto const uri_file = write_uri_file(scratch.conninfo());
        auto const master_key = write_fixture_master_key(expected.master_key_hex);
        auto const signing_key = postgresql_fixture_signing_key(scratch.conninfo());

        WHEN("the current runtime starts on it")
        {
            auto started =
                merovingian::homeserver::start_client_server(with_master_key(postgresql_config(uri_file), master_key));
            REQUIRE(started.started);
            auto const view = view_fixture(started.runtime, expected);

            THEN("the schema is current and every account, room, message, media item and setting it held is served")
            {
                REQUIRE(started.runtime.homeserver.database.schema_version ==
                        merovingian::database::current_schema_version());
                require_fixture_served(view, expected);
                require_signed_with_fixture_key(started.runtime, expected, view, signing_key);
            }
        }
        std::filesystem::remove(uri_file);
        std::filesystem::remove(master_key);
    }
}
