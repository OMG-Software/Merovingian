// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// The schema's upgrade path (ADR-0216, ADR-0224, ADR-0778). Every pre-1.0
// migration is collapsed into the one v1 step and 1.1.0 adds migration 002 (the
// OAuth 2.0 tables), so these scenarios show what the path does: a database is
// built at v1 exactly as 1.0.x built it, a v1 database is migrated to the
// current version and then holds exactly the schema a fresh one does, the
// forward-only seam (migrate_*_schema_to) never moves past this build or
// backwards, and a database a pre-1.0 build created is refused rather than
// misread. The 1.0.3 release's own databases (tests/fixtures/upgrade/1.0.3/)
// are opened, migrated and served at the end of the file: opening one applies
// the v1 to v2 step, and what the manifest lists is still served afterwards.
#include "../support/JsonTestSupport.hpp"
#include "../support/TempDirectory.hpp"
#include "ScratchPostgresqlDatabase.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/crypto/Ed25519.hpp"
#include "merovingian/crypto/Ed25519PublicKey.hpp"
#include "merovingian/crypto/Ed25519Signature.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PostgresqlStore.hpp"
#include "merovingian/database/Schema.hpp"
#include "merovingian/database/SchemaState.hpp"
#include "merovingian/events/EventSigner.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/StoredRoomVersion.hpp"
#include "merovingian/sync/StreamToken.hpp"

#include <catch2/catch_test_macros.hpp>
#include <libpq-fe.h>
#include <sodium.h>
#include <sqlite3.h>

#include <algorithm>
#include <array>
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
#include <utility>
#include <variant>
#include <vector>

namespace
{

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

// Prepares one statement on a connection that creates the file if it is
// missing, with every value bound as text.
class SqliteQuery final
{
public:
    SqliteQuery(std::filesystem::path const& path, std::string const& sql, std::vector<std::string> values)
        : values_{std::move(values)}
    {
        auto* raw = static_cast<sqlite3*>(nullptr);
        auto const opened =
            sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        connection_ = std::unique_ptr<sqlite3, SqliteClose>{raw};
        if (opened != SQLITE_OK)
        {
            return;
        }
        auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
        if (sqlite3_prepare_v2(connection_.get(), sql.c_str(), -1, &raw_statement, nullptr) != SQLITE_OK)
        {
            return;
        }
        statement_ = std::unique_ptr<sqlite3_stmt, SqliteFinalize>{raw_statement};
        // A null destructor is SQLITE_STATIC (whose macro is an old-style cast):
        // `values_` outlives every step, so SQLite need not copy them.
        for (auto index = std::size_t{0U}; index < values_.size(); ++index)
        {
            if (sqlite3_bind_text(statement_.get(), static_cast<int>(index + 1U), values_[index].c_str(),
                                  static_cast<int>(values_[index].size()), nullptr) != SQLITE_OK)
            {
                statement_.reset();
                return;
            }
        }
    }

    // One step: true when it ran to completion.
    [[nodiscard]] auto execute() -> bool
    {
        return statement_ != nullptr && sqlite3_step(statement_.get()) == SQLITE_DONE;
    }

    // The first column of every row, as text.
    [[nodiscard]] auto first_column_texts() -> std::vector<std::string>
    {
        auto texts = std::vector<std::string>{};
        while (statement_ != nullptr && sqlite3_step(statement_.get()) == SQLITE_ROW)
        {
            auto const* text = sqlite3_column_text(statement_.get(), 0);
            texts.emplace_back(text == nullptr ? "" : reinterpret_cast<char const*>(text));
        }
        return texts;
    }

    // The first column of the first row as an integer, or -1 when there is none.
    [[nodiscard]] auto first_integer() -> std::int64_t
    {
        if (statement_ == nullptr || sqlite3_step(statement_.get()) != SQLITE_ROW)
        {
            return -1;
        }
        return sqlite3_column_int64(statement_.get(), 0);
    }

private:
    std::vector<std::string> values_{};
    std::unique_ptr<sqlite3, SqliteClose> connection_{};
    std::unique_ptr<sqlite3_stmt, SqliteFinalize> statement_{};
};

[[nodiscard]] auto sqlite_execute(std::filesystem::path const& path, std::string const& sql,
                                  std::vector<std::string> values = {}) -> bool
{
    return SqliteQuery{path, sql, std::move(values)}.execute();
}

[[nodiscard]] auto sqlite_count(std::filesystem::path const& path, std::string const& sql,
                                std::vector<std::string> values = {}) -> std::int64_t
{
    return SqliteQuery{path, sql, std::move(values)}.first_integer();
}

// Every table and index SQLite records, as its type, name and normalised DDL, in a fixed order.
[[nodiscard]] auto sqlite_schema_shape(std::filesystem::path const& path) -> std::vector<std::string>
{
    return SqliteQuery{path,
                       "SELECT type || ' ' || name || ' ' || coalesce(sql, '') FROM sqlite_master "
                       "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
                       {}}
        .first_column_texts();
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

[[nodiscard]] auto pg_query(std::string const& conninfo, std::string const& sql, std::vector<std::string> const& values)
    -> std::unique_ptr<PGresult, PgClear>
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    if (PQstatus(connection.get()) != CONNECTION_OK)
    {
        return {};
    }
    auto pointers = std::vector<char const*>{};
    std::ranges::transform(values, std::back_inserter(pointers), [](std::string const& value) {
        return value.c_str();
    });
    return std::unique_ptr<PGresult, PgClear>{
        PQexecParams(connection.get(), sql.c_str(), static_cast<int>(pointers.size()), nullptr,
                     pointers.empty() ? nullptr : pointers.data(), nullptr, nullptr, 0)};
}

[[nodiscard]] auto pg_execute(std::string const& conninfo, std::string const& sql,
                              std::vector<std::string> const& values = {}) -> bool
{
    auto const result = pg_query(conninfo, sql, values);
    auto const status = PQresultStatus(result.get());
    return status == PGRES_COMMAND_OK || status == PGRES_TUPLES_OK;
}

// The first column of the first row as an integer, or -1 when there is none.
[[nodiscard]] auto pg_count(std::string const& conninfo, std::string const& sql,
                            std::vector<std::string> const& values = {}) -> std::int64_t
{
    auto const result = pg_query(conninfo, sql, values);
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) < 1)
    {
        return -1;
    }
    return std::stoll(PQgetvalue(result.get(), 0, 0));
}

// The first column of every row, as text; empty when the query fails.
[[nodiscard]] auto pg_texts(std::string const& conninfo, std::string const& sql) -> std::vector<std::string>
{
    auto const result = pg_query(conninfo, sql, {});
    auto texts = std::vector<std::string>{};
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK)
    {
        return texts;
    }
    for (auto row = 0; row < PQntuples(result.get()); ++row)
    {
        texts.emplace_back(PQgetvalue(result.get(), row, 0));
    }
    return texts;
}

// Every column (with its type, nullability and default) and every index definition of the public schema.
[[nodiscard]] auto pg_schema_shape(std::string const& conninfo) -> std::vector<std::string>
{
    auto shape = pg_texts(conninfo, "SELECT table_name || '.' || column_name || ' ' || data_type || ' ' || is_nullable "
                                    "|| ' ' || coalesce(column_default, '') FROM information_schema.columns WHERE "
                                    "table_schema = 'public' ORDER BY table_name, column_name");
    auto indexes = pg_texts(conninfo, "SELECT indexdef FROM pg_indexes WHERE schemaname = 'public' ORDER BY indexname");
    shape.insert(shape.end(), std::make_move_iterator(indexes.begin()), std::make_move_iterator(indexes.end()));
    return shape;
}

[[nodiscard]] auto postgresql_uri_from_environment() -> std::string
{
    auto const* value = std::getenv("MEROVINGIAN_TEST_POSTGRESQL_URI");
    return value == nullptr ? std::string{} : std::string{value};
}

[[nodiscard]] auto has_table(merovingian::database::SchemaState const& state, std::string_view table) -> bool
{
    return std::ranges::find(state.tables, table) != state.tables.end();
}

// Columns the pre-1.0 chain ALTERed onto an existing table, which the v1 step
// now creates with the table.
struct FoldedColumn final
{
    std::string table{};
    std::string column{};
};

[[nodiscard]] auto folded_columns() -> std::vector<FoldedColumn>
{
    return {
        {"account_threepids",  "client_secret"           },
        {"account_threepids",  "sid"                     },
        {"pushers",            "data_extra_json"         },
        {"users",              "deactivated"             },
        {"events",             "status"                  },
        {"state_groups",       "parent_state_group_id"   },
        {"state_groups",       "delta_depth"             },
        {"media",              "legacy_endpoint_visible" },
        {"media",              "upload_name"             },
        {"refresh_tokens",     "predecessor_hash"        },
        {"access_tokens",      "predecessor_refresh_hash"},
        {"rooms",              "directory_public"        },
        {"to_device_messages", "created_at_ms"           },
        {"remote_media",       "local_media_id"          },
        {"remote_media",       "fetched_at_ms"           },
        {"room_aliases",       "creator_user_id"         },
    };
}

constexpr auto v1_index_names = std::array{
    std::string_view{"event_edges_prev_event_id"}, std::string_view{"idx_to_device_messages_recipient_age"},
    std::string_view{"idx_deferred_pdus_room_id"}, std::string_view{"idx_media_pending_uploads_owner"},
    std::string_view{"idx_events_room_id"},        std::string_view{"idx_state_groups_room_id"},
};

// Versions 2 to 26 of the ledger every pre-1.0 build up to 0.12.46 wrote, after
// its v1 row (also named initial_schema).
constexpr auto pre_collapse_step_names = std::array{
    std::string_view{"sync_stream_watermark"},
    std::string_view{"event_stream_watermark"},
    std::string_view{"state_transitions"},
    std::string_view{"backfill_state_transitions"},
    std::string_view{"account_threepids"},
    std::string_view{"account_threepids_columns"},
    std::string_view{"pushers"},
    std::string_view{"notifications"},
    std::string_view{"openid_tokens"},
    std::string_view{"pushers_data_extra"},
    std::string_view{"login_tokens"},
    std::string_view{"appservice_txn_cursor"},
    std::string_view{"user_deactivation"},
    std::string_view{"event_graph_state"},
    std::string_view{"media_legacy_endpoint_visibility"},
    std::string_view{"token_rotation_lineage"},
    std::string_view{"room_directory_visibility"},
    std::string_view{"to_device_queue_age_bound"},
    std::string_view{"remote_media_cache_mapping"},
    std::string_view{"room_alias_creator"},
    std::string_view{"appservice_outbox"},
    std::string_view{"deferred_pdus"},
    std::string_view{"receipts"},
    std::string_view{"appservice_directory"},
    std::string_view{"media_upload_names_and_pending_uploads"},
};

constexpr auto pre_collapse_ledger_rows = static_cast<std::int64_t>(pre_collapse_step_names.size() + 1U);

// ---------------------------------------------------------------------------
// The previous series' last release's own database (ADR-0216).
// tests/fixtures/upgrade/<release>/ was written over HTTP by that release's
// server; manifest.json records what it was asked to store and the credentials
// to read it back with. Nothing below names an ID, token or key: every value
// comes from the manifest. Never regenerate the fixture with current code.
// ---------------------------------------------------------------------------

constexpr auto previous_series_fixture_release = std::string_view{"1.0.3"};

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

struct FixtureUser final
{
    std::string user_id{};
    std::string password{};
    std::string device_id{};
    std::string access_token{};
};

struct FixtureMessage final
{
    std::string sender{};
    std::string event_id{};
    std::string body{};
};

// What one backend's run of the old release stored, as manifest.json records it.
struct FixtureExpectations final
{
    std::string release{};
    std::int64_t schema_version{0};
    std::string server_name{};
    std::string master_key_hex{};
    FixtureUser alice{};
    FixtureUser bob{};
    std::string displayname{};
    std::string private_room_id{};
    std::string public_room_id{};
    std::string alias{};
    std::vector<FixtureMessage> messages{};
    std::string media_mxc_uri{};
    std::string media_sha256{};
    std::string account_data_type{};
    std::string account_data_fixture_value{};
    std::string pushkey{};
    std::string device_ed25519_key{};
    std::string next_batch{};
    std::size_t non_2xx_steps{0U};
};

[[nodiscard]] auto fixture_user_at(merovingian::canonicaljson::Object const& users, std::string_view name)
    -> FixtureUser
{
    auto const user = object_at(users, name);
    return {string_at(user, "user_id"), string_at(user, "password"), string_at(user, "device_id"),
            string_at(user, "access_token")};
}

[[nodiscard]] auto load_fixture_expectations(std::string_view backend) -> FixtureExpectations
{
    auto const manifest =
        merovingian::tests::parse_object_json(read_binary_file(fixture_directory() / "manifest.json"));
    auto const run = object_at(manifest, backend);
    auto const users = object_at(run, "users");
    auto expected = FixtureExpectations{};
    expected.release = string_at(manifest, "release");
    if (auto const* version = merovingian::tests::int_member(manifest, "schema_version"); version != nullptr)
    {
        expected.schema_version = *version;
    }
    expected.server_name = string_at(manifest, "server_name");
    expected.master_key_hex = string_at(manifest, "master_key_hex");
    expected.alice = fixture_user_at(users, "alice");
    expected.bob = fixture_user_at(users, "bob");
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
                expected.messages.push_back(
                    {string_at(*fields, "sender"), string_at(*fields, "event_id"), string_at(*fields, "body")});
            }
        }
    }
    auto const media = object_at(run, "media");
    expected.media_mxc_uri = string_at(media, "mxc_uri");
    expected.media_sha256 = string_at(media, "sha256");
    auto const account_data = object_at(run, "account_data");
    expected.account_data_type = string_at(account_data, "type");
    expected.account_data_fixture_value = string_at(object_at(account_data, "content"), "fixture");
    expected.pushkey = string_at(object_at(run, "pusher"), "pushkey");
    expected.device_ed25519_key = string_at(object_at(run, "device_keys"), "ed25519_public_key");
    expected.next_batch = string_at(run, "next_batch");
    if (auto const* non_2xx = merovingian::tests::object_member_as_array(run, "non_2xx"); non_2xx != nullptr)
    {
        expected.non_2xx_steps = non_2xx->size();
    }
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
    auto const path = merovingian::tests::unique_temporary_path("merovingian-upgrade-fixture-master", ".key");
    {
        auto output = std::ofstream{path, std::ios::binary};
        REQUIRE(output.is_open());
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        output.write(reinterpret_cast<char const*>(key.data()), static_cast<std::streamsize>(key.size()));
        output.close();
        REQUIRE_FALSE(output.fail());
    }
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
    return path;
}

[[nodiscard]] auto sha256_hex(std::string const& bytes) -> std::string
{
    auto digest = std::vector<unsigned char>(crypto_hash_sha256_BYTES);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    crypto_hash_sha256(digest.data(), reinterpret_cast<unsigned char const*>(bytes.data()), bytes.size());
    auto hex = std::string(digest.size() * 2U + 1U, '\0');
    sodium_bin2hex(hex.data(), hex.size(), digest.data(), digest.size());
    hex.resize(digest.size() * 2U);
    return hex;
}

[[nodiscard]] auto fixture_config(merovingian::config::DatabaseConfig database, std::filesystem::path const& master_key,
                                  std::string const& server_name) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = server_name;
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = master_key.string();
    return {server,   merovingian::config::ListenersConfig{},        std::move(database),
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto sqlite_fixture_config(std::filesystem::path const& path, std::filesystem::path const& master_key,
                                         std::string const& server_name) -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    return fixture_config(std::move(database), master_key, server_name);
}

[[nodiscard]] auto postgresql_fixture_config(std::filesystem::path const& uri_file,
                                             std::filesystem::path const& master_key, std::string const& server_name)
    -> merovingian::config::Config
{
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::postgresql;
    database.uri_file = uri_file.string();
    return fixture_config(std::move(database), master_key, server_name);
}

// The runtime reads its database URI only from an owner-read-only file (ISO-7).
[[nodiscard]] auto write_uri_file(std::string const& conninfo) -> std::filesystem::path
{
    auto const path = merovingian::tests::unique_temporary_path("merovingian-upgrade-uri", "");
    {
        auto output = std::ofstream{path};
        REQUIRE(output.is_open());
        output << conninfo << '\n';
        output.close();
        REQUIRE_FALSE(output.fail());
    }
    std::filesystem::permissions(path, std::filesystem::perms::owner_read);
    return path;
}

// Runs a whole dump (plain SQL, no COPY, no psql meta-commands) in one PQexec.
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

// The server signing key the old release stored for the server, read from its
// own database rather than the manifest: what the runtime must keep signing with.
struct FixtureSigningKey final
{
    std::string key_id{};
    std::string public_key{};
};

[[nodiscard]] auto sqlite_fixture_signing_key(std::filesystem::path const& path, std::string const& server_name)
    -> FixtureSigningKey
{
    auto* raw = static_cast<sqlite3*>(nullptr);
    auto const opened = sqlite3_open_v2(path.string().c_str(), &raw, SQLITE_OPEN_READONLY, nullptr);
    auto const connection = std::unique_ptr<sqlite3, SqliteClose>{raw};
    auto* raw_statement = static_cast<sqlite3_stmt*>(nullptr);
    if (opened != SQLITE_OK ||
        sqlite3_prepare_v2(connection.get(),
                           "SELECT key_id, public_key FROM server_signing_keys WHERE server_name = ?1", -1,
                           &raw_statement, nullptr) != SQLITE_OK)
    {
        return {};
    }
    auto const statement = std::unique_ptr<sqlite3_stmt, SqliteFinalize>{raw_statement};
    if (sqlite3_bind_text(statement.get(), 1, server_name.c_str(), static_cast<int>(server_name.size()), nullptr) !=
            SQLITE_OK ||
        sqlite3_step(statement.get()) != SQLITE_ROW)
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

[[nodiscard]] auto postgresql_fixture_signing_key(std::string const& conninfo, std::string const& server_name)
    -> FixtureSigningKey
{
    auto const connection = std::unique_ptr<PGconn, PgFinish>{PQconnectdb(conninfo.c_str())};
    auto const* values = server_name.c_str();
    auto const result = std::unique_ptr<PGresult, PgClear>{
        PQexecParams(connection.get(), "SELECT key_id, public_key FROM server_signing_keys WHERE server_name = $1", 1,
                     nullptr, &values, nullptr, nullptr, 0)};
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK || PQntuples(result.get()) != 1)
    {
        return {};
    }
    return {PQgetvalue(result.get(), 0, 0), PQgetvalue(result.get(), 0, 1)};
}

struct Response final
{
    unsigned status{0U};
    std::string body{};
};

[[nodiscard]] auto request(merovingian::homeserver::ClientServerRuntime& runtime, std::string method,
                           std::string target, std::string token, std::string body = {}) -> Response
{
    auto const handled = merovingian::homeserver::handle_client_server_request(
        runtime, {std::move(method), std::move(target), std::move(token), std::move(body)});
    return {handled.response.status, handled.response.body};
}

[[nodiscard]] auto json_string_field(std::string const& body, std::string_view name) -> std::string
{
    return string_at(merovingian::tests::parse_object_json(body), name);
}

// Everything a client can read back of the old release's data, and writes that
// need its signing secret. Not the room directory: it is checked by neither
// release's fixture run beyond the old server's own read-back.
struct FixtureView final
{
    Response alice_whoami{};
    Response bob_whoami{};
    Response bob_login{};
    Response displayname{};
    Response account_data{};
    Response messages{};
    Response members{};
    Response alias{};
    Response pushers{};
    Response media{};
    Response device_keys{};
    Response sync_since_old_token{};
    Response initial_sync{};
    Response replay_old_transaction{};
    Response send_into_old_room{};
    Response read_new_event{};
};

[[nodiscard]] auto view_fixture(merovingian::homeserver::ClientServerRuntime& runtime,
                                FixtureExpectations const& expected) -> FixtureView
{
    auto const& alice = expected.alice.access_token;
    auto const media_id = expected.media_mxc_uri.substr(expected.media_mxc_uri.rfind('/') + 1U);
    auto const private_room = "/_matrix/client/v3/rooms/" + expected.private_room_id;
    auto view = FixtureView{};
    view.alice_whoami = request(runtime, "GET", "/_matrix/client/v3/account/whoami", alice);
    view.bob_whoami = request(runtime, "GET", "/_matrix/client/v3/account/whoami", expected.bob.access_token);
    view.bob_login = request(runtime, "POST", "/_matrix/client/v3/login", {},
                             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" +
                                 expected.bob.user_id + R"("},"password":")" + expected.bob.password + R"("})");
    view.displayname =
        request(runtime, "GET", "/_matrix/client/v3/profile/" + expected.alice.user_id + "/displayname", alice);
    view.account_data = request(
        runtime, "GET",
        "/_matrix/client/v3/user/" + expected.alice.user_id + "/account_data/" + expected.account_data_type, alice);
    view.messages = request(runtime, "GET", private_room + "/messages?dir=b&limit=50", alice);
    view.members = request(runtime, "GET", private_room + "/joined_members", alice);
    view.alias = request(runtime, "GET", "/_matrix/client/v3/directory/room/%23" + expected.alias.substr(1U), alice);
    view.pushers = request(runtime, "GET", "/_matrix/client/v3/pushers", alice);
    view.media =
        request(runtime, "GET", "/_matrix/client/v1/media/download/" + expected.server_name + "/" + media_id, alice);
    view.device_keys = request(runtime, "POST", "/_matrix/client/v3/keys/query", alice,
                               R"({"device_keys":{")" + expected.alice.user_id + R"(":[]}})");
    view.sync_since_old_token =
        request(runtime, "GET", "/_matrix/client/v3/sync?timeout=0&since=" + expected.next_batch, alice);
    // The control: a sync with no token, which must replay the room's timeline.
    view.initial_sync = request(runtime, "GET", "/_matrix/client/v3/sync?timeout=0", alice);
    // The old release sent the first fixture message as `upgrade-txn-1` from this
    // device, so repeating it must replay that event, not create one.
    view.replay_old_transaction = request(runtime, "PUT", private_room + "/send/m.room.message/upgrade-txn-1", alice,
                                          R"({"msgtype":"m.text","body":")" + expected.messages.front().body + R"("})");
    // A transaction ID the old release never saw, so a new event is created and signed.
    view.send_into_old_room = request(runtime, "PUT", private_room + "/send/m.room.message/after-upgrade-txn-1", alice,
                                      R"({"msgtype":"m.text","body":"sent after the upgrade"})");
    view.read_new_event = request(
        runtime, "GET", private_room + "/event/" + json_string_field(view.send_into_old_room.body, "event_id"), alice);
    return view;
}

auto require_fixture_served(FixtureView const& view, FixtureExpectations const& expected) -> void
{
    // The old release wrote a clean, complete run: it is the manifest that says what to expect.
    REQUIRE(expected.release == previous_series_fixture_release);
    REQUIRE(expected.non_2xx_steps == 0U);
    REQUIRE_FALSE(expected.alice.access_token.empty());
    REQUIRE_FALSE(expected.bob.access_token.empty());
    // Both users' old access tokens still authenticate: their hash format is read.
    REQUIRE(view.alice_whoami.status == 200U);
    REQUIRE(json_string_field(view.alice_whoami.body, "user_id") == expected.alice.user_id);
    REQUIRE(json_string_field(view.alice_whoami.body, "device_id") == expected.alice.device_id);
    REQUIRE(view.bob_whoami.status == 200U);
    REQUIRE(json_string_field(view.bob_whoami.body, "user_id") == expected.bob.user_id);
    // Its password hashes still verify.
    REQUIRE(view.bob_login.status == 200U);
    REQUIRE(json_string_field(view.bob_login.body, "user_id") == expected.bob.user_id);
    REQUIRE(view.displayname.status == 200U);
    REQUIRE(json_string_field(view.displayname.body, "displayname") == expected.displayname);
    REQUIRE(view.account_data.status == 200U);
    REQUIRE(json_string_field(view.account_data.body, "fixture") == expected.account_data_fixture_value);
    REQUIRE(view.messages.status == 200U);
    REQUIRE_FALSE(expected.messages.empty());
    for (auto const& message : expected.messages)
    {
        INFO("message " << message.event_id);
        REQUIRE(view.messages.body.find(message.event_id) != std::string::npos);
        REQUIRE(view.messages.body.find(message.body) != std::string::npos);
        REQUIRE(view.messages.body.find(message.sender) != std::string::npos);
    }
    REQUIRE(view.members.status == 200U);
    REQUIRE(view.members.body.find(expected.alice.user_id) != std::string::npos);
    REQUIRE(view.members.body.find(expected.bob.user_id) != std::string::npos);
    REQUIRE(view.alias.status == 200U);
    REQUIRE(json_string_field(view.alias.body, "room_id") == expected.public_room_id);
    REQUIRE(view.pushers.status == 200U);
    REQUIRE(view.pushers.body.find(expected.pushkey) != std::string::npos);
    REQUIRE(view.media.status == 200U);
    REQUIRE(sha256_hex(view.media.body) == expected.media_sha256);
    REQUIRE(view.device_keys.status == 200U);
    REQUIRE(view.device_keys.body.find(expected.device_ed25519_key) != std::string::npos);
    // A client that synced against the old release carries on from its token. A token whose epoch is not the
    // store's is served as an initial sync, also with a 200 (src/sync/AGENTS.md), so the status alone would pass a
    // migration that replaced the stream token epoch. Prove the answer is incremental and the epoch survived.
    REQUIRE(view.sync_since_old_token.status == 200U);
    REQUIRE(view.initial_sync.status == 200U);
    for (auto const& message : expected.messages)
    {
        INFO("message " << message.event_id);
        // The control replays what the old release had already delivered; the answer to the old token must not.
        REQUIRE(view.initial_sync.body.find(message.event_id) != std::string::npos);
        REQUIRE(view.sync_since_old_token.body.find(message.event_id) == std::string::npos);
    }
    auto const old_token = merovingian::sync::decode_stream_token(expected.next_batch);
    REQUIRE(old_token.has_value());
    REQUIRE(old_token->epoch != 0U);
    auto const new_token =
        merovingian::sync::decode_stream_token(json_string_field(view.sync_since_old_token.body, "next_batch"));
    REQUIRE(new_token.has_value());
    REQUIRE(new_token->epoch == old_token->epoch);
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

// The event created after the upgrade carries the server's signature under the
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
    auto const* by_server = merovingian::tests::object_member_as_object(*signatures, expected.server_name);
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

SCENARIO("A SQLite schema is built at v1 and stops there", "[database][upgrade][sqlite]")
{
    GIVEN("no database file")
    {
        auto const path = unique_sqlite_path("stop");
        std::filesystem::remove(path);

        WHEN("the schema is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(path.string(), 1U);

            THEN("the schema is at v1, recorded by one ledger row, with every v1 table and no later one")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == 1U);
                REQUIRE(migrated.state.applied_migrations.size() == 1U);
                REQUIRE(migrated.state.applied_migrations.front().name == "initial_schema");
                for (auto const table : merovingian::database::initial_schema_tables())
                {
                    INFO("table " << table);
                    REQUIRE(has_table(migrated.state, table));
                }
                REQUIRE_FALSE(has_table(migrated.state, "oauth_clients"));
                REQUIRE_FALSE(has_table(migrated.state, "oauth_sessions"));
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'oauth%'") == 0);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite schema is never migrated past this build", "[database][upgrade][sqlite]")
{
    GIVEN("a database at the current version")
    {
        auto const path = unique_sqlite_path("bounds");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(),
                                                                merovingian::database::current_schema_version())
                    .ok);

        WHEN("it is asked for a version newer than this build knows")
        {
            auto const ahead = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version() + 1U);

            THEN("it refuses and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                auto const again = merovingian::database::migrate_sqlite_schema_to(
                    path.string(), merovingian::database::current_schema_version());
                REQUIRE(again.ok);
                REQUIRE(again.state.version == merovingian::database::current_schema_version());
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

        WHEN("the schema is migrated to the current version")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version());

            THEN("it refuses and leaves the file as it was")
            {
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(std::filesystem::is_regular_file(parent));
            }
        }
        std::filesystem::remove(parent);
    }
}

// Tables the v1 step did not create, with no ledger to say what they are, must
// not be adopted: the step fails on them, records nothing, and nothing is served.
SCENARIO("A SQLite database holding tables but no schema ledger is refused, not adopted", "[database][upgrade][sqlite]")
{
    GIVEN("a SQLite database with a users table of another shape and no schema_migrations")
    {
        auto const path = unique_sqlite_path("unexpected");
        std::filesystem::remove(path);
        REQUIRE(sqlite_execute(path, "CREATE TABLE users (name TEXT)"));

        WHEN("it is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(path.string(), 1U);

            THEN("the migration fails and records no ledger")
            {
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE name = 'schema_migrations'") == 0);
            }
        }

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());

            THEN("the store refuses to open rather than serve a schema it did not build")
            {
                REQUIRE_FALSE(opened.ok);
            }
        }
        std::filesystem::remove(path);
    }
}

// Covers nothing while v1 is the only version; it starts to test every forward
// migration as soon as a v2 exists.
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

SCENARIO("A SQLite database migrated from v1 holds exactly the schema a fresh one does",
         "[database][upgrade][sqlite][oauth]")
{
    GIVEN("a database built at v1 and no fresh database yet")
    {
        auto const migrated_path = unique_sqlite_path("v1-to-current");
        auto const fresh_path = unique_sqlite_path("fresh-current");
        std::filesystem::remove(migrated_path);
        std::filesystem::remove(fresh_path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(migrated_path.string(), 1U).ok);

        WHEN("the v1 database and a fresh one are each opened as a persistent store")
        {
            auto const migrated = merovingian::database::open_sqlite_persistent_store(migrated_path.string());
            auto const fresh = merovingian::database::open_sqlite_persistent_store(fresh_path.string());

            THEN("migration 002 ran on the v1 database, both tables are empty, and the two schemas are identical")
            {
                REQUIRE(migrated.ok);
                REQUIRE(fresh.ok);
                REQUIRE(migrated.store.schema.version == merovingian::database::current_schema_version());
                REQUIRE(migrated.store.schema.applied_migrations.back().name == "oauth_tables");
                REQUIRE(sqlite_count(migrated_path, "SELECT count(*) FROM schema_migrations") == 2);
                REQUIRE(sqlite_count(migrated_path, "SELECT count(*) FROM oauth_clients") == 0);
                REQUIRE(sqlite_count(migrated_path, "SELECT count(*) FROM oauth_sessions") == 0);
                REQUIRE(migrated.store.oauth.client_count() == 0U);
                auto const migrated_shape = sqlite_schema_shape(migrated_path);
                REQUIRE_FALSE(migrated_shape.empty());
                REQUIRE(migrated_shape == sqlite_schema_shape(fresh_path));
                REQUIRE(sqlite_count(migrated_path, "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND "
                                                    "name = 'idx_oauth_sessions_client_id'") == 1);
            }
        }
        std::filesystem::remove(migrated_path);
        std::filesystem::remove(fresh_path);
    }
}

SCENARIO("A fresh SQLite database has every column and index of the v1 schema", "[database][upgrade][sqlite][collapse]")
{
    GIVEN("no database file")
    {
        auto const path = unique_sqlite_path("shape");
        std::filesystem::remove(path);

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
            REQUIRE(opened.ok);

            THEN("each column the pre-1.0 chain added later is already on its table")
            {
                for (auto const& [table, column] : folded_columns())
                {
                    INFO("table " << table << " column " << column);
                    REQUIRE(sqlite_count(path, "SELECT count(*) FROM pragma_table_info(?1) WHERE name = ?2",
                                         {table, column}) == 1);
                }
            }

            AND_THEN("each index the store's lookups rely on exists")
            {
                for (auto const index : v1_index_names)
                {
                    INFO("index " << index);
                    REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                                         {std::string{index}}) == 1);
                }
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A SQLite database a pre-1.0 build created is refused, not upgraded",
         "[database][upgrade][sqlite][collapse][security]")
{
    GIVEN("a SQLite database whose ledger records the 26 migrations a pre-1.0 build applied")
    {
        auto const path = unique_sqlite_path("pre-collapse");
        std::filesystem::remove(path);
        REQUIRE(merovingian::database::migrate_sqlite_schema_to(path.string(), 1U).ok);
        for (auto index = std::size_t{0U}; index < pre_collapse_step_names.size(); ++index)
        {
            REQUIRE(sqlite_execute(path, "INSERT INTO schema_migrations VALUES (?1, ?2, 'upgrade')",
                                   {std::to_string(index + 2U), std::string{pre_collapse_step_names[index]}}));
        }

        WHEN("it is opened as a persistent store, or migrated")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(path.string());
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version());

            THEN("both refuse, the open says why, and the ledger is left as it was")
            {
                REQUIRE_FALSE(opened.ok);
                INFO("reason: " << opened.reason);
                REQUIRE(opened.reason.find("migration this build does not have") != std::string::npos);
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM schema_migrations") == pre_collapse_ledger_rows);
            }
        }
        std::filesystem::remove(path);
    }
}

SCENARIO("A PostgreSQL schema is built at v1 and stops there", "[database][upgrade][postgresql][integration]")
{
    GIVEN("an empty PostgreSQL database")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());

        WHEN("the schema is migrated to v1")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 1U);

            THEN("the schema is at v1, recorded by one ledger row, with every v1 table and no later one")
            {
                REQUIRE(migrated.ok);
                REQUIRE(migrated.state.version == 1U);
                REQUIRE(migrated.state.applied_migrations.size() == 1U);
                for (auto const table : merovingian::database::initial_schema_tables())
                {
                    INFO("table " << table);
                    REQUIRE(has_table(migrated.state, table));
                }
                REQUIRE_FALSE(has_table(migrated.state, "oauth_clients"));
                REQUIRE_FALSE(has_table(migrated.state, "oauth_sessions"));
                REQUIRE(pg_count(scratch.conninfo(), "SELECT count(*) FROM information_schema.tables WHERE "
                                                     "table_schema = 'public' AND table_name LIKE 'oauth%'") == 0);
            }
        }
    }
}

SCENARIO("A PostgreSQL schema is never migrated past this build", "[database][upgrade][postgresql][integration]")
{
    GIVEN("a PostgreSQL database at the current version")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(),
                                                                    merovingian::database::current_schema_version())
                    .ok);

        WHEN("it is asked for a version newer than this build knows, or for version 0")
        {
            auto const ahead = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version() + 1U);
            auto const zero = merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 0U);

            THEN("both are refused and the schema stays where it was")
            {
                REQUIRE_FALSE(ahead.ok);
                REQUIRE_FALSE(zero.ok);
                auto const again = merovingian::database::migrate_postgresql_schema_to(
                    scratch.conninfo(), merovingian::database::current_schema_version());
                REQUIRE(again.ok);
                REQUIRE(again.state.version == merovingian::database::current_schema_version());
            }
        }
    }
}

// libpq reads a URI's query after its path, so a dbname there would send the
// "scratch" connection back to the shared database (PR #536 review).
SCENARIO("A scratch database's connection string names only the scratch database", "[database][postgresql][scratch]")
{
    GIVEN("connection strings for the shared database, some naming it again in the query")
    {
        auto const cases = std::vector<std::pair<std::string, std::string>>{
            {"postgresql://scratch_user@db.test:5432/shared?dbname=shared&sslmode=disable",
             "postgresql://scratch_user@db.test:5432/scratch?sslmode=disable"                                                         },
            {"postgresql://db.test/shared?sslmode=require&%64bname=shared&connect_timeout=5",
             "postgresql://db.test/scratch?sslmode=require&connect_timeout=5"                                                         },
            {"postgresql://db.test/shared?dbname=shared",                                     "postgresql://db.test/scratch"          },
            {"postgres://db.test?dbname=shared",                                              "postgres://db.test/scratch"            },
            {"postgresql://db.test/shared",                                                   "postgresql://db.test/scratch"          },
            {"postgresql://db.test/shared?dbnamex=1",                                         "postgresql://db.test/scratch?dbnamex=1"},
        };

        WHEN("each is pointed at the scratch database")
        {
            THEN("the path names it and no query parameter names another")
            {
                for (auto const& [shared, expected] : cases)
                {
                    INFO("conninfo " << shared);
                    REQUIRE(merovingian::tests::conninfo_for_database(shared, "scratch") == expected);
                }
            }

            AND_THEN("a keyword/value string gets the scratch dbname last, which libpq uses")
            {
                REQUIRE(merovingian::tests::conninfo_for_database("host=db.test dbname=shared", "scratch") ==
                        "host=db.test dbname=shared dbname=scratch");
                // Only a postgresql:// or postgres:// prefix makes a URI (PR #536 review): a
                // "://" inside a keyword's value does not.
                REQUIRE(merovingian::tests::conninfo_for_database(
                            "host=db.test dbname=shared application_name=ci://worker", "scratch") ==
                        "host=db.test dbname=shared application_name=ci://worker dbname=scratch");
                REQUIRE(merovingian::tests::conninfo_for_database("host=db.test dbname=shared options='x://y'",
                                                                  "scratch") ==
                        "host=db.test dbname=shared options='x://y' dbname=scratch");
            }
        }
    }
}

SCENARIO("A PostgreSQL server that cannot be reached is refused", "[database][upgrade][postgresql]")
{
    GIVEN("a connection string for a loopback port with nothing listening")
    {
        auto const conninfo = std::string{"postgresql://merovingian_test@127.0.0.1:1/merovingian_test?sslmode=disable"};

        WHEN("the schema is migrated to the current version")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(
                conninfo, merovingian::database::current_schema_version());

            THEN("it refuses")
            {
                REQUIRE_FALSE(migrated.ok);
            }
        }
    }
}

SCENARIO("A PostgreSQL database migrated from v1 holds exactly the schema a fresh one does",
         "[database][upgrade][postgresql][integration][oauth]")
{
    GIVEN("a database built at v1 and an empty one")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const migrated_scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        auto const fresh_scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(migrated_scratch.created());
        REQUIRE(fresh_scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(migrated_scratch.conninfo(), 1U).ok);

        WHEN("each is opened as a persistent store")
        {
            auto const migrated = merovingian::database::open_postgresql_persistent_store(migrated_scratch.conninfo());
            auto const fresh = merovingian::database::open_postgresql_persistent_store(fresh_scratch.conninfo());

            THEN("migration 002 ran on the v1 database, both tables are empty, and the two schemas are identical")
            {
                INFO("migrated: " << migrated.reason << " fresh: " << fresh.reason);
                REQUIRE(migrated.ok);
                REQUIRE(fresh.ok);
                REQUIRE(migrated.store.schema.version == merovingian::database::current_schema_version());
                REQUIRE(pg_count(migrated_scratch.conninfo(), "SELECT count(*) FROM schema_migrations") == 2);
                REQUIRE(pg_count(migrated_scratch.conninfo(), "SELECT count(*) FROM oauth_clients") == 0);
                REQUIRE(pg_count(migrated_scratch.conninfo(), "SELECT count(*) FROM oauth_sessions") == 0);
                auto const migrated_shape = pg_schema_shape(migrated_scratch.conninfo());
                REQUIRE_FALSE(migrated_shape.empty());
                REQUIRE(migrated_shape == pg_schema_shape(fresh_scratch.conninfo()));
            }
        }
    }
}

SCENARIO("A fresh PostgreSQL database has every column and index of the v1 schema",
         "[database][upgrade][postgresql][integration][collapse]")
{
    GIVEN("an empty PostgreSQL database")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());

        WHEN("it is opened as a persistent store")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(scratch.conninfo());
            INFO("open refused: " << opened.reason);
            REQUIRE(opened.ok);

            THEN("each column the pre-1.0 chain added later is already on its table")
            {
                for (auto const& [table, column] : folded_columns())
                {
                    INFO("table " << table << " column " << column);
                    REQUIRE(pg_count(scratch.conninfo(),
                                     "SELECT count(*) FROM information_schema.columns WHERE table_schema = 'public' "
                                     "AND table_name = $1 AND column_name = $2",
                                     {table, column}) == 1);
                }
            }

            AND_THEN("each index the store's lookups rely on exists")
            {
                for (auto const index : v1_index_names)
                {
                    INFO("index " << index);
                    REQUIRE(pg_count(scratch.conninfo(),
                                     "SELECT count(*) FROM pg_indexes WHERE schemaname = 'public' AND indexname = $1",
                                     {std::string{index}}) == 1);
                }
            }
        }
    }
}

SCENARIO("A PostgreSQL database a pre-1.0 build created is refused, not upgraded",
         "[database][upgrade][postgresql][integration][collapse][security]")
{
    GIVEN("a PostgreSQL database whose ledger records the 26 migrations a pre-1.0 build applied")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(merovingian::database::migrate_postgresql_schema_to(scratch.conninfo(), 1U).ok);
        for (auto index = std::size_t{0U}; index < pre_collapse_step_names.size(); ++index)
        {
            REQUIRE(pg_execute(scratch.conninfo(), "INSERT INTO schema_migrations VALUES ($1, $2, 'upgrade')",
                               {std::to_string(index + 2U), std::string{pre_collapse_step_names[index]}}));
        }

        WHEN("it is opened as a persistent store, or migrated")
        {
            auto const opened = merovingian::database::open_postgresql_persistent_store(scratch.conninfo());
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version());

            THEN("both refuse, the open says why, and the ledger is left as it was")
            {
                REQUIRE_FALSE(opened.ok);
                INFO("reason: " << opened.reason);
                REQUIRE(opened.reason.find("migration this build does not have") != std::string::npos);
                REQUIRE_FALSE(migrated.ok);
                REQUIRE(pg_count(scratch.conninfo(), "SELECT count(*) FROM schema_migrations") ==
                        pre_collapse_ledger_rows);
            }
        }
    }
}

SCENARIO("The 1.0.3 release's own SQLite database is migrated and served by this build",
         "[database][upgrade][sqlite][homeserver][fixture]")
{
    GIVEN("a copy of the SQLite database the last 1.0.x release wrote, and its master key")
    {
        auto const expected = load_fixture_expectations("sqlite");
        auto const path = merovingian::tests::unique_temporary_path("merovingian-upgrade-fixture", ".sqlite3");
        std::filesystem::copy_file(fixture_directory() / "merovingian.sqlite3", path,
                                   std::filesystem::copy_options::overwrite_existing);
        std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
        auto const master_key = write_fixture_master_key(expected.master_key_hex);
        auto const signing_key = sqlite_fixture_signing_key(path, expected.server_name);
        // The release wrote schema v1: one ledger row, and none of version 2's tables.
        auto const ledger_rows_before = sqlite_count(path, "SELECT count(*) FROM schema_migrations");
        auto const oauth_objects_before =
            sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE name LIKE 'oauth%'");

        WHEN("the migration path runs on it and the current runtime starts on the result")
        {
            auto const migrated = merovingian::database::migrate_sqlite_schema_to(
                path.string(), merovingian::database::current_schema_version());
            // Version 2's tables take a row and give it back; the runtime is not started yet, so nothing else holds the
            // file.
            auto const oauth_tables_usable =
                sqlite_execute(path, "INSERT INTO oauth_clients VALUES ('upgrade-probe', '{}', '0', '0')") &&
                sqlite_count(path, "SELECT count(*) FROM oauth_clients WHERE client_id = 'upgrade-probe'") == 1 &&
                sqlite_execute(path, "DELETE FROM oauth_clients WHERE client_id = 'upgrade-probe'");
            auto started = merovingian::homeserver::start_client_server(
                sqlite_fixture_config(path, master_key, expected.server_name));
            REQUIRE(started.started);
            auto const view = view_fixture(started.runtime, expected);

            THEN(
                "the v1 to v2 step ran, version 2's tables are usable, and everything the old release stored is served")
            {
                REQUIRE(migrated.ok);
                REQUIRE(expected.schema_version == 1);
                REQUIRE(ledger_rows_before == 1);
                REQUIRE(oauth_objects_before == 0);
                REQUIRE(migrated.state.version == merovingian::database::current_schema_version());
                REQUIRE(static_cast<std::int64_t>(migrated.state.version) > expected.schema_version);
                REQUIRE(static_cast<std::int64_t>(migrated.state.applied_migrations.size()) > ledger_rows_before);
                REQUIRE(migrated.state.applied_migrations.back().name == "oauth_tables");
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM schema_migrations") ==
                        static_cast<std::int64_t>(migrated.state.applied_migrations.size()));
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM oauth_clients") == 0);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM oauth_sessions") == 0);
                REQUIRE(sqlite_count(path, "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND "
                                           "name = 'idx_oauth_sessions_client_id'") == 1);
                REQUIRE(oauth_tables_usable);
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

SCENARIO("The 1.0.3 release's own PostgreSQL database is migrated and served by this build",
         "[database][upgrade][postgresql][integration][homeserver][fixture]")
{
    GIVEN("a PostgreSQL database restored from the dump the last 1.0.x release wrote")
    {
        auto const uri = postgresql_uri_from_environment();
        if (uri.empty())
        {
            SUCCEED("skipped: MEROVINGIAN_TEST_POSTGRESQL_URI is not set");
            return;
        }
        auto const expected = load_fixture_expectations("postgresql");
        auto const scratch = merovingian::tests::ScratchPostgresqlDatabase{uri};
        REQUIRE(scratch.created());
        REQUIRE(pg_execute_script(scratch.conninfo(), read_binary_file(fixture_directory() / "postgresql.sql")));
        auto const uri_file = write_uri_file(scratch.conninfo());
        auto const master_key = write_fixture_master_key(expected.master_key_hex);
        auto const signing_key = postgresql_fixture_signing_key(scratch.conninfo(), expected.server_name);
        // The release wrote schema v1: one ledger row, and none of version 2's tables.
        auto const ledger_rows_before = pg_count(scratch.conninfo(), "SELECT count(*) FROM schema_migrations");
        auto const oauth_tables_before =
            pg_count(scratch.conninfo(), "SELECT count(*) FROM information_schema.tables WHERE "
                                         "table_schema = 'public' AND table_name LIKE 'oauth%'");

        WHEN("the migration path runs on it and the current runtime starts on the result")
        {
            auto const migrated = merovingian::database::migrate_postgresql_schema_to(
                scratch.conninfo(), merovingian::database::current_schema_version());
            // Version 2's tables take a row and give it back; the runtime is not started yet.
            auto const oauth_tables_usable =
                pg_execute(scratch.conninfo(), "INSERT INTO oauth_clients VALUES ('upgrade-probe', '{}', '0', '0')") &&
                pg_count(scratch.conninfo(), "SELECT count(*) FROM oauth_clients WHERE client_id = 'upgrade-probe'") ==
                    1 &&
                pg_execute(scratch.conninfo(), "DELETE FROM oauth_clients WHERE client_id = 'upgrade-probe'");
            auto started = merovingian::homeserver::start_client_server(
                postgresql_fixture_config(uri_file, master_key, expected.server_name));
            REQUIRE(started.started);
            auto const view = view_fixture(started.runtime, expected);

            THEN(
                "the v1 to v2 step ran, version 2's tables are usable, and everything the old release stored is served")
            {
                REQUIRE(migrated.ok);
                REQUIRE(expected.schema_version == 1);
                REQUIRE(ledger_rows_before == 1);
                REQUIRE(oauth_tables_before == 0);
                REQUIRE(migrated.state.version == merovingian::database::current_schema_version());
                REQUIRE(static_cast<std::int64_t>(migrated.state.version) > expected.schema_version);
                REQUIRE(static_cast<std::int64_t>(migrated.state.applied_migrations.size()) > ledger_rows_before);
                REQUIRE(migrated.state.applied_migrations.back().name == "oauth_tables");
                REQUIRE(pg_count(scratch.conninfo(), "SELECT count(*) FROM schema_migrations") ==
                        static_cast<std::int64_t>(migrated.state.applied_migrations.size()));
                REQUIRE(oauth_tables_usable);
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
