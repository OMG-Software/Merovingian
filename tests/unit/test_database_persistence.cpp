// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/connection.hpp"
#include "merovingian/database/migration.hpp"
#include "merovingian/database/migration_files.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/database/schema.hpp"
#include "merovingian/database/statement.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include <sqlite3.h>

namespace
{

[[nodiscard]] auto locate_repository_migrations_directory() -> std::filesystem::path
{
    auto candidate = std::filesystem::current_path();
    while (!candidate.empty())
    {
        auto const migrations = candidate / "migrations";
        if (std::filesystem::exists(migrations / "001_initial_schema.sql"))
        {
            return migrations;
        }
        auto const parent = candidate.parent_path();
        if (parent == candidate)
        {
            break;
        }
        candidate = parent;
    }
    return {};
}

class RecordingExecutor final : public merovingian::database::DatabaseExecutor
{
public:
    [[nodiscard]] auto execute(merovingian::database::PreparedStatement const& statement)
        -> merovingian::database::QueryResult override
    {
        executed_statement_names_.push_back(statement.name);
        return {true, {}, {{"ok"}}};
    }

    [[nodiscard]] auto executed_statement_names() const noexcept -> std::vector<std::string> const&
    {
        return executed_statement_names_;
    }

private:
    std::vector<std::string> executed_statement_names_{};
};

[[nodiscard]] auto create_users_statement() -> merovingian::database::PreparedStatement
{
    return {"create_users", "CREATE TABLE users (user_id TEXT PRIMARY KEY)", {}};
}

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-transaction-unit-" + std::to_string(now) + ".sqlite3");
}

} // namespace

SCENARIO("Database statement validation enforces prepared statement shape", "[database]")
{
    GIVEN("valid and invalid prepared statements")
    {
        auto const valid_statement = merovingian::database::PreparedStatement{
            "select_user_by_id",
            "SELECT id FROM users WHERE id = $1",
            {merovingian::database::BoundValue{"@alice:example.org", false}},
        };
        auto const invalid_name =
            merovingian::database::PreparedStatement{"select-user", "SELECT id FROM users WHERE id = $1", {}};
        auto const unsafe_sql =
            merovingian::database::PreparedStatement{"select_user", "SELECT id FROM users; SELECT id FROM devices", {}};

        WHEN("the statements are validated")
        {
            auto const valid_result = merovingian::database::prepared_statement_is_valid(valid_statement);
            auto const invalid_name_result = merovingian::database::prepared_statement_is_valid(invalid_name);
            auto const unsafe_sql_result = merovingian::database::prepared_statement_is_valid(unsafe_sql);

            THEN("only the bounded prepared statement shape is accepted")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(invalid_name_result.valid);
                REQUIRE(invalid_name_result.reason == "invalid statement name");
                REQUIRE_FALSE(unsafe_sql_result.valid);
                REQUIRE(unsafe_sql_result.reason == "SQL shape is not allowed");
            }
        }
    }
}

SCENARIO("Database statement validation allows SET and RESET role switching SQL", "[database]")
{
    GIVEN("SET ROLE and RESET ROLE statements with no placeholders")
    {
        auto const set_role =
            merovingian::database::PreparedStatement{"set_postgresql_role", R"(SET ROLE "merovingian_runtime")", {}};
        auto const reset_role = merovingian::database::PreparedStatement{"reset_postgresql_role", "RESET ROLE", {}};

        WHEN("each statement is validated")
        {
            auto const set_result = merovingian::database::prepared_statement_is_valid(set_role);
            auto const reset_result = merovingian::database::prepared_statement_is_valid(reset_role);

            THEN("the boundary accepts both as legal session-config statements")
            {
                REQUIRE(set_result.valid);
                REQUIRE(reset_result.valid);
            }
        }
    }
}

SCENARIO("Database statement validation allows explicit PostgreSQL transaction control SQL", "[database]")
{
    GIVEN("BEGIN, SAVEPOINT, ROLLBACK TO SAVEPOINT, and COMMIT statements with no placeholders")
    {
        auto const begin = merovingian::database::PreparedStatement{"postgresql_begin", "BEGIN", {}};
        auto const savepoint = merovingian::database::PreparedStatement{"postgresql_savepoint", "SAVEPOINT sp1", {}};
        auto const rollback =
            merovingian::database::PreparedStatement{"postgresql_rollback", "ROLLBACK TO SAVEPOINT sp1", {}};
        auto const commit = merovingian::database::PreparedStatement{"postgresql_commit", "COMMIT", {}};

        WHEN("each statement is validated")
        {
            auto const begin_result = merovingian::database::prepared_statement_is_valid(begin);
            auto const savepoint_result = merovingian::database::prepared_statement_is_valid(savepoint);
            auto const rollback_result = merovingian::database::prepared_statement_is_valid(rollback);
            auto const commit_result = merovingian::database::prepared_statement_is_valid(commit);

            THEN("the boundary accepts transaction-control statements needed by the PostgreSQL durability tests")
            {
                REQUIRE(begin_result.valid);
                REQUIRE(savepoint_result.valid);
                REQUIRE(rollback_result.valid);
                REQUIRE(commit_result.valid);
            }
        }
    }
}

SCENARIO("To-device drain does not acknowledge messages beyond the sync response snapshot", "[database][to-device]")
{
    GIVEN("Alice has two pending to-device room-key messages")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::enqueue_to_device_message(
            store, {0U, "@bob:example.org", "@alice:example.org", "ALICE", "m.room_key", R"({"k":"one"})"}));
        REQUIRE(merovingian::database::enqueue_to_device_message(
            store, {0U, "@bob:example.org", "@alice:example.org", "ALICE", "m.room_key", R"({"k":"two"})"}));

        WHEN("sync drains only through the first response snapshot")
        {
            auto const first =
                merovingian::database::drain_to_device_messages(store, "@alice:example.org", "ALICE", 0U, 1U);

            THEN("only the first message is delivered and neither queued row is prematurely deleted")
            {
                REQUIRE(first.size() == 1U);
                REQUIRE(first.front().content_json == R"({"k":"one"})");
                REQUIRE(store.to_device_messages.size() == 2U);
            }
        }

        WHEN("Alice acknowledges the first snapshot and syncs through the second")
        {
            auto const second =
                merovingian::database::drain_to_device_messages(store, "@alice:example.org", "ALICE", 1U, 2U);

            THEN("the first row is purged as acknowledged and the second room key is delivered")
            {
                REQUIRE(second.size() == 1U);
                REQUIRE(second.front().content_json == R"({"k":"two"})");
                REQUIRE(store.to_device_messages.size() == 1U);
                REQUIRE(store.to_device_messages.front().content_json == R"({"k":"two"})");
            }
        }
    }
}

SCENARIO("Persistent store upserts sync filters and returns them by user and filter id",
         "[database][persistence][filter]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice stores a sync filter and then replaces it with updated JSON")
        {
            auto const first = merovingian::database::PersistentFilter{
                "@alice:example.org",
                "filter-1",
                R"({"room":{"timeline":{"limit":10}}})",
            };
            auto const second = merovingian::database::PersistentFilter{
                "@alice:example.org",
                "filter-1",
                R"({"room":{"timeline":{"limit":20}}})",
            };

            REQUIRE(merovingian::database::store_filter(store, first));
            REQUIRE(merovingian::database::store_filter(store, second));

            auto const stored = merovingian::database::find_filter(store, "@alice:example.org", "filter-1");
            auto const missing = merovingian::database::find_filter(store, "@alice:example.org", "missing-filter");

            THEN("the latest JSON replaces the earlier copy without duplicating the filter row")
            {
                REQUIRE(store.filters.size() == 1U);
                REQUIRE(stored.has_value());
                REQUIRE(stored->user_id == "@alice:example.org");
                REQUIRE(stored->filter_id == "filter-1");
                REQUIRE(stored->json == R"({"room":{"timeline":{"limit":20}}})");
                REQUIRE_FALSE(missing.has_value());
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements.back().name == "upsert_filter");
                REQUIRE(store.prepared_statements.back().parameters.size() == 3U);
                REQUIRE(store.prepared_statements.back().parameters[2].sensitive);
            }
        }

        WHEN("a filter is missing required identity fields or JSON")
        {
            auto const empty_user =
                merovingian::database::store_filter(store, {"", "filter-1", R"({"event_fields":["type"]})"});
            auto const empty_filter_id =
                merovingian::database::store_filter(store, {"@alice:example.org", "", R"({"event_fields":["type"]})"});
            auto const empty_json = merovingian::database::store_filter(store, {"@alice:example.org", "filter-1", ""});

            THEN("the store rejects the malformed filter input")
            {
                REQUIRE_FALSE(empty_user);
                REQUIRE_FALSE(empty_filter_id);
                REQUIRE_FALSE(empty_json);
                REQUIRE(store.filters.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Persistent store profiles upsert and apply targeted displayname and avatar updates",
         "[database][persistence][profile]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice stores a profile and later updates each field through the targeted helpers")
        {
            REQUIRE(merovingian::database::store_profile(
                store, {"@alice:example.org", "Alice", "mxc://example.org/alice-avatar"}));
            REQUIRE(merovingian::database::update_profile_displayname(store, "@alice:example.org", "Alice Admin"));
            REQUIRE(merovingian::database::update_profile_avatar_url(store, "@alice:example.org",
                                                                     "mxc://example.org/alice-avatar-2"));

            auto const stored = merovingian::database::find_profile(store, "@alice:example.org");

            THEN("the profile remains a single row with the updated display name and avatar URL")
            {
                REQUIRE(store.profiles.size() == 1U);
                REQUIRE(stored.has_value());
                REQUIRE(stored->displayname == "Alice Admin");
                REQUIRE(stored->avatar_url == "mxc://example.org/alice-avatar-2");
                REQUIRE(store.prepared_statements.size() == 3U);
                REQUIRE(store.prepared_statements[0].name == "upsert_profile");
                REQUIRE(store.prepared_statements[1].name == "update_profile_displayname");
                REQUIRE(store.prepared_statements[2].name == "update_profile_avatar_url");
            }
        }

        WHEN("alice stores the profile again with a new full payload")
        {
            REQUIRE(merovingian::database::store_profile(
                store, {"@alice:example.org", "Alice", "mxc://example.org/alice-avatar"}));
            REQUIRE(merovingian::database::store_profile(
                store, {"@alice:example.org", "Alice Updated", "mxc://example.org/alice-avatar-3"}));

            auto const stored = merovingian::database::find_profile(store, "@alice:example.org");

            THEN("upsert replaces the existing stored profile without duplicating the row")
            {
                REQUIRE(store.profiles.size() == 1U);
                REQUIRE(stored.has_value());
                REQUIRE(stored->displayname == "Alice Updated");
                REQUIRE(stored->avatar_url == "mxc://example.org/alice-avatar-3");
            }
        }

        WHEN("profile helpers target a user with no stored profile or the input has no user id")
        {
            auto const empty_user = merovingian::database::store_profile(store, {"", "Alice", "mxc://example.org/a"});
            auto const missing_display =
                merovingian::database::update_profile_displayname(store, "@ghost:example.org", "Ghost");
            auto const missing_avatar =
                merovingian::database::update_profile_avatar_url(store, "@ghost:example.org", "mxc://example.org/g");
            auto const missing = merovingian::database::find_profile(store, "@ghost:example.org");

            THEN("the store fails closed and does not synthesize partial profile rows")
            {
                REQUIRE_FALSE(empty_user);
                REQUIRE_FALSE(missing_display);
                REQUIRE_FALSE(missing_avatar);
                REQUIRE_FALSE(missing.has_value());
                REQUIRE(store.profiles.empty());
            }
        }
    }
}

SCENARIO("Persistent client transaction records keep the first response and scope idempotency by room and type",
         "[database][persistence][client-txn]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice stores the same room send transaction twice with different event ids")
        {
            auto const first = merovingian::database::PersistentClientTxnRecord{
                "@alice:example.org", "!room-a:example.org", "m.room.message", "txn-1", "$event-first",
            };
            auto const duplicate = merovingian::database::PersistentClientTxnRecord{
                "@alice:example.org", "!room-a:example.org", "m.room.message", "txn-1", "$event-second",
            };

            REQUIRE(merovingian::database::store_client_txn(store, first));
            REQUIRE(merovingian::database::store_client_txn(store, duplicate));

            auto const replay = merovingian::database::find_client_txn_event_id(
                store, "@alice:example.org", "!room-a:example.org", "m.room.message", "txn-1");

            THEN("the original event id is preserved and the duplicate retry does not add a second row")
            {
                REQUIRE(store.client_txn_ids.size() == 1U);
                REQUIRE(replay.has_value());
                REQUIRE(*replay == "$event-first");
                REQUIRE(store.prepared_statements.size() == 1U);
                REQUIRE(store.prepared_statements.front().name == "insert_client_txn_id");
            }
        }

        WHEN("the same txn id is reused for a different room or event type")
        {
            REQUIRE(merovingian::database::store_client_txn(
                store, {"@alice:example.org", "!room-a:example.org", "m.room.message", "txn-1", "$event-a"}));
            REQUIRE(merovingian::database::store_client_txn(
                store, {"@alice:example.org", "!room-b:example.org", "m.room.message", "txn-1", "$event-b"}));
            REQUIRE(merovingian::database::store_client_txn(
                store, {"@alice:example.org", "!room-a:example.org", "m.reaction", "txn-1", "$event-c"}));

            THEN("each unique (room_id, event_type, txn_id) combination is stored independently")
            {
                REQUIRE(store.client_txn_ids.size() == 3U);
                REQUIRE(merovingian::database::find_client_txn_event_id(
                            store, "@alice:example.org", "!room-a:example.org", "m.room.message", "txn-1") ==
                        std::optional<std::string>{"$event-a"});
                REQUIRE(merovingian::database::find_client_txn_event_id(
                            store, "@alice:example.org", "!room-b:example.org", "m.room.message", "txn-1") ==
                        std::optional<std::string>{"$event-b"});
                REQUIRE(merovingian::database::find_client_txn_event_id(store, "@alice:example.org",
                                                                        "!room-a:example.org", "m.reaction", "txn-1") ==
                        std::optional<std::string>{"$event-c"});
            }
        }

        WHEN("a client transaction is missing required identifying fields")
        {
            auto const missing_user = merovingian::database::store_client_txn(
                store, {"", "!room-a:example.org", "m.room.message", "txn-1", "$event-a"});
            auto const missing_type = merovingian::database::store_client_txn(
                store, {"@alice:example.org", "!room-a:example.org", "", "txn-1", "$event-a"});
            auto const missing_txn = merovingian::database::store_client_txn(
                store, {"@alice:example.org", "!room-a:example.org", "m.room.message", "", "$event-a"});

            THEN("the malformed idempotency record is rejected")
            {
                REQUIRE_FALSE(missing_user);
                REQUIRE_FALSE(missing_type);
                REQUIRE_FALSE(missing_txn);
                REQUIRE(store.client_txn_ids.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Device-list change records validate inputs and advance the sync stream monotonically",
         "[database][persistence][device-list]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("valid changed and left notifications are recorded")
        {
            REQUIRE(merovingian::database::record_device_list_change(
                store, {0U, "@alice:example.org", "@bob:example.org", "changed"}));
            REQUIRE(merovingian::database::record_device_list_change(
                store, {0U, "@alice:example.org", "@carol:example.org", "left"}));

            THEN("the rows are appended with increasing stream ids and durable statements")
            {
                REQUIRE(store.device_list_changes.size() == 2U);
                REQUIRE(store.device_list_changes[0].stream_id == 1U);
                REQUIRE(store.device_list_changes[0].observer_user_id == "@alice:example.org");
                REQUIRE(store.device_list_changes[0].subject_user_id == "@bob:example.org");
                REQUIRE(store.device_list_changes[0].change_type == "changed");
                REQUIRE(store.device_list_changes[1].stream_id == 2U);
                REQUIRE(store.device_list_changes[1].subject_user_id == "@carol:example.org");
                REQUIRE(store.device_list_changes[1].change_type == "left");
                REQUIRE(store.next_sync_stream_id == 2U);
                // Each device-list change allocates a sync-stream id, so the
                // prepared statements include one watermark upsert per change
                // plus the actual insert_device_list_change statements.
                REQUIRE(store.prepared_statements.size() == 4U);
                REQUIRE(store.prepared_statements[0].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[1].name == "insert_device_list_change");
                REQUIRE(store.prepared_statements[2].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[3].name == "insert_device_list_change");
            }
        }

        WHEN("a device-list change is missing users or uses an unsupported type")
        {
            auto const missing_observer =
                merovingian::database::record_device_list_change(store, {0U, "", "@bob:example.org", "changed"});
            auto const missing_subject =
                merovingian::database::record_device_list_change(store, {0U, "@alice:example.org", "", "changed"});
            auto const bad_type = merovingian::database::record_device_list_change(
                store, {0U, "@alice:example.org", "@bob:example.org", "deleted"});

            THEN("the malformed change is rejected without advancing the sync stream")
            {
                REQUIRE_FALSE(missing_observer);
                REQUIRE_FALSE(missing_subject);
                REQUIRE_FALSE(bad_type);
                REQUIRE(store.device_list_changes.empty());
                REQUIRE(store.next_sync_stream_id == 0U);
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Presence snapshots upsert per user and keep only the latest stream-shaped state",
         "[database][persistence][presence]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice first appears online and later updates to unavailable")
        {
            REQUIRE(merovingian::database::upsert_presence(store,
                                                           {0U, "@alice:example.org", "online", "Working", 25, true}));
            REQUIRE(merovingian::database::upsert_presence(
                store, {0U, "@alice:example.org", "unavailable", "Away", 900, false}));

            THEN("the store keeps one row for alice with the latest content and stream id")
            {
                REQUIRE(store.presence_states.size() == 1U);
                REQUIRE(store.presence_states[0].user_id == "@alice:example.org");
                REQUIRE(store.presence_states[0].presence == "unavailable");
                REQUIRE(store.presence_states[0].status_msg == "Away");
                REQUIRE(store.presence_states[0].last_active_ago == 900);
                REQUIRE_FALSE(store.presence_states[0].currently_active);
                REQUIRE(store.presence_states[0].stream_id == 2U);
                REQUIRE(store.next_sync_stream_id == 2U);
                // Each presence update allocates a sync-stream id, so the
                // prepared statements include one watermark upsert per update
                // plus the actual upsert_presence statements.
                REQUIRE(store.prepared_statements.size() == 4U);
                REQUIRE(store.prepared_statements[0].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[1].name == "upsert_presence");
                REQUIRE(store.prepared_statements[2].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[3].name == "upsert_presence");
            }
        }

        WHEN("presence data omits the user id or presence state")
        {
            auto const missing_user = merovingian::database::upsert_presence(store, {0U, "", "online", {}, 0, true});
            auto const missing_presence =
                merovingian::database::upsert_presence(store, {0U, "@alice:example.org", "", {}, 0, false});

            THEN("the malformed snapshot is rejected before it affects the stream state")
            {
                REQUIRE_FALSE(missing_user);
                REQUIRE_FALSE(missing_presence);
                REQUIRE(store.presence_states.empty());
                REQUIRE(store.next_sync_stream_id == 0U);
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Room aliases require an existing room and reject duplicate mappings", "[database][persistence][room-alias]")
{
    GIVEN("an in-memory persistent store with one known room")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::store_room(store, {"!room:example.org", "@alice:example.org"}));

        WHEN("a fresh alias is stored for the existing room")
        {
            REQUIRE(merovingian::database::store_room_alias(store, {"#lobby:example.org", "!room:example.org"}));
            auto const stored = merovingian::database::find_room_alias(store, "#lobby:example.org");

            THEN("the mapping is durable and discoverable by alias")
            {
                REQUIRE(store.room_aliases.size() == 1U);
                REQUIRE(stored.has_value());
                REQUIRE(stored->room_alias == "#lobby:example.org");
                REQUIRE(stored->room_id == "!room:example.org");
                REQUIRE(store.prepared_statements.back().name == "insert_room_alias");
            }
        }

        WHEN("the same alias is reused or the target room does not exist")
        {
            REQUIRE(merovingian::database::store_room_alias(store, {"#lobby:example.org", "!room:example.org"}));
            auto const duplicate =
                merovingian::database::store_room_alias(store, {"#lobby:example.org", "!other-room:example.org"});
            auto const missing_room =
                merovingian::database::store_room_alias(store, {"#elsewhere:example.org", "!missing:example.org"});
            auto const empty_alias = merovingian::database::store_room_alias(store, {"", "!room:example.org"});

            THEN("invalid alias writes are rejected without replacing the original mapping")
            {
                REQUIRE_FALSE(duplicate);
                REQUIRE_FALSE(missing_room);
                REQUIRE_FALSE(empty_alias);
                REQUIRE(store.room_aliases.size() == 1U);
                REQUIRE(merovingian::database::find_room_alias(store, "#lobby:example.org")->room_id ==
                        "!room:example.org");
                REQUIRE_FALSE(merovingian::database::find_room_alias(store, "#elsewhere:example.org").has_value());
            }
        }
    }
}

SCENARIO("Account data upserts global and room-scoped rows while advancing the sync stream",
         "[database][persistence][account-data]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("alice stores and then replaces both global and room account-data rows")
        {
            REQUIRE(merovingian::database::store_account_data(
                store, {"@alice:example.org", "", "m.push_rules", R"({"global":{"override":[]}})", 0U}));
            REQUIRE(
                merovingian::database::store_account_data(store, {"@alice:example.org", "!room:example.org", "m.tag",
                                                                  R"({"tags":{"u.work":{"order":0.1}}})", 0U}));
            REQUIRE(merovingian::database::store_account_data(
                store, {"@alice:example.org", "", "m.push_rules", R"({"global":{"override":["updated"]}})", 0U}));
            REQUIRE(
                merovingian::database::store_account_data(store, {"@alice:example.org", "!room:example.org", "m.tag",
                                                                  R"({"tags":{"u.work":{"order":0.2}}})", 0U}));

            auto const global =
                std::ranges::find_if(store.account_data, [](merovingian::database::PersistentAccountData const& row) {
                    return row.user_id == "@alice:example.org" && row.room_id.empty() &&
                           row.event_type == "m.push_rules";
                });
            auto const room =
                std::ranges::find_if(store.account_data, [](merovingian::database::PersistentAccountData const& row) {
                    return row.user_id == "@alice:example.org" && row.room_id == "!room:example.org" &&
                           row.event_type == "m.tag";
                });

            THEN("each scope keeps one latest row and records the correct backend statement shape")
            {
                REQUIRE(store.account_data.size() == 2U);
                REQUIRE(global != store.account_data.end());
                REQUIRE(room != store.account_data.end());
                REQUIRE(global->content_json == R"({"global":{"override":["updated"]}})");
                REQUIRE(global->stream_id == 3U);
                REQUIRE(room->content_json == R"({"tags":{"u.work":{"order":0.2}}})");
                REQUIRE(room->stream_id == 4U);
                REQUIRE(store.next_sync_stream_id == 4U);
                // Every account-data write now allocates a persisted sync-stream
                // id, so each store call produces a watermark upsert followed by
                // the account-data upsert.
                REQUIRE(store.prepared_statements.size() == 8U);
                REQUIRE(store.prepared_statements[0].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[1].name == "upsert_account_data");
                REQUIRE(store.prepared_statements[2].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[3].name == "upsert_room_account_data");
                REQUIRE(store.prepared_statements[4].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[5].name == "upsert_account_data");
                REQUIRE(store.prepared_statements[6].name == "upsert_sync_stream_watermark");
                REQUIRE(store.prepared_statements[7].name == "upsert_room_account_data");
                REQUIRE(store.prepared_statements[1].parameters.size() == 4U);
                REQUIRE(store.prepared_statements[1].parameters[2].sensitive);
                REQUIRE(store.prepared_statements[3].parameters.size() == 5U);
                REQUIRE(store.prepared_statements[3].parameters[4].sensitive);
            }
        }

        WHEN("account data omits the user id or event type")
        {
            auto const missing_user =
                merovingian::database::store_account_data(store, {"", "", "m.push_rules", R"({})", 0U});
            auto const missing_event_type =
                merovingian::database::store_account_data(store, {"@alice:example.org", "", "", R"({})", 0U});

            THEN("the malformed row is rejected before it can consume a sync stream id")
            {
                REQUIRE_FALSE(missing_user);
                REQUIRE_FALSE(missing_event_type);
                REQUIRE(store.account_data.empty());
                REQUIRE(store.next_sync_stream_id == 0U);
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Media persistence helpers validate inputs, reject duplicates, and apply moderation state",
         "[database][persistence][media]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("a local media row is stored, moderated, and the same remote media id appears on two servers")
        {
            REQUIRE(merovingian::database::store_local_media(
                store, {"mxc-local-1", "@alice:example.org", "image/png", 512U, "sha256", "abc123", false, false}));
            REQUIRE(merovingian::database::update_local_media_state(store, "mxc-local-1", true, true));
            REQUIRE(merovingian::database::store_remote_media(
                store, {"remote-a.example.org", "mxc-remote-1", "image/jpeg", 2048U, false}));
            REQUIRE(merovingian::database::store_remote_media(
                store, {"remote-b.example.org", "mxc-remote-1", "image/jpeg", 4096U, true}));

            THEN("the local moderation flags mutate in place and remote rows stay scoped by origin server")
            {
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.local_media.front().media_id == "mxc-local-1");
                REQUIRE(store.local_media.front().quarantined);
                REQUIRE(store.local_media.front().removed);
                REQUIRE(store.remote_media.size() == 2U);
                REQUIRE(store.remote_media[0].server_name == "remote-a.example.org");
                REQUIRE(store.remote_media[1].server_name == "remote-b.example.org");
                REQUIRE(store.remote_media[1].quarantined);
                REQUIRE(store.prepared_statements.size() == 4U);
                REQUIRE(store.prepared_statements[0].name == "insert_media");
                REQUIRE(store.prepared_statements[1].name == "update_media_state");
                REQUIRE(store.prepared_statements[2].name == "insert_remote_media");
                REQUIRE(store.prepared_statements[3].name == "insert_remote_media");
            }
        }

        WHEN("media helpers receive invalid hashes, duplicate identities, or missing rows")
        {
            REQUIRE(merovingian::database::store_local_media(
                store, {"mxc-local-1", "@alice:example.org", "image/png", 512U, "sha256", "abc123", false, false}));
            REQUIRE(merovingian::database::store_remote_media(
                store, {"remote-a.example.org", "mxc-remote-1", "image/jpeg", 2048U, false}));

            auto const bad_digest = merovingian::database::store_local_media(
                store, {"mxc-local-2", "@alice:example.org", "image/png", 256U, "sha256", "bad/digest", false, false});
            auto const zero_size = merovingian::database::store_local_media(
                store, {"mxc-local-3", "@alice:example.org", "image/png", 0U, "sha256", "digest", false, false});
            auto const duplicate_local = merovingian::database::store_local_media(
                store, {"mxc-local-1", "@bob:example.org", "image/png", 256U, "sha256", "other", false, false});
            auto const missing_local =
                merovingian::database::update_local_media_state(store, "missing-media", true, false);
            auto const duplicate_remote = merovingian::database::store_remote_media(
                store, {"remote-a.example.org", "mxc-remote-1", "image/jpeg", 2048U, false});

            THEN("the invalid operations fail closed without mutating the stored rows")
            {
                REQUIRE_FALSE(bad_digest);
                REQUIRE_FALSE(zero_size);
                REQUIRE_FALSE(duplicate_local);
                REQUIRE_FALSE(missing_local);
                REQUIRE_FALSE(duplicate_remote);
                REQUIRE(store.local_media.size() == 1U);
                REQUIRE(store.remote_media.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 2U);
            }
        }
    }
}

SCENARIO("Policy rules upsert by rule id and direct deletion rejects missing identifiers",
         "[database][persistence][policy-rule]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("a rule is replaced and then deleted by its stable rule id")
        {
            REQUIRE(merovingian::database::store_policy_rule(
                store, {"deny-1", "server", "evil.example.org", "deny", "seed list"}));
            REQUIRE(merovingian::database::store_policy_rule(
                store, {"deny-1", "server", "evil.example.org", "muzzle", "operator override"}));
            REQUIRE(merovingian::database::delete_policy_rule(store, "deny-1"));

            THEN("upsert keeps one durable row and deletion removes it cleanly")
            {
                REQUIRE(store.policy_rules.empty());
                REQUIRE(store.prepared_statements.size() == 3U);
                REQUIRE(store.prepared_statements[0].name == "upsert_policy_rule");
                REQUIRE(store.prepared_statements[1].name == "upsert_policy_rule");
                REQUIRE(store.prepared_statements[2].name == "delete_policy_rule");
            }
        }

        WHEN("the caller deletes a missing or empty rule id")
        {
            auto const missing = merovingian::database::delete_policy_rule(store, "deny-missing");
            auto const empty = merovingian::database::delete_policy_rule(store, "");

            THEN("the helper rejects the request")
            {
                REQUIRE_FALSE(missing);
                REQUIRE_FALSE(empty);
                REQUIRE(store.policy_rules.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("Database statement validation enforces placeholder arity", "[database]")
{
    GIVEN("statements with matching and mismatched placeholder arity")
    {
        auto const valid_statement = merovingian::database::PreparedStatement{
            "select_user_device",
            "SELECT id FROM devices WHERE user_id = $1 AND device_id = $2",
            {
              merovingian::database::BoundValue{"@alice:example.org", false},
              merovingian::database::BoundValue{"DEVICE", false},
              },
        };
        auto const missing_first_placeholder = merovingian::database::PreparedStatement{
            "select_device",
            "SELECT id FROM devices WHERE device_id = $2",
            {merovingian::database::BoundValue{"DEVICE", false}},
        };
        auto const extra_parameter = merovingian::database::PreparedStatement{
            "select_users",
            "SELECT id FROM users",
            {merovingian::database::BoundValue{"unused", false}},
        };

        WHEN("the statements are validated")
        {
            auto const valid_result = merovingian::database::prepared_statement_is_valid(valid_statement);
            auto const missing_first_result =
                merovingian::database::prepared_statement_is_valid(missing_first_placeholder);
            auto const extra_parameter_result = merovingian::database::prepared_statement_is_valid(extra_parameter);

            THEN("placeholder indexes must match the bound parameter count exactly")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(missing_first_result.valid);
                REQUIRE(missing_first_result.reason == "SQL placeholder arity does not match bound parameters");
                REQUIRE_FALSE(extra_parameter_result.valid);
                REQUIRE(extra_parameter_result.reason == "SQL placeholder arity does not match bound parameters");
            }
        }
    }
}

SCENARIO("Database executor validates statements before execution", "[database]")
{
    GIVEN("a recording executor and valid or invalid statements")
    {
        auto executor = RecordingExecutor{};
        auto const valid_statement =
            merovingian::database::PreparedStatement{"select_user", "SELECT id FROM users", {}};
        auto const invalid_statement =
            merovingian::database::PreparedStatement{"select-user", "SELECT id FROM users", {}};

        WHEN("validated execution is requested")
        {
            auto const valid_result = merovingian::database::execute_validated(executor, valid_statement);
            auto const invalid_result = merovingian::database::execute_validated(executor, invalid_statement);

            THEN("invalid statements fail before reaching the executor")
            {
                REQUIRE(valid_result.ok);
                REQUIRE_FALSE(invalid_result.ok);
                REQUIRE(invalid_result.error == "invalid statement name");
                REQUIRE(executor.executed_statement_names().size() == 1U);
                REQUIRE(executor.executed_statement_names().front() == "select_user");
            }
        }
    }
}

SCENARIO("PostgreSQL executor connection supports RAII moves", "[database][postgresql]")
{
    GIVEN("the PostgreSQL connection owns libpq state through an executor base")
    {
        WHEN("the connection type is returned by value from factory results")
        {
            THEN("the executor base permits moving while still rejecting copies")
            {
                STATIC_REQUIRE(std::is_move_constructible_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE(std::is_move_assignable_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<merovingian::database::PostgresqlConnection>);
                STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<merovingian::database::PostgresqlConnection>);
            }
        }
    }
}

SCENARIO("Database bound value summaries redact sensitive values", "[database]")
{
    GIVEN("public and sensitive bound parameters")
    {
        auto const parameters = std::vector<merovingian::database::BoundValue>{
            {"@alice:example.org", false},
            {"secret-token-hash",  true }
        };

        WHEN("a parameter summary is produced")
        {
            auto const summary = merovingian::database::redacted_parameter_summary(parameters);

            THEN("the sensitive value is not disclosed")
            {
                REQUIRE(summary == "parameters=2 [present, redacted]");
                REQUIRE(summary.find("secret-token-hash") == std::string::npos);
            }
        }
    }
}

SCENARIO("Database migration plans are contiguous and direction-aware", "[database][migration]")
{
    GIVEN("valid, wrong-direction, and non-contiguous migration plans")
    {
        auto const valid_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {
              merovingian::database::MigrationStep{1U, "create_users", {create_users_statement()}},
              merovingian::database::MigrationStep{
                    2U,
                    "create_devices",
                    {{"create_devices", "CREATE TABLE devices (device_id TEXT PRIMARY KEY)", {}}}},
              },
            merovingian::database::MigrationDirection::upgrade,
        };
        auto const wrong_direction_plan = merovingian::database::MigrationPlan{
            2U,
            1U,
            {merovingian::database::MigrationStep{1U, "drop_devices", {{"drop_devices", "DROP TABLE devices", {}}}}},
            merovingian::database::MigrationDirection::upgrade};
        auto const gap_plan = merovingian::database::MigrationPlan{
            0U,
            2U,
            {merovingian::database::MigrationStep{
                2U, "create_devices", {{"create_devices", "CREATE TABLE devices (device_id TEXT PRIMARY KEY)", {}}}}}};

        WHEN("the migration plans are validated")
        {
            auto const valid_result = merovingian::database::migration_plan_is_valid(valid_plan);
            auto const wrong_direction_result = merovingian::database::migration_plan_is_valid(wrong_direction_plan);
            auto const gap_result = merovingian::database::migration_plan_is_valid(gap_plan);
            auto const summary = merovingian::database::migration_plan_summary(valid_plan);

            THEN("only contiguous plans with the correct direction are accepted")
            {
                REQUIRE(valid_result.valid);
                REQUIRE_FALSE(wrong_direction_result.valid);
                REQUIRE(wrong_direction_result.reason == "downgrade migration plan has wrong direction");
                REQUIRE_FALSE(gap_result.valid);
                REQUIRE(gap_result.reason == "migration versions must be contiguous");
                REQUIRE(summary == "database migration plan direction=upgrade current_version=0 "
                                   "target_version=2 steps=2");
            }
        }
    }
}

SCENARIO("Database migration runner applies the current schema and the matching explicit downgrade",
         "[database][migration]")
{
    GIVEN("an empty schema state")
    {
        auto const empty_state = merovingian::database::SchemaState{};

        WHEN("the initial upgrade and explicit downgrade are applied")
        {
            auto const upgrade_plan = merovingian::database::migration_plan_for(empty_state);
            auto const upgraded = merovingian::database::apply_migration_plan(empty_state, upgrade_plan);
            auto const second_plan = merovingian::database::migration_plan_for(upgraded.state);
            auto const compatible = merovingian::database::schema_state_is_compatible(upgraded.state);
            auto const downgrade_plan = merovingian::database::migration_plan_between(upgraded.state.version, 0U);
            auto const downgraded = merovingian::database::apply_migration_plan(upgraded.state, downgrade_plan);

            THEN("the upgrade chain reaches the current schema version and is reversible")
            {
                REQUIRE(upgrade_plan.direction == merovingian::database::MigrationDirection::upgrade);
                REQUIRE(upgrade_plan.current_version == 0U);
                REQUIRE(upgrade_plan.target_version == merovingian::database::current_schema_version());
                REQUIRE(upgrade_plan.steps.size() == 2U);
                REQUIRE(upgrade_plan.steps[0].version == 1U);
                REQUIRE(upgrade_plan.steps[0].name == "initial_schema");
                REQUIRE(upgrade_plan.steps[1].version == 2U);
                REQUIRE(upgrade_plan.steps[1].name == "sync_stream_watermark");
                REQUIRE(upgraded.ok);
                REQUIRE(upgraded.state.version == merovingian::database::current_schema_version());
                REQUIRE(upgraded.state.applied_migrations.size() == 2U);
                REQUIRE(upgraded.state.applied_migrations[0].name == "initial_schema");
                REQUIRE(upgraded.state.applied_migrations[1].name == "sync_stream_watermark");
                REQUIRE(upgraded.state.tables.size() == merovingian::database::current_schema_tables().size());
                REQUIRE(compatible.valid);
                REQUIRE(second_plan.steps.empty());
                REQUIRE(downgrade_plan.direction == merovingian::database::MigrationDirection::downgrade);
                REQUIRE(downgrade_plan.steps.size() == 2U);
                REQUIRE(downgrade_plan.steps[0].name == "drop_sync_stream_watermark");
                REQUIRE(downgrade_plan.steps[1].name == "drop_initial_schema");
                REQUIRE(downgraded.ok);
                REQUIRE(downgraded.state.version == 0U);
                REQUIRE(downgraded.state.tables.empty());
            }
        }
    }
}

SCENARIO("Database schema validation fails closed on incompatible state", "[database][migration]")
{
    GIVEN("a migrated schema missing a required table and a future schema")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto missing_table = opened.store.schema;
        missing_table.tables.clear();
        auto future_schema = opened.store.schema;
        future_schema.version = merovingian::database::current_schema_version() + 1U;

        WHEN("compatibility is checked")
        {
            auto const missing_result = merovingian::database::schema_state_is_compatible(missing_table);
            auto const future_result = merovingian::database::schema_state_is_compatible(future_schema);
            auto const rollback = merovingian::database::migration_rollback_policy();

            THEN("startup blockers are explicit")
            {
                REQUIRE_FALSE(missing_result.valid);
                REQUIRE(missing_result.reason.find("required table is missing") != std::string::npos);
                REQUIRE_FALSE(future_result.valid);
                REQUIRE(future_result.reason == "schema version is not compatible");
                REQUIRE(rollback.find("downgrade") != std::string_view::npos);
            }
        }
    }
}

SCENARIO("Persistent store records MVP homeserver data with hashed tokens only", "[database][persistence]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("users devices tokens rooms events state audit and admin actions are stored")
        {
            auto const user_ok = merovingian::database::store_user(
                store, {"@alice:example.org", "password-hash:v1:1", false, false, true});
            auto const device_ok =
                merovingian::database::store_device(store, {"@alice:example.org", "DEVICE1", "Alice laptop"});
            auto const bad_token_ok = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "plaintext", false, std::nullopt});
            auto const token_ok = merovingian::database::store_access_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:123", false, std::nullopt});
            auto const refresh_ok = merovingian::database::store_refresh_token(
                store, {"@alice:example.org", "DEVICE1", "token-hash:v2:refresh123", false, std::nullopt});
            auto const room_ok = merovingian::database::store_room(store, {"!room1:example.org", "@alice:example.org"});
            auto const membership_ok =
                merovingian::database::store_membership(store, {"!room1:example.org", "@alice:example.org"}) ==
                merovingian::database::MembershipStoreResult::stored;
            auto const message_event_ok =
                merovingian::database::store_event(store, {"$event1:example.org", "!room1:example.org",
                                                           "@alice:example.org", R"({"type":"m.room.message"})"});
            auto const message_state_ok = merovingian::database::store_state(
                store, {"!room1:example.org", "m.room.member", "@alice:example.org", "$event1:example.org"});
            auto const state_event_ok = merovingian::database::store_event(
                store, {"$event2:example.org", "!room1:example.org", "@alice:example.org",
                        R"({"type":"m.room.member","state_key":"@alice:example.org"})"});
            auto const state_ok = merovingian::database::store_state(
                store, {"!room1:example.org", "m.room.member", "@alice:example.org", "$event2:example.org"});
            auto const audit_ok = merovingian::database::append_audit_event(
                store, {"auth", "auth.login", "@alice:example.org", "DEVICE1", "accepted"});
            auto const admin_ok = merovingian::database::append_admin_action(
                store, {"@alice:example.org", "quarantine", "!room1:example.org"});
            auto const revoked = merovingian::database::revoke_access_token(store, "token-hash:v2:123");
            auto const refresh_revoked = merovingian::database::revoke_refresh_token(store, "token-hash:v2:refresh123");
            auto const valid = merovingian::database::validate_persistent_store(store);

            THEN("state rows are only accepted for matching state events")
            {
                REQUIRE(user_ok);
                REQUIRE(device_ok);
                REQUIRE_FALSE(bad_token_ok);
                REQUIRE(token_ok);
                REQUIRE(refresh_ok);
                REQUIRE(room_ok);
                REQUIRE(membership_ok);
                REQUIRE(message_event_ok);
                REQUIRE_FALSE(message_state_ok);
                REQUIRE(state_event_ok);
                REQUIRE(state_ok);
                REQUIRE(audit_ok);
                REQUIRE(admin_ok);
                REQUIRE(revoked == 1U);
                REQUIRE(refresh_revoked == 1U);
                REQUIRE(valid.valid);
                REQUIRE(store.users.size() == 1U);
                REQUIRE(store.devices.size() == 1U);
                REQUIRE(store.access_tokens.front().revoked);
                REQUIRE(store.refresh_tokens.front().revoked);
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.audit_log.size() == 1U);
                REQUIRE(store.admin_actions.size() == 1U);
                REQUIRE(merovingian::database::sensitive_values_are_redacted(store));
            }
        }
    }
}

SCENARIO("Persistent store transactions commit all rows or no rows", "[database][persistence][transaction]")
{
    GIVEN("a SQLite persistent store and a transaction whose second statement violates storage state")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const statements = std::vector<merovingian::database::PreparedStatement>{
            {"insert_room",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!txn-room:example.org", false}, {"@alice:example.org", false}}},
            {"insert_room_duplicate",
             "INSERT INTO rooms VALUES ($1, $2)", {{"!txn-room:example.org", false}, {"@bob:example.org", false}}  },
        };

        WHEN("the transaction is committed")
        {
            auto const committed = merovingian::database::commit_persistent_transaction(store, statements);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("the successful first statement is rolled back with the failed statement")
            {
                REQUIRE_FALSE(committed);
                // `restore_sync_stream_id()` may have persisted the sync-stream watermark
                // on startup; any such housekeeping statement is unrelated to this transaction.
                auto const transaction_statements = std::ranges::count_if(
                    store.prepared_statements, [](merovingian::database::PreparedStatement const& statement) {
                        return statement.name != "upsert_sync_stream_watermark";
                    });
                REQUIRE(transaction_statements == 0U);
                REQUIRE(reopened.store.rooms.empty());
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store offers atomic helpers for multi-row runtime mutations",
         "[database][persistence][transaction]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("a room membership and a state event are stored through transaction helpers")
        {
            auto const room_ok = merovingian::database::store_room_with_membership(
                store, {"!room-txn:example.org", "@alice:example.org"},
                {"!room-txn:example.org", "@alice:example.org"});
            auto const event_ok = merovingian::database::store_event_with_state(
                store,
                {"$state-txn:example.org", "!room-txn:example.org", "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})"},
                merovingian::database::PersistentStateEvent{"!room-txn:example.org", "m.room.member",
                                                            "@alice:example.org", "$state-txn:example.org"});

            THEN("all related rows become visible together")
            {
                REQUIRE(room_ok);
                REQUIRE(event_ok);
                REQUIRE(store.rooms.size() == 1U);
                REQUIRE(store.memberships.size() == 1U);
                REQUIRE(store.events.size() == 1U);
                REQUIRE(store.state.size() == 1U);
                REQUIRE(store.prepared_statements.size() == 4U);
            }
        }
    }
}

SCENARIO("Persistent store records server signing keys and event DAG metadata", "[database][persistence][events]")
{
    GIVEN("an opened persistent store with a room")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_room(store, {"!room-dag:example.org", "@alice:example.org"}));

        WHEN("a runtime signing key and a signed state-linked event are stored")
        {
            auto const key_ok = merovingian::database::store_server_signing_key(
                store, {"example.org", "ed25519:auto", "public-key-base64", 32503680000000ULL});
            auto const state_event_ok = merovingian::database::store_event_with_state(
                store,
                {"$state:example.org",
                 "!room-dag:example.org",
                 "@alice:example.org",
                 R"({"type":"m.room.member","state_key":"@alice:example.org"})",
                 1U,
                 0U,
                 {},
                 {},
                 {}},
                merovingian::database::PersistentStateEvent{"!room-dag:example.org", "m.room.member",
                                                            "@alice:example.org", "$state:example.org"});
            auto const message_event_ok = merovingian::database::store_event_with_state(
                store,
                {"$message:example.org",
                 "!room-dag:example.org",
                 "@alice:example.org",
                 R"({"type":"m.room.message","state_key":""})",
                 2U,
                 0U,
                 {"$state:example.org"},
                 {"$state:example.org"},
                 {{"example.org", "ed25519:auto",
                   "c3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzc3Nzcw"}}},
                std::nullopt);
            auto const found_key = merovingian::database::find_server_signing_key(store, "example.org", "ed25519:auto");

            THEN("the signing key edge auth and signature rows are durable")
            {
                REQUIRE(key_ok);
                REQUIRE(state_event_ok);
                REQUIRE(message_event_ok);
                REQUIRE(found_key.has_value());
                REQUIRE(found_key->server_name == "example.org");
                REQUIRE(found_key->public_key == "public-key-base64");
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.events.back().depth == 2U);
                REQUIRE(store.event_edges.size() == 1U);
                REQUIRE(store.event_auth.size() == 1U);
                REQUIRE(store.event_signatures.size() == 1U);
                REQUIRE(store.event_edges.front().prev_event_id == "$state:example.org");
                REQUIRE(store.event_auth.front().auth_event_id == "$state:example.org");
                REQUIRE(store.event_signatures.front().server_name == "example.org");
                REQUIRE(store.prepared_statements.back().name == "insert_event_signature");
            }
        }
    }
}

SCENARIO("Persistent store replays outbound federation queue state after restart",
         "[database][persistence][federation]")
{
    GIVEN("a SQLite persistent store with destination retry state and a pending outbound transaction")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto destination = merovingian::database::PersistentFederationDestination{};
        destination.server_name = "remote.example.org";
        destination.state = "backoff";
        destination.retry_after_ts = 5000U;
        destination.last_success_ts = 1000U;
        destination.consecutive_failures = 3U;

        auto transaction = merovingian::database::PersistentFederationTransaction{};
        transaction.transaction_id = "txn-1";
        transaction.server_name = "remote.example.org";
        transaction.method = "PUT";
        transaction.target = "/_matrix/federation/v1/send/txn-1";
        transaction.origin = "origin.example.org";
        transaction.origin_server_ts = "1234";
        transaction.body = R"({"pdus":[]})";
        transaction.retry_count = 2U;
        transaction.next_retry_ts = 5000U;

        WHEN("the rows are stored and the database is reopened")
        {
            auto const destination_ok = merovingian::database::store_federation_destination(store, destination);
            auto const transaction_ok = merovingian::database::store_federation_transaction(store, transaction);
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("destination retry state and pending transaction details are hydrated for replay")
            {
                REQUIRE(destination_ok);
                REQUIRE(transaction_ok);
                REQUIRE(reopened.store.federation_destinations.size() == 1U);
                REQUIRE(reopened.store.federation_transactions.size() == 1U);
                REQUIRE(reopened.store.federation_destinations.front().server_name == "remote.example.org");
                REQUIRE(reopened.store.federation_destinations.front().state == "backoff");
                REQUIRE(reopened.store.federation_destinations.front().retry_after_ts == 5000U);
                REQUIRE(reopened.store.federation_destinations.front().last_success_ts == 1000U);
                REQUIRE(reopened.store.federation_destinations.front().consecutive_failures == 3U);
                REQUIRE(reopened.store.federation_transactions.front().transaction_id == "txn-1");
                REQUIRE(reopened.store.federation_transactions.front().server_name == "remote.example.org");
                REQUIRE(reopened.store.federation_transactions.front().body == R"({"pdus":[]})");
                REQUIRE(reopened.store.federation_transactions.front().retry_count == 2U);
                REQUIRE(reopened.store.federation_transactions.front().next_retry_ts == 5000U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store replays policy rules and durable media blobs after restart",
         "[database][persistence][media][policy]")
{
    GIVEN("a SQLite persistent store with policy and media blob rows")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("policy rules and blob bytes are stored and the database is reopened")
        {
            auto const policy_ok = merovingian::database::store_policy_rule(
                store, {"deny-evil", "server", "evil.example.org", "deny", "trusted policy list"});
            auto const digest = std::string(64U, 'a');
            auto const blob_ok = merovingian::database::store_media_blob(
                store, {"blob_" + digest + "_5", "blake2b", digest, 5U, "hello", 2U});
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);

            THEN("policy enforcement inputs and blob payloads are hydrated durably")
            {
                REQUIRE(policy_ok);
                REQUIRE(blob_ok);
                REQUIRE(reopened.store.policy_rules.size() == 1U);
                REQUIRE(reopened.store.policy_rules.front().rule_id == "deny-evil");
                REQUIRE(reopened.store.policy_rules.front().action == "deny");
                REQUIRE(reopened.store.media_blobs.size() == 1U);
                REQUIRE(reopened.store.media_blobs.front().storage_id == "blob_" + digest + "_5");
                REQUIRE(reopened.store.media_blobs.front().bytes == "hello");
                REQUIRE(reopened.store.media_blobs.front().ref_count == 2U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store records durable server-blind E2EE key state", "[database][persistence][key-api]")
{
    GIVEN("an opened persistent store")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        WHEN("device, one-time, fallback, cross-signing, signature, and backup keys are stored")
        {
            auto const device_ok = merovingian::database::store_device_key(
                store, {"@alice:example.org", "DEVICE1", R"({"algorithms":["m.megolm.v1.aes-sha2"]})"});
            auto const one_time_ok = merovingian::database::store_one_time_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:AAA", R"({"key":"otk"})"});
            auto const fallback_ok = merovingian::database::store_fallback_key(
                store, {"@alice:example.org", "DEVICE1", "signed_curve25519:FB", R"({"key":"fallback"})"});
            auto const cross_signing_ok = merovingian::database::store_cross_signing_key(
                store, {"@alice:example.org", "master", R"({"keys":{"ed25519:master":"pub"}})"});
            auto const signature_ok = merovingian::database::store_key_signature(
                store, {"@alice:example.org", "@alice:example.org", "DEVICE1", R"({"signatures":{}})"});
            auto const backup_version_ok = merovingian::database::store_key_backup_version(
                store, {"@alice:example.org", "1", R"({"algorithm":"m.megolm_backup.v1"})"});
            auto const backup_session_ok = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "SESSION1", R"({"session_data":{}})"});
            auto claimed = merovingian::database::claim_one_time_key(store, "@alice:example.org", "DEVICE1");
            auto fallback = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1");
            auto fallback_again = merovingian::database::find_fallback_key(store, "@alice:example.org", "DEVICE1");

            THEN("one-time keys are consumed while fallback and backup state remain durable")
            {
                REQUIRE(device_ok);
                REQUIRE(one_time_ok);
                REQUIRE(fallback_ok);
                REQUIRE(cross_signing_ok);
                REQUIRE(signature_ok);
                REQUIRE(backup_version_ok);
                REQUIRE(backup_session_ok);
                REQUIRE(claimed.has_value());
                REQUIRE(claimed->key_id == "signed_curve25519:AAA");
                REQUIRE(store.one_time_keys.empty());
                REQUIRE(fallback.has_value());
                REQUIRE(fallback_again.has_value());
                REQUIRE(store.fallback_keys.size() == 1U);
                REQUIRE(store.device_keys.size() == 1U);
                REQUIRE(store.cross_signing_keys.size() == 1U);
                REQUIRE(store.key_signatures.size() == 1U);
                REQUIRE(store.key_backup_versions.size() == 1U);
                REQUIRE(store.key_backup_sessions.size() == 1U);
                REQUIRE(merovingian::database::sensitive_values_are_redacted(store));
            }
        }
    }
}

SCENARIO("delete_key_backup_version removes the version from the store", "[database][key-backup]")
{
    GIVEN("a store with a key backup version")
    {
        auto store = merovingian::database::PersistentStore{};
        REQUIRE(merovingian::database::store_key_backup_version(
            store, {"@alice:example.org", "1", R"({"algorithm":"m.megolm_backup.v1"})"}));
        REQUIRE(store.key_backup_versions.size() == 1U);

        WHEN("the backup version is deleted")
        {
            auto const result = merovingian::database::delete_key_backup_version(store, "@alice:example.org", "1");

            THEN("the operation succeeds and the version is gone from the store")
            {
                REQUIRE(result);
                REQUIRE(store.key_backup_versions.empty());
            }
        }

        WHEN("a non-existent version is deleted")
        {
            auto const result = merovingian::database::delete_key_backup_version(store, "@alice:example.org", "99");

            THEN("the operation succeeds idempotently and the existing version is unaffected")
            {
                REQUIRE(result);
                REQUIRE(store.key_backup_versions.size() == 1U);
            }
        }
    }
}

SCENARIO("Key backup session helpers upsert one row per tuple and support scoped cleanup",
         "[database][persistence][key-backup][sessions]")
{
    GIVEN("an in-memory persistent store")
    {
        auto store = merovingian::database::PersistentStore{};

        WHEN("the same backup session tuple is stored twice with updated JSON")
        {
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "SESSION1", R"({"session_data":{"v":1}})"}));
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "SESSION1", R"({"session_data":{"v":2}})"}));

            THEN("the row is upserted in place and the payload stays sensitive")
            {
                REQUIRE(store.key_backup_sessions.size() == 1U);
                REQUIRE(store.key_backup_sessions.front().json == R"({"session_data":{"v":2}})");
                REQUIRE(store.prepared_statements.size() == 2U);
                REQUIRE(store.prepared_statements[0].name == "upsert_key_backup_session");
                REQUIRE(store.prepared_statements[1].name == "upsert_key_backup_session");
                REQUIRE(store.prepared_statements[0].parameters[4].sensitive);
                REQUIRE(store.prepared_statements[1].parameters[4].sensitive);
            }
        }

        WHEN("one session, one room, or one user scope is deleted")
        {
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room-a:example.org", "SESSION1", R"({"session_data":{"v":1}})"}));
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room-a:example.org", "SESSION2", R"({"session_data":{"v":2}})"}));
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room-b:example.org", "SESSION3", R"({"session_data":{"v":3}})"}));
            REQUIRE(merovingian::database::store_key_backup_session(
                store, {"@bob:example.org", "9", "!room-z:example.org", "SESSION9", R"({"session_data":{"v":9}})"}));

            REQUIRE(merovingian::database::delete_key_backup_session(store, "@alice:example.org", "1",
                                                                     "!room-a:example.org", "SESSION1"));
            REQUIRE(merovingian::database::delete_key_backup_room_sessions(store, "@alice:example.org", "1",
                                                                           "!room-a:example.org"));
            REQUIRE(merovingian::database::delete_all_key_backup_sessions(store, "@alice:example.org"));

            THEN("cleanup removes only the requested scope and leaves other users untouched")
            {
                REQUIRE(store.key_backup_sessions.size() == 1U);
                REQUIRE(store.key_backup_sessions.front().user_id == "@bob:example.org");
                REQUIRE(store.key_backup_sessions.front().session_id == "SESSION9");
                REQUIRE(store.prepared_statements.size() == 7U);
                REQUIRE(store.prepared_statements[4].name == "delete_key_backup_session");
                REQUIRE(store.prepared_statements[5].name == "delete_key_backup_room_sessions");
                REQUIRE(store.prepared_statements[6].name == "delete_all_key_backup_sessions");
            }
        }

        WHEN("a backup session payload or identifier is missing")
        {
            auto const empty_payload = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "SESSION1", ""});
            auto const missing_version = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "", "!room:example.org", "SESSION1", R"({"session_data":{}})"});
            auto const missing_room = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "", "SESSION1", R"({"session_data":{}})"});
            auto const missing_session = merovingian::database::store_key_backup_session(
                store, {"@alice:example.org", "1", "!room:example.org", "", R"({"session_data":{}})"});

            THEN("the incomplete session is rejected before it reaches the store")
            {
                REQUIRE_FALSE(empty_payload);
                REQUIRE_FALSE(missing_version);
                REQUIRE_FALSE(missing_room);
                REQUIRE_FALSE(missing_session);
                REQUIRE(store.key_backup_sessions.empty());
                REQUIRE(store.prepared_statements.empty());
            }
        }
    }
}

SCENARIO("PostgreSQL connection policy rejects unsafe or ambiguous libpq inputs", "[database][postgresql]")
{
    GIVEN("empty and non-PostgreSQL connection strings")
    {
        WHEN("the connection strings are validated")
        {
            auto const empty = merovingian::database::validate_postgresql_conninfo("");
            auto const sqlite_path = merovingian::database::validate_postgresql_conninfo("/tmp/merovingian.sqlite3");
            auto const uri = merovingian::database::validate_postgresql_conninfo(
                "postgresql://merovingian:secret@db.example.org/merovingian?sslmode=verify-full");

            THEN("only explicit PostgreSQL libpq connection strings are accepted")
            {
                REQUIRE_FALSE(empty.allowed);
                REQUIRE(empty.reason == "PostgreSQL connection info must not be empty");
                REQUIRE_FALSE(sqlite_path.allowed);
                REQUIRE(sqlite_path.reason == "PostgreSQL connection info must use a PostgreSQL URI or key/value form");
                REQUIRE(uri.allowed);
            }
        }
    }
}

SCENARIO("PostgreSQL connection summaries redact credentials before logging", "[database][postgresql]")
{
    GIVEN("URI and key-value libpq connection strings containing passwords")
    {
        WHEN("redacted summaries are produced")
        {
            auto const uri = merovingian::database::redact_postgresql_conninfo(
                "postgresql://merovingian:secret@db.example.org/merovingian?sslmode=verify-full");
            auto const key_value = merovingian::database::redact_postgresql_conninfo(
                "host=db.example.org dbname=merovingian user=merovingian password=secret sslmode=verify-full");

            THEN("the password material is not disclosed")
            {
                REQUIRE(uri.find("secret") == std::string::npos);
                REQUIRE(uri.find("redacted") != std::string::npos);
                REQUIRE(key_value.find("secret") == std::string::npos);
                REQUIRE(key_value.find("password=redacted") != std::string::npos);
            }
        }
    }
}

SCENARIO("PostgreSQL schema bootstrap exposes current schema statements", "[database][postgresql][migration]")
{
    GIVEN("the current schema inventory")
    {
        WHEN("PostgreSQL bootstrap statements are created")
        {
            auto const statements = merovingian::database::postgresql_schema_bootstrap_statements();

            THEN("the bootstrap can create every core table and record the initial migration")
            {
                // One CREATE TABLE per core table plus one INSERT-on-conflict
                // row that records the initial_schema migration ledger entry.
                REQUIRE(statements.size() == merovingian::database::initial_schema_tables().size() + 1U);
                REQUIRE(statements.front().name == "postgresql_create_schema_migrations");
                REQUIRE(statements.front().sql.find("CREATE TABLE IF NOT EXISTS schema_migrations") == 0U);
                REQUIRE(statements.back().sql.find("ON CONFLICT") != std::string::npos);
            }
        }
    }
}

SCENARIO("Physical migration files load into validated migration plans", "[database][migration][files]")
{
    GIVEN("a temporary migration file with explicit statement names")
    {
        auto const directory = std::filesystem::temp_directory_path() / "merovingian-migration-file-test";
        std::filesystem::create_directories(directory);
        auto const file = directory / "003_policy_rules.sql";
        {
            auto output = std::ofstream{file};
            output << "-- merovingian-migration version=3 name=policy_rules direction=upgrade\n";
            output << "-- statement create_policy_rules_extra\n";
            output << "CREATE TABLE policy_rules_extra (rule_id TEXT PRIMARY KEY)\n";
        }

        WHEN("the migration directory is loaded")
        {
            auto const loaded = merovingian::database::load_migration_files(directory.string());

            THEN("the file becomes a validated migration step")
            {
                REQUIRE(loaded.ok);
                REQUIRE(loaded.steps.size() == 1U);
                REQUIRE(loaded.steps.front().version == 3U);
                REQUIRE(loaded.steps.front().name == "policy_rules");
                REQUIRE(loaded.steps.front().statements.size() == 1U);
                REQUIRE(merovingian::database::migration_step_is_valid(loaded.steps.front()).valid);
            }
        }

        std::filesystem::remove(file);
        std::filesystem::remove(directory);
    }
}

SCENARIO("Checked-in migrations cover the v1 bootstrap and v2 sync-stream watermark", "[database][migration][files]")
{
    GIVEN("the repository migration directory")
    {
        auto const directory = locate_repository_migrations_directory();

        WHEN("the checked-in migration files are loaded")
        {
            REQUIRE_FALSE(directory.empty());
            auto const loaded = merovingian::database::load_migration_files(directory.string());

            THEN("the v1 bootstrap creates the initial schema and a numbered v2 migration adds the watermark table")
            {
                REQUIRE(loaded.ok);
                REQUIRE(loaded.steps.size() == 2U);
                REQUIRE(loaded.steps[0].version == 1U);
                REQUIRE(loaded.steps[0].name == "initial_schema");
                REQUIRE(loaded.steps[0].statements.size() == merovingian::database::initial_schema_tables().size());
                REQUIRE(loaded.steps[1].version == 2U);
                REQUIRE(loaded.steps[1].name == "sync_stream_watermark");
                REQUIRE(loaded.steps[1].statements.size() == 1U);

                for (auto const& statement : loaded.steps[0].statements)
                {
                    // Before v1.0.0 there are no live databases to migrate; the
                    // checked-in v1 file must create the whole schema directly.
                    REQUIRE(statement.sql.find("CREATE TABLE ") == 0U);
                    REQUIRE(statement.sql.find("ALTER TABLE ") == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("Offline migrator plans require migration database role", "[database][migration][role]")
{
    GIVEN("runtime and migration database roles")
    {
        auto runtime_config = merovingian::config::DatabaseConfig{};
        runtime_config.role = merovingian::config::DatabaseRole::runtime;
        auto migration_config = merovingian::config::DatabaseConfig{};
        migration_config.role = merovingian::config::DatabaseRole::migration;

        WHEN("migrator plans are built")
        {
            auto const runtime_plan = merovingian::database::build_offline_migration_plan(runtime_config, 0U, 1U, {});
            auto const migration_plan =
                merovingian::database::build_offline_migration_plan(migration_config, 0U, 1U, {});

            THEN("only the migration role may run schema changes")
            {
                REQUIRE_FALSE(runtime_plan.ok);
                REQUIRE(runtime_plan.reason == "database migration requires database.role=migration");
                REQUIRE(migration_plan.ok);
                REQUIRE(migration_plan.plan.target_version == 1U);
            }
        }
    }
}

SCENARIO("Database schema inventory covers the core Matrix tables", "[database][schema]")
{
    GIVEN("the initial schema inventory")
    {
        WHEN("core table membership is queried")
        {
            auto const tables = merovingian::database::initial_schema_tables();
            auto const users_definition = merovingian::database::schema_table_definition("users");
            auto const current_state_definition = merovingian::database::schema_table_definition("current_state");
            auto const room_aliases_definition = merovingian::database::schema_table_definition("room_aliases");
            auto const users_sql = users_definition.has_value()
                                       ? merovingian::database::create_table_sql(users_definition.value())
                                       : std::nullopt;
            auto const current_state_columns = current_state_definition.has_value()
                                                   ? current_state_definition.value().columns_sql
                                                   : std::string_view{};
            auto const unknown_is_core = merovingian::database::schema_table_is_core("not_a_table");

            THEN("required Matrix storage areas have table-specific definitions")
            {
                // 45 = the 37 baseline tables plus four sync-surface tables,
                // plus durable media blob storage plus the user profiles table
                // plus the durable room-alias registry plus client_txn_ids
                // (room_account_data, to_device_messages, device_list_changes,
                // presence_state) folded into the v1 initial schema.
                // sync_stream_watermark arrives in migration v2 and is counted in
                // the current schema inventory instead.
                REQUIRE(tables.size() == 45U);
                REQUIRE(merovingian::database::current_schema_version() == 2U);
                REQUIRE(merovingian::database::current_schema_tables().size() == 46U);
                REQUIRE(users_definition.has_value());
                REQUIRE(current_state_definition.has_value());
                REQUIRE(room_aliases_definition.has_value());
                REQUIRE(users_sql.has_value());
                REQUIRE(users_sql->find("user_id TEXT PRIMARY KEY") != std::string::npos);
                REQUIRE(current_state_columns.find("PRIMARY KEY (room_id, event_type, state_key)") !=
                        std::string_view::npos);
                REQUIRE_FALSE(unknown_is_core);
            }
        }
    }
}

SCENARIO("SQLite identifier quoting and DDL allowlisting reject malicious identifiers", "[database][schema]")
{
    GIVEN("safe and malicious table identifiers")
    {
        auto const safe = merovingian::database::quote_sqlite_identifier("users");
        auto const with_underscore = merovingian::database::quote_sqlite_identifier("client_txn_ids");
        auto const empty = merovingian::database::quote_sqlite_identifier("");
        auto const with_semicolon = merovingian::database::quote_sqlite_identifier("users; DROP TABLE users;--");
        auto const with_quote = merovingian::database::quote_sqlite_identifier("bad\"name");

        WHEN("they are validated against the core table allowlist and identifier grammar")
        {
            auto const users_definition = merovingian::database::schema_table_definition("users");
            auto const malicious_definition =
                merovingian::database::SchemaTableDefinition{"users; DROP TABLE users;--", "user_id TEXT PRIMARY KEY"};
            auto const safe_sql = users_definition.has_value()
                                      ? merovingian::database::create_table_sql(users_definition.value())
                                      : std::nullopt;
            auto const malicious_sql = merovingian::database::create_table_sql(malicious_definition);
            auto const unknown_is_core = merovingian::database::schema_table_is_core("users; DROP TABLE users;--");

            THEN("safe identifiers are quoted and malicious inputs are rejected")
            {
                REQUIRE(safe.has_value());
                REQUIRE(safe.value() == "\"users\"");
                REQUIRE(with_underscore.has_value());
                REQUIRE(with_underscore.value() == "\"client_txn_ids\"");
                REQUIRE_FALSE(empty.has_value());
                REQUIRE_FALSE(with_semicolon.has_value());
                REQUIRE_FALSE(with_quote.has_value());

                REQUIRE(safe_sql.has_value());
                REQUIRE(safe_sql->find("\"users\"") != std::string::npos);
                REQUIRE_FALSE(malicious_sql.has_value());
                REQUIRE_FALSE(unknown_is_core);
            }
        }
    }
}

SCENARIO("SQLite migration step failure rolls back the ledger row", "[database][persistence][migration][sqlite]")
{
    GIVEN("a fresh SQLite file with a pre-existing core table that forces apply_pending_migrations")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);

        // Seed the file with an existing 'users' table so the store-opening
        // path takes the migration route instead of the bootstrap route.
        sqlite3* seed = nullptr;
        REQUIRE(sqlite3_open(sqlite_path.string().c_str(), &seed) == SQLITE_OK);
        REQUIRE(sqlite3_exec(seed, "CREATE TABLE users (user_id TEXT PRIMARY KEY)", nullptr, nullptr, nullptr) ==
                SQLITE_OK);
        sqlite3_close(seed);

        WHEN("opening the store and the initial migration step fails mid-step")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());

            THEN("the store is rejected")
            {
                REQUIRE_FALSE(opened.ok);
            }

            AND_WHEN("the database is reopened to inspect the ledger")
            {
                sqlite3* raw = nullptr;
                REQUIRE(sqlite3_open(sqlite_path.string().c_str(), &raw) == SQLITE_OK);
                sqlite3_stmt* statement = nullptr;
                REQUIRE(sqlite3_prepare_v2(raw,
                                           "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = "
                                           "'schema_migrations'",
                                           -1, &statement, nullptr) == SQLITE_OK);
                auto ledger_tables = std::int64_t{0};
                if (sqlite3_step(statement) == SQLITE_ROW)
                {
                    ledger_tables = sqlite3_column_int64(statement, 0);
                }
                sqlite3_finalize(statement);
                sqlite3_close(raw);

                THEN("no migration ledger table was committed")
                {
                    REQUIRE(ledger_tables == 0);
                }
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Persistent store upserts inbound invite metadata for sync replay", "[database][persistence][invite]")
{
    GIVEN("an open store and an invited local user")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);

        auto invite = merovingian::database::PersistentInvite{
            "!remote:example.org",
            "@alice:example.org",
            "@bob:remote.example.org",
            "$invite:remote.example.org",
            R"({"event_id":"$invite:remote.example.org","type":"m.room.member","content":{"membership":"invite"}})",
            {
              R"({"type":"m.room.create","state_key":"","content":{"creator":"@bob:remote.example.org","room_version":"12"}})",
              R"({"type":"m.room.name","state_key":"","content":{"name":"Remote DM"}})", },
            7U,
        };

        WHEN("the invite is stored, updated, and queried for the invited user")
        {
            REQUIRE(merovingian::database::upsert_invite(opened.store, invite));

            invite.invite_state_events_json[1] =
                R"({"type":"m.room.name","state_key":"","content":{"name":"Remote DM Updated"}})";
            invite.stream_ordering = 8U;
            REQUIRE(merovingian::database::upsert_invite(opened.store, invite));
            auto const stored =
                merovingian::database::find_invite(opened.store, "!remote:example.org", "@alice:example.org");

            THEN("the signed invite event and stripped state round-trip through the store")
            {
                REQUIRE(stored.has_value());
                REQUIRE(stored->event_id == "$invite:remote.example.org");
                REQUIRE(stored->signed_event_json.find("\"membership\":\"invite\"") != std::string::npos);
                REQUIRE(stored->invite_state_events_json.size() == 2U);
                REQUIRE(stored->invite_state_events_json[1].find("Remote DM Updated") != std::string::npos);
                REQUIRE(stored->stream_ordering == 8U);
            }
        }
    }
}

SCENARIO("Persistent store includes event depth in event statements", "[database][persistence][events]")
{
    GIVEN("an opened persistent store with a room")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;
        REQUIRE(merovingian::database::store_room(store, {"!room-depth:example.org", "@alice:example.org"}));

        WHEN("events with explicit depth are stored")
        {
            auto const event_ok = merovingian::database::store_event(store, {"$depth1:example.org",
                                                                             "!room-depth:example.org",
                                                                             "@alice:example.org",
                                                                             R"({"type":"m.room.message"})",
                                                                             1U,
                                                                             0U,
                                                                             {},
                                                                             {},
                                                                             {}});
            auto const event_ok2 = merovingian::database::store_event(store, {"$depth2:example.org",
                                                                              "!room-depth:example.org",
                                                                              "@alice:example.org",
                                                                              R"({"type":"m.room.message"})",
                                                                              5U,
                                                                              0U,
                                                                              {},
                                                                              {},
                                                                              {}});

            THEN("depth is persisted in the event row and recoverable after storage")
            {
                REQUIRE(event_ok);
                REQUIRE(event_ok2);
                REQUIRE(store.events.size() == 2U);
                REQUIRE(store.events.front().depth == 1U);
                REQUIRE(store.events.back().depth == 5U);
                REQUIRE(store.prepared_statements.back().sql.find("$5") != std::string::npos);
            }
        }
    }
}

SCENARIO("Server signing key secret survives a database restart", "[database][persistence][signing-key][restart]")
{
    GIVEN("a SQLite persistent store with a server signing key that includes a stored secret")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);
        auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
        REQUIRE(opened.ok);

        // The secret is stored as unpadded standard base64 text so that null bytes embedded
        // in raw Ed25519 key material do not truncate the value when read back via C string APIs.
        // This string decodes to binary data whose first three bytes are 0x00 0x01 0x02.
        auto constexpr stored_secret = std::string_view{"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"};
        auto const key = merovingian::database::PersistentServerSigningKey{
            "pong.example.org", "ed25519:auto", "public-key-base64", 32503680000000ULL, std::string{stored_secret}};
        auto const stored_ok = merovingian::database::store_server_signing_key(opened.store, key);

        WHEN("the database is reopened to simulate a server restart")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);
            auto const found =
                merovingian::database::find_server_signing_key(reopened.store, "pong.example.org", "ed25519:auto");

            THEN("the public key and its base64-encoded secret are both hydrated from disk without truncation")
            {
                REQUIRE(stored_ok);
                REQUIRE(found.has_value());
                REQUIRE(found->public_key == "public-key-base64");
                REQUIRE(found->secret_key == stored_secret);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("store_server_signing_key preserves an existing secret when upserted with an empty secret",
         "[database][persistence][signing-key]")
{
    GIVEN("an in-memory store with a signing key that has a stored secret")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        // Secret is stored as base64 text, matching what room_service stores via ensure_runtime_server_signing_key.
        auto constexpr original_secret = std::string_view{"c2VjcmV0LWtleS1pbi1iYXNlNjQ"};
        auto const initial_ok = merovingian::database::store_server_signing_key(
            store, {"example.org", "ed25519:auto", "pub-v1", 32503680000000ULL, std::string{original_secret}});
        REQUIRE(initial_ok);

        WHEN("the same key is upserted with a new public key but no secret")
        {
            auto const ok = merovingian::database::store_server_signing_key(
                store, {"example.org", "ed25519:auto", "pub-v2", 32503680000000ULL, {}});
            auto const found = merovingian::database::find_server_signing_key(store, "example.org", "ed25519:auto");

            THEN("the public key is updated and the existing base64 secret is preserved")
            {
                REQUIRE(ok);
                REQUIRE(found.has_value());
                REQUIRE(found->public_key == "pub-v2");
                REQUIRE(found->secret_key == original_secret);
            }
        }
    }
}

SCENARIO("Server signing keys are looked up by server identity and key ID", "[database][persistence][signing-key]")
{
    GIVEN("an opened persistent store with signing keys for different servers")
    {
        auto opened = merovingian::database::open_persistent_store();
        REQUIRE(opened.ok);
        auto& store = opened.store;

        auto const key_a_ok = merovingian::database::store_server_signing_key(
            store, {"server-a.org", "ed25519:auto", "public-key-a", 32503680000000ULL});
        auto const key_b_ok = merovingian::database::store_server_signing_key(
            store, {"server-b.org", "ed25519:auto", "public-key-b", 32503680000000ULL});

        WHEN("keys are looked up by server name and key ID")
        {
            auto const found_a = merovingian::database::find_server_signing_key(store, "server-a.org", "ed25519:auto");
            auto const found_b = merovingian::database::find_server_signing_key(store, "server-b.org", "ed25519:auto");
            auto const not_found =
                merovingian::database::find_server_signing_key(store, "server-c.org", "ed25519:auto");

            THEN("each server has its own key and unrelated lookups return nothing")
            {
                REQUIRE(key_a_ok);
                REQUIRE(key_b_ok);
                REQUIRE(found_a.has_value());
                REQUIRE(found_a->server_name == "server-a.org");
                REQUIRE(found_a->public_key == "public-key-a");
                REQUIRE(found_b.has_value());
                REQUIRE(found_b->server_name == "server-b.org");
                REQUIRE(found_b->public_key == "public-key-b");
                REQUIRE_FALSE(not_found.has_value());
            }
        }
    }
}

SCENARIO("SQLite migration bootstrap records the applied migration in schema_migrations",
         "[database][persistence][migration][sqlite]")
{
    GIVEN("a fresh SQLite persistent store that triggers the initial migration")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);

        WHEN("the store is opened and the initial schema migration is applied")
        {
            auto const opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(opened.ok);

            THEN("the schema_migrations row is written with the initial_schema name and upgrade direction")
            {
                // Open a separate raw connection to inspect schema_migrations
                // directly. The store's own in-memory state was populated
                // from the same migration step, so we just need to confirm
                // the row landed.
                sqlite3* raw = nullptr;
                REQUIRE(sqlite3_open(sqlite_path.string().c_str(), &raw) == SQLITE_OK);
                auto const* select_sql = "SELECT name FROM schema_migrations";
                sqlite3_stmt* statement = nullptr;
                REQUIRE(sqlite3_prepare_v2(raw, select_sql, -1, &statement, nullptr) == SQLITE_OK);
                auto saw_initial_schema = false;
                while (sqlite3_step(statement) == SQLITE_ROW)
                {
                    auto const* name = reinterpret_cast<char const*>(sqlite3_column_text(statement, 0));
                    if (name != nullptr && std::string{name} == "initial_schema")
                    {
                        saw_initial_schema = true;
                    }
                }
                sqlite3_finalize(statement);
                sqlite3_close(raw);
                REQUIRE(saw_initial_schema);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("Sync stream watermark prevents sync-stream id rollback across SQLite restart",
         "[database][persistence][sync-stream][watermark][regression]")
{
    GIVEN("a SQLite persistent store that has advanced the sync stream counter")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);

        {
            auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(opened.ok);
            auto& store = opened.store;

            // Allocate several sync-stream ids through different surfaces so the
            // watermark table records a value greater than zero.
            REQUIRE(merovingian::database::store_account_data(
                store, {"@alice:example.org", "", "m.push_rules", R"({\"global\":{\"override\":[]}})", 0U}));
            REQUIRE(merovingian::database::store_account_data(
                store, {"@alice:example.org", "!room:example.org", "m.tag", R"({\"tags\":{}})", 0U}));
            REQUIRE(merovingian::database::record_device_list_change(
                store, {0U, "@alice:example.org", "@bob:example.org", "changed"}));
            REQUIRE(
                merovingian::database::upsert_presence(store, {0U, "@alice:example.org", "online", "here", 0, true}));

            REQUIRE(store.next_sync_stream_id == 4U);
        }

        WHEN("the store is reopened after all handles are dropped")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);
            auto& store = reopened.store;

            THEN("the restored counter is at least the previously persisted watermark and allocations continue "
                 "monotonically")
            {
                REQUIRE(store.next_sync_stream_id >= 4U);

                auto const next_id = merovingian::database::allocate_sync_stream_id(store);
                REQUIRE(next_id > 4U);
                REQUIRE(store.next_sync_stream_id == next_id);

                // Confirm the watermark row itself was updated to the new value.
                sqlite3* raw = nullptr;
                REQUIRE(sqlite3_open(sqlite_path.string().c_str(), &raw) == SQLITE_OK);
                auto const* select_sql = "SELECT watermark FROM sync_stream_watermark WHERE singleton = 1";
                sqlite3_stmt* statement = nullptr;
                REQUIRE(sqlite3_prepare_v2(raw, select_sql, -1, &statement, nullptr) == SQLITE_OK);
                auto watermark = std::uint64_t{0U};
                if (sqlite3_step(statement) == SQLITE_ROW)
                {
                    auto const* text = reinterpret_cast<char const*>(sqlite3_column_text(statement, 0));
                    if (text != nullptr)
                    {
                        watermark = static_cast<std::uint64_t>(std::stoull(text));
                    }
                }
                sqlite3_finalize(statement);
                sqlite3_close(raw);
                REQUIRE(watermark == next_id);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("ensure_sync_stream_id_ahead_of recovers from a counter rollback",
         "[database][persistence][sync-stream][watermark][regression]")
{
    GIVEN("a SQLite persistent store whose watermark is lower than a client's since-token")
    {
        auto const sqlite_path = unique_sqlite_path();
        std::filesystem::remove(sqlite_path);

        {
            auto opened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(opened.ok);
            auto& store = opened.store;

            // Push the watermark up to a known value.
            REQUIRE(merovingian::database::allocate_sync_stream_id(store) == 1U);
            REQUIRE(merovingian::database::allocate_sync_stream_id(store) == 2U);
            REQUIRE(merovingian::database::allocate_sync_stream_id(store) == 3U);
        }

        WHEN("the store is reopened and a client presents a since-token ahead of the watermark")
        {
            auto reopened = merovingian::database::open_sqlite_persistent_store(sqlite_path.string());
            REQUIRE(reopened.ok);
            auto& store = reopened.store;
            REQUIRE(store.next_sync_stream_id == 3U);

            auto const client_since = std::uint64_t{10U};
            REQUIRE(merovingian::database::ensure_sync_stream_id_ahead_of(store, client_since));

            THEN("the counter advances to the client's position and the watermark is persisted")
            {
                REQUIRE(store.next_sync_stream_id == client_since);

                sqlite3* raw = nullptr;
                REQUIRE(sqlite3_open(sqlite_path.string().c_str(), &raw) == SQLITE_OK);
                auto const* select_sql = "SELECT watermark FROM sync_stream_watermark WHERE singleton = 1";
                sqlite3_stmt* statement = nullptr;
                REQUIRE(sqlite3_prepare_v2(raw, select_sql, -1, &statement, nullptr) == SQLITE_OK);
                auto watermark = std::uint64_t{0U};
                if (sqlite3_step(statement) == SQLITE_ROW)
                {
                    auto const* text = reinterpret_cast<char const*>(sqlite3_column_text(statement, 0));
                    if (text != nullptr)
                    {
                        watermark = static_cast<std::uint64_t>(std::stoull(text));
                    }
                }
                sqlite3_finalize(statement);
                sqlite3_close(raw);
                REQUIRE(watermark == client_since);
            }

            THEN("the next allocated sync-stream id is strictly greater than the client's since-token")
            {
                REQUIRE(merovingian::database::allocate_sync_stream_id(store) == client_since + 1U);
            }
        }

        std::filesystem::remove(sqlite_path);
    }
}

SCENARIO("repair_missing_state_entries creates state entries for events with state_key='' that have none",
         "[database][persistent_store][repair][regression]")
{
    GIVEN("a store with m.room.create and m.room.power_levels events stored but missing state entries, a member event "
          "with an existing state entry, and a non-state message event")
    {
        auto store = merovingian::database::PersistentStore{};
        store.open = true;
        store.backend = merovingian::database::PersistentStoreBackend::memory;

        auto const room_id = std::string{"!repair_test:example.org"};

        store.events.push_back({.event_id = "$create:example.org",
                                .room_id = room_id,
                                .sender_user_id = "@james:example.org",
                                .json = R"({"type":"m.room.create","state_key":"","content":{"room_version":"10"}})",
                                .depth = 1U,
                                .stream_ordering = 1U});
        store.events.push_back({.event_id = "$power_levels:example.org",
                                .room_id = room_id,
                                .sender_user_id = "@james:example.org",
                                .json = R"({"type":"m.room.power_levels","state_key":"","content":{}})",
                                .depth = 2U,
                                .stream_ordering = 2U});
        store.events.push_back(
            {.event_id = "$member:example.org",
             .room_id = room_id,
             .sender_user_id = "@james:example.org",
             .json = R"({"type":"m.room.member","state_key":"@james:example.org","content":{"membership":"join"}})",
             .depth = 3U,
             .stream_ordering = 3U});
        // Non-state event — no state_key field in JSON.
        store.events.push_back({.event_id = "$message:example.org",
                                .room_id = room_id,
                                .sender_user_id = "@james:example.org",
                                .json = R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"hello"}})",
                                .depth = 4U,
                                .stream_ordering = 4U});

        // Member state entry exists; create/power_levels entries are missing.
        store.state.push_back({room_id, "m.room.member", "@james:example.org", "$member:example.org"});

        WHEN("repair_missing_state_entries is called")
        {
            auto const repaired = merovingian::database::repair_missing_state_entries(store);

            THEN("exactly two state entries are created for the events that had none")
            {
                REQUIRE(repaired == 2U);
            }

            THEN("the m.room.create state entry points to the create event")
            {
                auto const has_create = std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.create" && s.state_key.empty() &&
                           s.event_id == "$create:example.org";
                });
                REQUIRE(has_create);
            }

            THEN("the m.room.power_levels state entry points to the power_levels event")
            {
                auto const has_pl = std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.power_levels" && s.state_key.empty() &&
                           s.event_id == "$power_levels:example.org";
                });
                REQUIRE(has_pl);
            }

            THEN("no state entry is created for the non-state message event")
            {
                auto const has_message = std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.event_id == "$message:example.org";
                });
                REQUIRE_FALSE(has_message);
            }

            THEN("the total state entry count is three (two repaired plus the pre-existing member)")
            {
                REQUIRE(store.state.size() == 3U);
            }

            AND_WHEN("repair is called a second time")
            {
                auto const repaired_again = merovingian::database::repair_missing_state_entries(store);

                THEN("no additional entries are created because the repair is idempotent")
                {
                    REQUIRE(repaired_again == 0U);
                }
            }
        }
    }
}

SCENARIO("repair_missing_state_entries selects the highest stream_ordering event when multiple events share the "
         "same (room_id, type, state_key) tuple",
         "[database][persistent_store][repair][regression]")
{
    GIVEN("a store with an older join and a newer leave event for the same user, both missing a state entry")
    {
        auto store = merovingian::database::PersistentStore{};
        store.open = true;
        store.backend = merovingian::database::PersistentStoreBackend::memory;

        auto const room_id = std::string{"!ordering_test:example.org"};

        store.events.push_back(
            {.event_id = "$join_old:example.org",
             .room_id = room_id,
             .sender_user_id = "@alice:example.org",
             .json = R"({"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"join"}})",
             .depth = 1U,
             .stream_ordering = 1U});
        store.events.push_back(
            {.event_id = "$leave:example.org",
             .room_id = room_id,
             .sender_user_id = "@alice:example.org",
             .json = R"({"type":"m.room.member","state_key":"@alice:example.org","content":{"membership":"leave"}})",
             .depth = 2U,
             .stream_ordering = 5U});

        WHEN("repair_missing_state_entries is called")
        {
            auto const repaired = merovingian::database::repair_missing_state_entries(store);

            THEN("exactly one state entry is created for the (room, type, state_key) tuple")
            {
                REQUIRE(repaired == 1U);
            }

            THEN("the state entry points to the event with the higher stream_ordering (the leave)")
            {
                auto const has_leave = std::ranges::any_of(store.state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" &&
                           s.state_key == "@alice:example.org" && s.event_id == "$leave:example.org";
                });
                REQUIRE(has_leave);
            }
        }
    }
}
