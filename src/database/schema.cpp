// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/schema.hpp"

#include <algorithm>
#include <array>

namespace merovingian::database
{
namespace
{

    // Every pre-1.0 migration was collapsed into v1 in 0.12.47 (ADR-0224). From
    // 1.0.0 the v1 step is frozen: a schema change is a new numbered migration,
    // never an edit to core_tables that changes what v1 creates.
    constexpr auto schema_version = std::uint32_t{1U};

    constexpr auto core_tables = std::array{
        SchemaTableDefinition{"schema_migrations",
                              "version TEXT PRIMARY KEY, name TEXT NOT NULL, direction TEXT NOT NULL"                                                                   },
        SchemaTableDefinition{
                              "users",                   "user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, locked TEXT NOT NULL, "
                     "suspended TEXT NOT NULL, admin TEXT NOT NULL, deactivated TEXT NOT NULL DEFAULT 'false'"                    },
        SchemaTableDefinition{"devices",                 "user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT NOT NULL, "
                                         "PRIMARY KEY (user_id, device_id)"                                                     },
        SchemaTableDefinition{
                              "access_tokens",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, revoked TEXT NOT NULL, "
            "expires_at TEXT NOT NULL DEFAULT '', predecessor_refresh_hash TEXT NOT NULL DEFAULT ''"                      },
        SchemaTableDefinition{
                              "refresh_tokens",          "token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, revoked TEXT NOT NULL, "
            "expires_at TEXT NOT NULL DEFAULT '', predecessor_hash TEXT NOT NULL DEFAULT ''"                             },
        SchemaTableDefinition{"server_signing_keys",
                              "server_name TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, "
                              "valid_until_ts TEXT NOT NULL, secret_key BLOB NOT NULL DEFAULT '', "
                              "PRIMARY KEY (server_name, key_id)"                                                                                                       },
        SchemaTableDefinition{
                              "rooms",                   "room_id TEXT PRIMARY KEY, creator_user_id TEXT NOT NULL, directory_public TEXT NOT NULL DEFAULT 'false'"      },
        SchemaTableDefinition{
                              "room_aliases",            "room_alias TEXT PRIMARY KEY, room_id TEXT NOT NULL, creator_user_id TEXT NOT NULL DEFAULT ''"                 },
        SchemaTableDefinition{"room_versions",           "room_id TEXT PRIMARY KEY, version TEXT NOT NULL"                                                              },
        SchemaTableDefinition{
                              "events",                  "event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, json TEXT "
            "NOT NULL, depth TEXT NOT NULL, stream_ordering TEXT NOT NULL DEFAULT '0', status TEXT NOT NULL DEFAULT "
            "'accepted'"                                                                                                         },
        SchemaTableDefinition{"event_json",              "event_id TEXT PRIMARY KEY, json TEXT NOT NULL"                                                                },
        SchemaTableDefinition{
                              "event_edges",             "event_id TEXT NOT NULL, prev_event_id TEXT NOT NULL, PRIMARY KEY (event_id, prev_event_id)"                   },
        SchemaTableDefinition{
                              "event_auth",              "event_id TEXT NOT NULL, auth_event_id TEXT NOT NULL, PRIMARY KEY (event_id, auth_event_id)"                   },
        SchemaTableDefinition{"event_signatures",
                              "event_id TEXT NOT NULL, server_name TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT "
                              "NOT NULL, PRIMARY KEY (event_id, server_name, key_id)"                                                                                   },
        SchemaTableDefinition{"current_state",
                              "room_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT "
                              "NOT NULL, PRIMARY KEY (room_id, event_type, state_key)"                                                                                  },
        SchemaTableDefinition{
                              "state_transitions",       "room_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT NOT "
            "NULL, previous_event_id TEXT NOT NULL DEFAULT '', PRIMARY KEY (room_id, event_type, state_key, event_id)"},
        SchemaTableDefinition{"account_threepids",
                              "user_id TEXT NOT NULL, medium TEXT NOT NULL, address TEXT NOT NULL, "
                              "country TEXT NOT NULL DEFAULT '', id_server TEXT NOT NULL DEFAULT '', "
                              "added_at_ms TEXT NOT NULL DEFAULT '0', validated_at_ms TEXT NOT NULL DEFAULT '0', "
                              "bound TEXT NOT NULL DEFAULT '0', client_secret TEXT NOT NULL DEFAULT '', "
                              "sid TEXT NOT NULL DEFAULT '', PRIMARY KEY (user_id, medium, address)"                                                                    },
        SchemaTableDefinition{
                              "state_groups",            "state_group_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, parent_state_group_id TEXT NOT NULL DEFAULT '', "
            "delta_depth TEXT NOT NULL DEFAULT '0'"                                                                        },
        SchemaTableDefinition{"state_group_edges",       "state_group_id TEXT NOT NULL, prev_state_group_id TEXT NOT NULL, "
                                                   "PRIMARY KEY (state_group_id, prev_state_group_id)"                },
        SchemaTableDefinition{"membership",
                              "room_id TEXT NOT NULL, user_id TEXT NOT NULL, membership TEXT NOT NULL DEFAULT 'join', "
                              "stream_ordering TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, user_id)"                                                               },
        SchemaTableDefinition{"invites",
                              "room_id TEXT NOT NULL, user_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, "
                              "event_id TEXT NOT NULL DEFAULT '', signed_event_json TEXT NOT NULL DEFAULT '', "
                              "invite_state_json TEXT NOT NULL DEFAULT '[]', stream_ordering TEXT NOT NULL "
                              "DEFAULT '0', resident_server TEXT NOT NULL DEFAULT '', "
                              "PRIMARY KEY (room_id, user_id)"                                                                                                          },
        SchemaTableDefinition{"account_data",
                              "user_id TEXT NOT NULL, event_type TEXT NOT NULL, json TEXT NOT NULL, stream_id TEXT "
                              "NOT NULL DEFAULT '0', PRIMARY KEY (user_id, event_type)"                                                                                 },
        SchemaTableDefinition{"room_account_data",
                              "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, stream_id TEXT "
                              "NOT NULL DEFAULT '0', json TEXT NOT NULL, PRIMARY KEY (user_id, room_id, event_type)"                                                    },
        SchemaTableDefinition{
                              "push_rules",              "user_id TEXT NOT NULL, rule_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, rule_id)"             },
        SchemaTableDefinition{
                              "filters",                 "user_id TEXT NOT NULL, filter_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, filter_id)"         },
        SchemaTableDefinition{"device_keys",             "user_id TEXT NOT NULL, device_id TEXT NOT NULL, json TEXT NOT NULL, "
                                             "PRIMARY KEY (user_id, device_id)"                                             },
        SchemaTableDefinition{"one_time_keys",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, "
                                               "json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id)"             },
        SchemaTableDefinition{"fallback_keys",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, "
                                               "json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id)"             },
        SchemaTableDefinition{
                              "cross_signing_keys",      "user_id TEXT NOT NULL, key_type TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, key_type)"           },
        SchemaTableDefinition{
                              "key_signatures",          "signer_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, target_device_id TEXT NOT NULL, "
            "json TEXT NOT NULL, PRIMARY KEY (signer_user_id, target_user_id, target_device_id)"                         },
        SchemaTableDefinition{
                              "key_backups",             "user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version)"             },
        SchemaTableDefinition{
                              "key_backup_versions",     "user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version)"             },
        SchemaTableDefinition{
                              "key_backup_sessions",     "user_id TEXT NOT NULL, version TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL, "
            "json TEXT NOT NULL, PRIMARY KEY (user_id, version, room_id, session_id)"                               },
        SchemaTableDefinition{
                              "media",                   "media_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, content_type TEXT NOT "
                     "NULL, size_bytes TEXT NOT NULL, hash_algorithm TEXT NOT NULL, digest TEXT NOT "
                     "NULL, quarantined TEXT NOT NULL, removed TEXT NOT NULL, legacy_endpoint_visible TEXT NOT NULL "
                     "DEFAULT 'true', upload_name TEXT NOT NULL DEFAULT ''"                                                       },
        SchemaTableDefinition{"media_blobs",
                              "storage_id TEXT PRIMARY KEY, hash_algorithm TEXT NOT NULL, digest TEXT NOT NULL, "
                              "size_bytes TEXT NOT NULL, bytes BLOB NOT NULL, ref_count TEXT NOT NULL"                                                                  },
        SchemaTableDefinition{
                              "remote_media",            "server_name TEXT NOT NULL, media_id TEXT NOT NULL, content_type TEXT NOT NULL, size_bytes "
            "TEXT NOT NULL, quarantined TEXT NOT NULL, local_media_id TEXT NOT NULL DEFAULT '', fetched_at_ms "
            "TEXT NOT NULL DEFAULT '0', PRIMARY KEY (server_name, media_id)"                                               },
        SchemaTableDefinition{"federation_destinations",
                              "server_name TEXT PRIMARY KEY, state TEXT NOT NULL, retry_after_ts TEXT NOT NULL, "
                              "last_success_ts TEXT NOT NULL, consecutive_failures TEXT NOT NULL"                                                                       },
        SchemaTableDefinition{"federation_transactions",
                              "transaction_id TEXT PRIMARY KEY, server_name TEXT NOT NULL, json TEXT NOT NULL, "
                              "method TEXT NOT NULL, target TEXT NOT NULL, origin TEXT NOT NULL, "
                              "origin_server_ts TEXT NOT NULL, body TEXT NOT NULL, retry_count TEXT NOT NULL, "
                              "next_retry_ts TEXT NOT NULL"                                                                                                             },
        SchemaTableDefinition{"rate_limits",             "scope TEXT NOT NULL, key TEXT NOT NULL, count TEXT NOT NULL, reset_ts "
                                             "TEXT NOT NULL, PRIMARY KEY (scope, key)"                                      },
        SchemaTableDefinition{"audit_log",               "category TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, "
                                           "target TEXT NOT NULL, reason TEXT NOT NULL"                                       },
        SchemaTableDefinition{"policy_rules",            "rule_id TEXT PRIMARY KEY, scope TEXT NOT NULL, entity TEXT NOT NULL, "
                                              "action TEXT NOT NULL, reason TEXT NOT NULL"                                 },
        SchemaTableDefinition{"admin_actions",
                              "admin_user_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL"                                                                 },
        SchemaTableDefinition{"to_device_messages",
                              "stream_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, "
                              "target_device_id TEXT NOT NULL DEFAULT '', message_type TEXT NOT NULL, content TEXT "
                              "NOT NULL, created_at_ms TEXT NOT NULL DEFAULT '0', "
                              "PRIMARY KEY (stream_id, target_user_id, target_device_id)"                                                                               },
        SchemaTableDefinition{"device_list_changes",
                              "stream_id TEXT NOT NULL, observer_user_id TEXT NOT NULL, "
                              "subject_user_id TEXT NOT NULL, change_type TEXT NOT NULL DEFAULT 'changed', "
                              "PRIMARY KEY (stream_id, observer_user_id, subject_user_id)"                                                                              },
        SchemaTableDefinition{"presence_state",
                              "user_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL DEFAULT '0', presence TEXT NOT NULL "
                              "DEFAULT 'offline', status_msg TEXT NOT NULL DEFAULT '', last_active_ago TEXT NOT NULL "
                              "DEFAULT '0', currently_active TEXT NOT NULL DEFAULT 'false'"                                                                             },
        SchemaTableDefinition{
                              "sync_stream_watermark",   "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), watermark TEXT NOT NULL DEFAULT '0'"                     },
        SchemaTableDefinition{
                              "event_stream_watermark",  "singleton INTEGER PRIMARY KEY CHECK (singleton = 1), watermark TEXT NOT NULL DEFAULT '0'"                     },
        SchemaTableDefinition{"profiles",                "user_id TEXT PRIMARY KEY, displayname TEXT NOT NULL DEFAULT '', "
                                          "avatar_url TEXT NOT NULL DEFAULT ''"                                                },
        SchemaTableDefinition{"client_txn_ids",
                              "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, "
                              "txn_id TEXT NOT NULL, event_id TEXT NOT NULL, "
                              "PRIMARY KEY (user_id, room_id, event_type, txn_id)"                                                                                      },
        SchemaTableDefinition{"pushers",
                              "user_id TEXT NOT NULL, app_id TEXT NOT NULL, pushkey TEXT NOT NULL, "
                              "kind TEXT NOT NULL, app_display_name TEXT NOT NULL DEFAULT '', "
                              "device_display_name TEXT NOT NULL DEFAULT '', profile_tag TEXT NOT NULL DEFAULT '', "
                              "lang TEXT NOT NULL DEFAULT '', data_url TEXT NOT NULL DEFAULT '', "
                              "data_format TEXT NOT NULL DEFAULT '', data_extra_json TEXT NOT NULL DEFAULT '', "
                              "PRIMARY KEY (user_id, app_id, pushkey)"                                                                                                  },
        SchemaTableDefinition{"notifications",
                              "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_id TEXT NOT NULL, "
                              "stream_ordering TEXT NOT NULL DEFAULT '0', ts TEXT NOT NULL DEFAULT '0', "
                              "actions TEXT NOT NULL DEFAULT '[]', profile_tag TEXT NOT NULL DEFAULT '', "
                              "highlight TEXT NOT NULL DEFAULT 'false', PRIMARY KEY (user_id, event_id)"                                                                },
        SchemaTableDefinition{"openid_tokens",           "user_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, "
                                               "expires_at TEXT NOT NULL DEFAULT '0'"                                     },
        SchemaTableDefinition{"login_tokens",
                              "user_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, expires_at TEXT NOT NULL "
                              "DEFAULT '0', used TEXT NOT NULL DEFAULT 'false'"                                                                                         },
        SchemaTableDefinition{"appservice_txn_cursor",
                              "appservice_id TEXT NOT NULL PRIMARY KEY, next_txn_id TEXT NOT NULL DEFAULT '1', "
                              "delivered_stream_ordering TEXT NOT NULL DEFAULT '0', pending_txn_id TEXT NOT NULL "
                              "DEFAULT '0', pending_stream_ordering TEXT NOT NULL DEFAULT '0'"                                                                          },
        // ADR-0064: a state group's own delta rows (or, for a snapshot
        // group, its full state). See database::create_or_reuse_state_group.
        SchemaTableDefinition{"state_group_state",
                              "state_group_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, "
                              "event_id TEXT NOT NULL, PRIMARY KEY (state_group_id, event_type, state_key)"                                                             },
        // ADR-0064: maps an event to the state group holding the
        // room's state immediately after it.
        SchemaTableDefinition{"event_state_groups",      "event_id TEXT PRIMARY KEY, state_group_id TEXT NOT NULL"                                                      },
        // ADR-0064: a room's current forward extremities (DAG leaves).
        SchemaTableDefinition{"forward_extremities",
                              "room_id TEXT NOT NULL, event_id TEXT NOT NULL, PRIMARY KEY (room_id, event_id)"                                                          },
        // Audit R01: one row per event queued for an appservice. stream_ordering is TEXT like every
        // other numeric column here (BoundValue is text); the store orders numerically in memory.
        SchemaTableDefinition{"appservice_outbox",
                              "appservice_id TEXT NOT NULL, stream_ordering TEXT NOT NULL, event_id TEXT NOT NULL, "
                              "PRIMARY KEY (appservice_id, stream_ordering)"                                                                                            },
        // R03, ADR-0165: a federation PDU main could not yet place and keeps
        // for a retry. Numbers are TEXT like every other numeric column here.
        SchemaTableDefinition{"deferred_pdus",
                              "event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, origin TEXT NOT NULL, "
                              "pdu_json TEXT NOT NULL, received_at_ms TEXT NOT NULL DEFAULT '0', "
                              "attempts TEXT NOT NULL DEFAULT '0'"                                                                                                      },
        // ADR-0169: one read receipt per (room, type, user, thread). An
        // unthreaded receipt has thread_id ''. Numbers are TEXT like every other
        // numeric column here.
        SchemaTableDefinition{
                              "receipts",                "room_id TEXT NOT NULL, receipt_type TEXT NOT NULL, user_id TEXT NOT NULL, "
                        "thread_id TEXT NOT NULL DEFAULT '', event_id TEXT NOT NULL, ts TEXT NOT NULL DEFAULT '0', "
                        "stream_id TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, receipt_type, user_id, thread_id)"         },
        // ADR-0192: a room an appservice published to the directory of one of its networks.
        SchemaTableDefinition{"appservice_directory",
                              "appservice_id TEXT NOT NULL, network_id TEXT NOT NULL, room_id TEXT NOT NULL, "
                              "PRIMARY KEY (appservice_id, network_id, room_id)"                                                                                        },
        // ADR-0212: one row per mxc:// URI reserved by POST
        // /_matrix/media/v1/create and not yet uploaded. Times are Unix
        // milliseconds, TEXT like every other numeric column here.
        SchemaTableDefinition{"media_pending_uploads",
                              "media_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, created_at_ms TEXT NOT NULL, "
                              "expires_at_ms TEXT NOT NULL"                                                                                                             },
    };

    // The secondary indexes v1 creates, after every table. Each serves a lookup
    // outside its table's primary key: an event's children (ADR-0064), a
    // device's to-device queue by age (ADR-0117), a room's deferred PDUs
    // (ADR-0165), and a user's pending uploads (ADR-0212).
    constexpr auto core_indexes = std::array{
        SchemaIndexDefinition{"event_edges_prev_event_id",            "event_edges",           "prev_event_id"},
        SchemaIndexDefinition{"idx_to_device_messages_recipient_age", "to_device_messages",
                              "target_user_id, target_device_id, created_at_ms"                               },
        SchemaIndexDefinition{"idx_deferred_pdus_room_id",            "deferred_pdus",         "room_id"      },
        SchemaIndexDefinition{"idx_media_pending_uploads_owner",      "media_pending_uploads", "owner_user_id"},
    };

    [[nodiscard]] auto index_sql(SchemaIndexDefinition const& index, std::string_view prefix)
        -> std::optional<std::string>
    {
        // Only registered indexes on core tables may participate in generated
        // DDL; names are checked against the same identifier rule as tables.
        auto const registered = std::ranges::any_of(core_indexes, [&index](SchemaIndexDefinition const& known) {
            return known.name == index.name && known.table == index.table && known.columns_sql == index.columns_sql;
        });
        if (!registered || !schema_table_is_core(index.table) || !quote_sqlite_identifier(index.name).has_value() ||
            !quote_sqlite_identifier(index.table).has_value())
        {
            return std::nullopt;
        }
        return std::string{prefix} + std::string{index.name} + " ON " + std::string{index.table} + " (" +
               std::string{index.columns_sql} + ")";
    }

} // namespace

auto current_schema_version() noexcept -> std::uint32_t
{
    return schema_version;
}

// While v1 is the only version, the shape v1 creates is the current one. The
// first post-1.0 migration must split them again: initial_* keeps returning
// exactly what v1 created (migrations/001_initial_schema.sql is that record),
// and only current_* gains what the later migration adds.
auto initial_schema_definitions() -> std::vector<SchemaTableDefinition>
{
    return {core_tables.begin(), core_tables.end()};
}

auto current_schema_definitions() -> std::vector<SchemaTableDefinition>
{
    return {core_tables.begin(), core_tables.end()};
}

auto initial_schema_indexes() -> std::vector<SchemaIndexDefinition>
{
    return {core_indexes.begin(), core_indexes.end()};
}

auto initial_schema_tables() -> std::vector<std::string_view>
{
    auto tables = std::vector<std::string_view>{};
    tables.reserve(core_tables.size());
    for (auto const& table : core_tables)
    {
        tables.push_back(table.name);
    }
    return tables;
}

auto current_schema_tables() -> std::vector<std::string_view>
{
    auto tables = std::vector<std::string_view>{};
    tables.reserve(core_tables.size());
    for (auto const& table : core_tables)
    {
        tables.push_back(table.name);
    }
    return tables;
}

auto schema_table_definition(std::string_view table_name) noexcept -> std::optional<SchemaTableDefinition>
{
    auto const iterator = std::ranges::find_if(core_tables, [table_name](SchemaTableDefinition const& table) {
        return table.name == table_name;
    });
    return iterator == core_tables.end() ? std::nullopt : std::optional<SchemaTableDefinition>{*iterator};
}

auto schema_table_is_core(std::string_view table_name) noexcept -> bool
{
    return schema_table_definition(table_name).has_value();
}

auto quote_sqlite_identifier(std::string_view identifier) noexcept -> std::optional<std::string>
{
    if (identifier.empty())
    {
        return std::nullopt;
    }

    auto quoted = std::string{"\""};
    for (auto const character : identifier)
    {
        // Core table names use only ASCII letters, digits, and underscores.
        // Reject anything else (including embedded quotes) rather than trying
        // to escape attacker-controlled input.
        if ((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9') || character == '_')
        {
            quoted.push_back(character);
        }
        else
        {
            return std::nullopt;
        }
    }
    quoted.push_back('\"');
    return quoted;
}

auto create_table_sql(SchemaTableDefinition const& table) -> std::optional<std::string>
{
    // Only core tables may participate in generated DDL. Unknown names fail
    // closed instead of being concatenated into SQL.
    if (!schema_table_is_core(table.name))
    {
        return std::nullopt;
    }

    auto quoted = quote_sqlite_identifier(table.name);
    if (!quoted.has_value())
    {
        return std::nullopt;
    }

    return "CREATE TABLE " + std::move(*quoted) + " (" + std::string{table.columns_sql} + ")";
}

auto create_index_sql(SchemaIndexDefinition const& index) -> std::optional<std::string>
{
    return index_sql(index, "CREATE INDEX ");
}

auto create_index_if_missing_sql(SchemaIndexDefinition const& index) -> std::optional<std::string>
{
    return index_sql(index, "CREATE INDEX IF NOT EXISTS ");
}

} // namespace merovingian::database
