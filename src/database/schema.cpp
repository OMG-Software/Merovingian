// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/schema.hpp"

#include <algorithm>
#include <array>

namespace merovingian::database
{
namespace
{

    constexpr auto schema_version = std::uint32_t{1U};

    constexpr auto core_tables = std::array{
        SchemaTableDefinition{"schema_migrations",
                              "version TEXT PRIMARY KEY, name TEXT NOT NULL, direction TEXT NOT NULL"                                                          },
        SchemaTableDefinition{"users",                   "user_id TEXT PRIMARY KEY, password_hash TEXT NOT NULL, locked TEXT NOT NULL, "
                                       "suspended TEXT NOT NULL, admin TEXT NOT NULL"                                    },
        SchemaTableDefinition{"devices",                 "user_id TEXT NOT NULL, device_id TEXT NOT NULL, display_name TEXT NOT NULL, "
                                         "PRIMARY KEY (user_id, device_id)"                                            },
        SchemaTableDefinition{
                              "access_tokens",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, token_hash TEXT PRIMARY KEY, revoked TEXT NOT NULL"  },
        SchemaTableDefinition{
                              "refresh_tokens",          "token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, device_id TEXT NOT NULL, revoked TEXT NOT NULL"  },
        SchemaTableDefinition{"server_signing_keys",
                              "server_name TEXT NOT NULL, key_id TEXT NOT NULL, public_key TEXT NOT NULL, "
                              "valid_until_ts TEXT NOT NULL, secret_key TEXT, PRIMARY KEY (server_name, key_id)"                                               },
        SchemaTableDefinition{"rooms",                   "room_id TEXT PRIMARY KEY, creator_user_id TEXT NOT NULL"                                             },
        SchemaTableDefinition{"room_aliases",            "room_alias TEXT PRIMARY KEY, room_id TEXT NOT NULL"                                                  },
        SchemaTableDefinition{"room_versions",           "room_id TEXT PRIMARY KEY, version TEXT NOT NULL"                                                     },
        SchemaTableDefinition{
                              "events",                  "event_id TEXT PRIMARY KEY, room_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, json TEXT "
                      "NOT NULL, depth TEXT NOT NULL, stream_ordering TEXT NOT NULL DEFAULT '0'"                        },
        SchemaTableDefinition{"event_json",              "event_id TEXT PRIMARY KEY, json TEXT NOT NULL"                                                       },
        SchemaTableDefinition{
                              "event_edges",             "event_id TEXT NOT NULL, prev_event_id TEXT NOT NULL, PRIMARY KEY (event_id, prev_event_id)"          },
        SchemaTableDefinition{
                              "event_auth",              "event_id TEXT NOT NULL, auth_event_id TEXT NOT NULL, PRIMARY KEY (event_id, auth_event_id)"          },
        SchemaTableDefinition{"event_signatures",
                              "event_id TEXT NOT NULL, server_name TEXT NOT NULL, key_id TEXT NOT NULL, signature TEXT "
                              "NOT NULL, PRIMARY KEY (event_id, server_name, key_id)"                                                                          },
        SchemaTableDefinition{"current_state",
                              "room_id TEXT NOT NULL, event_type TEXT NOT NULL, state_key TEXT NOT NULL, event_id TEXT "
                              "NOT NULL, PRIMARY KEY (room_id, event_type, state_key)"                                                                         },
        SchemaTableDefinition{"state_groups",            "state_group_id TEXT PRIMARY KEY, room_id TEXT NOT NULL"                                              },
        SchemaTableDefinition{"state_group_edges",       "state_group_id TEXT NOT NULL, prev_state_group_id TEXT NOT NULL, "
                                                   "PRIMARY KEY (state_group_id, prev_state_group_id)"       },
        SchemaTableDefinition{"membership",
                              "room_id TEXT NOT NULL, user_id TEXT NOT NULL, membership TEXT NOT NULL DEFAULT 'join', "
                              "stream_ordering TEXT NOT NULL DEFAULT '0', PRIMARY KEY (room_id, user_id)"                                                      },
        SchemaTableDefinition{"invites",
                              "room_id TEXT NOT NULL, user_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, "
                              "event_id TEXT NOT NULL DEFAULT '', signed_event_json TEXT NOT NULL DEFAULT '', "
                              "invite_state_json TEXT NOT NULL DEFAULT '[]', stream_ordering TEXT NOT NULL "
                              "DEFAULT '0', "
                              "PRIMARY KEY (room_id, user_id)"                                                                                                 },
        SchemaTableDefinition{"account_data",
                              "user_id TEXT NOT NULL, event_type TEXT NOT NULL, json TEXT NOT NULL, stream_id TEXT "
                              "NOT NULL DEFAULT '0', PRIMARY KEY (user_id, event_type)"                                                                        },
        SchemaTableDefinition{"room_account_data",
                              "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, stream_id TEXT "
                              "NOT NULL DEFAULT '0', json TEXT NOT NULL, PRIMARY KEY (user_id, room_id, event_type)"                                           },
        SchemaTableDefinition{
                              "push_rules",              "user_id TEXT NOT NULL, rule_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, rule_id)"    },
        SchemaTableDefinition{
                              "filters",                 "user_id TEXT NOT NULL, filter_id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, filter_id)"},
        SchemaTableDefinition{"device_keys",             "user_id TEXT NOT NULL, device_id TEXT NOT NULL, json TEXT NOT NULL, "
                                             "PRIMARY KEY (user_id, device_id)"                                    },
        SchemaTableDefinition{"one_time_keys",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, "
                                               "json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id)"    },
        SchemaTableDefinition{"fallback_keys",           "user_id TEXT NOT NULL, device_id TEXT NOT NULL, key_id TEXT NOT NULL, "
                                               "json TEXT NOT NULL, PRIMARY KEY (user_id, device_id, key_id)"    },
        SchemaTableDefinition{
                              "cross_signing_keys",      "user_id TEXT NOT NULL, key_type TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, key_type)"  },
        SchemaTableDefinition{
                              "key_signatures",          "signer_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, target_device_id TEXT NOT NULL, "
            "json TEXT NOT NULL, PRIMARY KEY (signer_user_id, target_user_id, target_device_id)"                },
        SchemaTableDefinition{
                              "key_backups",             "user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version)"    },
        SchemaTableDefinition{
                              "key_backup_versions",     "user_id TEXT NOT NULL, version TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY (user_id, version)"    },
        SchemaTableDefinition{
                              "key_backup_sessions",     "user_id TEXT NOT NULL, version TEXT NOT NULL, room_id TEXT NOT NULL, session_id TEXT NOT NULL, "
            "json TEXT NOT NULL, PRIMARY KEY (user_id, version, room_id, session_id)"                      },
        SchemaTableDefinition{"media",                   "media_id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL, content_type TEXT NOT "
                                       "NULL, size_bytes TEXT NOT NULL, hash_algorithm TEXT NOT NULL, digest TEXT NOT "
                                       "NULL, quarantined TEXT NOT NULL, removed TEXT NOT NULL"                          },
        SchemaTableDefinition{"media_blobs",
                              "storage_id TEXT PRIMARY KEY, hash_algorithm TEXT NOT NULL, digest TEXT NOT NULL, "
                              "size_bytes TEXT NOT NULL, bytes TEXT NOT NULL, ref_count TEXT NOT NULL"                                                         },
        SchemaTableDefinition{
                              "remote_media",            "server_name TEXT NOT NULL, media_id TEXT NOT NULL, content_type TEXT NOT NULL, size_bytes "
                            "TEXT NOT NULL, quarantined TEXT NOT NULL, PRIMARY KEY (server_name, media_id)"       },
        SchemaTableDefinition{"federation_destinations",
                              "server_name TEXT PRIMARY KEY, state TEXT NOT NULL, retry_after_ts TEXT NOT NULL, "
                              "last_success_ts TEXT NOT NULL, consecutive_failures TEXT NOT NULL"                                                              },
        SchemaTableDefinition{"federation_transactions",
                              "transaction_id TEXT PRIMARY KEY, server_name TEXT NOT NULL, json TEXT NOT NULL, "
                              "method TEXT NOT NULL, target TEXT NOT NULL, origin TEXT NOT NULL, "
                              "origin_server_ts TEXT NOT NULL, body TEXT NOT NULL, retry_count TEXT NOT NULL, "
                              "next_retry_ts TEXT NOT NULL"                                                                                                    },
        SchemaTableDefinition{"rate_limits",             "scope TEXT NOT NULL, key TEXT NOT NULL, count TEXT NOT NULL, reset_ts "
                                             "TEXT NOT NULL, PRIMARY KEY (scope, key)"                             },
        SchemaTableDefinition{"audit_log",               "category TEXT NOT NULL, event_type TEXT NOT NULL, actor TEXT NOT NULL, "
                                           "target TEXT NOT NULL, reason TEXT NOT NULL"                              },
        SchemaTableDefinition{"policy_rules",            "rule_id TEXT PRIMARY KEY, scope TEXT NOT NULL, entity TEXT NOT NULL, "
                                              "action TEXT NOT NULL, reason TEXT NOT NULL"                        },
        SchemaTableDefinition{"admin_actions",
                              "admin_user_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL"                                                        },
        SchemaTableDefinition{"to_device_messages",
                              "stream_id TEXT NOT NULL, sender_user_id TEXT NOT NULL, target_user_id TEXT NOT NULL, "
                              "target_device_id TEXT NOT NULL DEFAULT '', message_type TEXT NOT NULL, content TEXT "
                              "NOT NULL, PRIMARY KEY (stream_id, target_user_id, target_device_id)"                                                            },
        SchemaTableDefinition{"device_list_changes",
                              "stream_id TEXT NOT NULL, observer_user_id TEXT NOT NULL, "
                              "subject_user_id TEXT NOT NULL, change_type TEXT NOT NULL DEFAULT 'changed', "
                              "PRIMARY KEY (stream_id, observer_user_id, subject_user_id)"                                                                     },
        SchemaTableDefinition{"presence_state",
                              "user_id TEXT PRIMARY KEY, stream_id TEXT NOT NULL DEFAULT '0', presence TEXT NOT NULL "
                              "DEFAULT 'offline', status_msg TEXT NOT NULL DEFAULT '', last_active_ago TEXT NOT NULL "
                              "DEFAULT '0', currently_active TEXT NOT NULL DEFAULT 'false'"                                                                    },
        SchemaTableDefinition{"profiles",                "user_id TEXT PRIMARY KEY, displayname TEXT NOT NULL DEFAULT '', "
                                          "avatar_url TEXT NOT NULL DEFAULT ''"                                       },
        SchemaTableDefinition{"client_txn_ids",
                              "user_id TEXT NOT NULL, room_id TEXT NOT NULL, event_type TEXT NOT NULL, "
                              "txn_id TEXT NOT NULL, event_id TEXT NOT NULL, "
                              "PRIMARY KEY (user_id, room_id, event_type, txn_id)"                                   },
    };

} // namespace

auto current_schema_version() noexcept -> std::uint32_t
{
    return schema_version;
}

auto initial_schema_definitions() -> std::vector<SchemaTableDefinition>
{
    return {core_tables.begin(), core_tables.end()};
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

auto create_table_sql(SchemaTableDefinition const& table) -> std::string
{
    return "CREATE TABLE " + std::string{table.name} + " (" + std::string{table.columns_sql} + ")";
}

} // namespace merovingian::database
