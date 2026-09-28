// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "../federation_signing_test_support.hpp"
#include "master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::tests::remote_room
{

// A room hosted on `local_server`, version `room_version`, in which
// `remote_member` (a user on `remote_server`) has joined. Events the remote
// server "sends" are signed with the key derived from `remote_key_seed`, and
// remote_runtime() is that server's genuine published key: a test wires it
// into remote_key_resolver to model the key the real server publishes.

inline constexpr auto remote_server = "remote.example.org";
inline constexpr auto remote_key_id = "ed25519:auto";
inline constexpr auto remote_key_seed = "pdu-backfill-test-remote-seed";
inline constexpr auto remote_member = "@bob:remote.example.org";
inline constexpr auto local_server = "local.example.org";
inline constexpr auto local_admin = "@admin:local.example.org";
inline constexpr auto room_version = "10";

[[nodiscard]] inline auto unique_sqlite_path(std::string_view prefix = "merovingian-pdu-backfill-")
    -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / (std::string{prefix} + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] inline auto config_with_sqlite(std::filesystem::path const& path) -> config::Config
{
    auto server = config::ServerConfig{};
    server.server_name = local_server;

    auto database = config::DatabaseConfig{};
    database.backend = config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = config::SecurityConfig{};
    security.secrets.master_key_file = shared_master_key_file();
    security.federation.enabled = true;

    return {server,   config::ListenersConfig{},        database,
            security, config::ClientRateLimitsConfig{}, config::LogModulesConfig{}};
}

// Seeds the room's genesis (create, power_levels, the admin's and the remote
// member's joins) as both current state and an ADR-0064 phase-A state group.
// Event IDs are `<room_id>:create`, `:pl`, `:member` and `:member:bob`.
inline auto seed_room_with_genesis_state_group(homeserver::HomeserverRuntime& runtime, std::string const& room_id)
    -> void
{
    auto& store = runtime.database.persistent_store;
    auto& local = runtime.database.rooms;

    store.rooms.push_back({room_id, local_admin});
    local.push_back({room_id, local_admin, {}, {}, false});

    auto const create_id = room_id + ":create";
    auto const pl_id = room_id + ":pl";
    auto const member_id = room_id + ":member";
    auto const member_bob_id = room_id + ":member:bob";

    auto const make_json = [&](std::string_view type, std::string_view state_key, std::string_view sender,
                               canonicaljson::Object content, std::int64_t depth, std::int64_t ts,
                               std::string_view event_id) -> std::string {
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));
        auto obj = canonicaljson::Object{};
        obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
        obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
        obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{std::string{event_id}}));
        obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
        obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
        obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
        obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{type}}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
        return serialized.output;
    };

    auto create_content = canonicaljson::Object{};
    create_content.push_back(canonicaljson::make_member("creator", canonicaljson::Value{std::string{local_admin}}));
    create_content.push_back(
        canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
    auto const create_json = make_json("m.room.create", "", local_admin, std::move(create_content), 0, 1, create_id);
    store.events.push_back({create_id, room_id, local_admin, create_json, 0U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.create", "", create_id});

    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    auto pl_users = canonicaljson::Object{};
    pl_users.push_back(canonicaljson::make_member(local_admin, canonicaljson::Value{std::int64_t{100}}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(pl_users)}));
    auto const pl_json = make_json("m.room.power_levels", "", local_admin, std::move(pl_content), 1, 2, pl_id);
    store.events.push_back({pl_id, room_id, local_admin, pl_json, 1U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.power_levels", "", pl_id});

    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json =
        make_json("m.room.member", local_admin, local_admin, std::move(member_content), 2, 3, member_id);
    store.events.push_back({member_id, room_id, local_admin, member_json, 2U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", local_admin, member_id});
    store.memberships.push_back({room_id, local_admin, "join", 0U});

    auto member_bob_content = canonicaljson::Object{};
    member_bob_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_bob_json =
        make_json("m.room.member", remote_member, remote_member, std::move(member_bob_content), 3, 4, member_bob_id);
    store.events.push_back({member_bob_id, room_id, remote_member, member_bob_json, 3U, 0U, {}, {}, {}});
    store.state.push_back({room_id, "m.room.member", remote_member, member_bob_id});
    store.memberships.push_back({room_id, remote_member, "join", 0U});

    auto const genesis_state = std::vector<database::PersistentStateGroupStateEntry>{
        {"", "m.room.create",       "",            create_id    },
        {"", "m.room.power_levels", "",            pl_id        },
        {"", "m.room.member",       local_admin,   member_id    },
        {"", "m.room.member",       remote_member, member_bob_id},
    };
    auto const group_id =
        database::create_or_reuse_state_group(store, room_id, room_id + ":genesis-group", std::nullopt, genesis_state);
    REQUIRE(group_id.has_value());
    REQUIRE(database::set_event_state_group(store, create_id, *group_id));
    REQUIRE(database::set_event_state_group(store, pl_id, *group_id));
    REQUIRE(database::set_event_state_group(store, member_id, *group_id));
    REQUIRE(database::set_event_state_group(store, member_bob_id, *group_id));
    REQUIRE(database::update_forward_extremities(store, room_id, member_id, {}, true));
}

// A PDU from the remote server, signed with the key derived from `key_seed`.
[[nodiscard]] inline auto make_remote_event_json(std::string const& room_id, std::string const& type,
                                                 std::optional<std::string> const& state_key, std::string const& sender,
                                                 canonicaljson::Object content,
                                                 std::vector<std::string> const& prev_event_ids,
                                                 std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                                 std::int64_t ts, std::string_view key_seed = remote_key_seed)
    -> std::string
{
    auto prev = canonicaljson::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev.push_back(canonicaljson::Value{id});
    }
    auto auth = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth.push_back(canonicaljson::Value{id});
    }

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{type}));
    if (state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
    }
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev)}));
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

    return federation::test::make_signed_event_json(serialized.output, remote_server, remote_key_id, key_seed,
                                                    room_version);
}

[[nodiscard]] inline auto make_remote_message_json(std::string const& room_id,
                                                   std::vector<std::string> const& prev_event_ids,
                                                   std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                                   std::int64_t ts, std::string_view key_seed = remote_key_seed)
    -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));
    content.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"backfill test"}}));
    return make_remote_event_json(room_id, "m.room.message", std::nullopt, remote_member, std::move(content),
                                  prev_event_ids, auth_event_ids, depth, ts, key_seed);
}

// The remote server's genuine published signing key. Valid until 2100-01-01:
// from room v5 a key must still be valid at each event's origin_server_ts.
[[nodiscard]] inline auto remote_runtime() -> federation::FederationRemoteRuntime
{
    auto remote = federation::FederationRemoteRuntime{};
    remote.server_name = remote_server;
    remote.signing_key = {remote_server, remote_key_id, 4'102'444'800'000U,
                          federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_server;
    remote.trust.reputation_score = 100U;
    return remote;
}

// A remote_key_resolver that knows only the remote server's genuine key.
[[nodiscard]] inline auto genuine_key_resolver()
{
    return [](std::string_view server_name,
              std::string_view key_id) -> std::optional<federation::FederationRemoteRuntime> {
        if (server_name != remote_server || key_id != remote_key_id)
        {
            return std::nullopt;
        }
        return remote_runtime();
    };
}

} // namespace merovingian::tests::remote_room
