// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "MembershipGenesis.hpp"
#include "master_key.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseConfig.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// A local server "local.example.org" holding a public room 10 with a local, joined admin, and the helpers that build
// and seed membership PDUs against it. Shared by the membership acceptor's unit and conformance scenarios.
namespace merovingian::tests::membership_acceptor_fixture
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] inline auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-membership-acceptor-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] inline auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] inline auto build_event_json(
    std::string const& room_id, std::string const& type, std::optional<std::string> const& state_key,
    std::string const& sender, merovingian::canonicaljson::Object content,
    std::vector<std::string> const& prev_event_ids, std::vector<std::string> const& auth_event_ids, std::int64_t depth,
    std::int64_t ts, std::optional<std::string> const& hash_override = std::nullopt) -> std::string
{
    using namespace merovingian;

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
    auto prev_arr = canonicaljson::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev_arr)}));
    auto auth_arr = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth_arr.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth_arr)}));

    auto hash_str = std::string{};
    if (hash_override.has_value())
    {
        hash_str = *hash_override;
    }
    else
    {
        auto const hash = events::make_content_hash(canonicaljson::Value{obj});
        REQUIRE(hash.error.empty());
        hash_str = hash.sha256;
    }
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash_str}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] inline auto make_envelope(std::string const& room_id, std::string const& event_id,
                                        std::string const& type, std::optional<std::string> const& state_key,
                                        std::string const& sender, std::vector<std::string> const& prev_event_ids,
                                        std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                        std::string const& json) -> InboundPduEnvelope
{
    auto env = InboundPduEnvelope{};
    env.event_id = event_id;
    env.room_id = room_id;
    env.room_version = "10";
    env.sender = sender;
    env.event_type = type;
    env.state_key = state_key;
    env.origin_server_ts = 0;
    env.depth = static_cast<std::uint64_t>(depth);
    env.prev_event_ids = prev_event_ids;
    env.auth_event_ids = auth_event_ids;
    env.json = json;
    return env;
}

inline auto seed_accepted_event(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id,
                                std::string const& type, std::optional<std::string> const& state_key,
                                std::string const& sender, std::string const& json,
                                std::vector<std::string> const& prev_event_ids, std::uint64_t depth) -> void
{
    using namespace merovingian;

    auto* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;

    store.events.push_back({event_id, room_id, sender, json, depth, 0U, prev_event_ids, {}, {}});
    if (state_key.has_value())
    {
        store.state.push_back({room_id, type, *state_key, event_id});
    }

    auto const state_before = homeserver::compute_state_before(store, room_id, *policy, prev_event_ids);
    REQUIRE(state_before.ok);
    auto const state_after = homeserver::compute_state_after(state_before.state, event_id, type, state_key);
    auto const group = homeserver::record_event_state(store, room_id, event_id, prev_event_ids, state_after, true);
    REQUIRE(group.has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));

    // Keep the in-memory membership cache in sync with seeded m.room.member
    // state, mirroring what membership_acceptor does for real receipts.
    if (type == "m.room.member" && state_key.has_value())
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        if (parsed.error == canonicaljson::ParseError::none)
        {
            auto const membership = events::extract_content_membership(parsed.value);
            if (!membership.empty())
            {
                auto const existing =
                    std::ranges::find_if(store.memberships, [&](database::PersistentMembership const& m) {
                        return m.room_id == room_id && m.user_id == *state_key;
                    });
                if (existing != store.memberships.end())
                {
                    existing->membership = std::string{membership};
                }
                else
                {
                    store.memberships.push_back({room_id, *state_key, std::string{membership}, 0U});
                }
            }
        }
    }
}
[[nodiscard]] inline auto seed_room_genesis(HomeserverRuntime& runtime, std::string const& room_id,
                                            std::string const& admin) -> Genesis
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, admin});
    runtime.database.rooms.push_back({room_id, admin, {}, false});

    auto const create_id = room_id + ":create";
    auto create_content = canonicaljson::Object{};
    create_content.push_back(canonicaljson::make_member("creator", canonicaljson::Value{admin}));
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
    auto const create_json =
        build_event_json(room_id, "m.room.create", std::string{}, admin, std::move(create_content), {}, {}, 0, 1);
    seed_accepted_event(runtime, room_id, create_id, "m.room.create", std::string{}, admin, create_json, {}, 0U);

    auto const pl_id = room_id + ":pl";
    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{std::int64_t{0}}));
    pl_content.push_back(canonicaljson::make_member("join_rule", canonicaljson::Value{std::string{"public"}}));
    auto users = canonicaljson::Object{};
    users.push_back(canonicaljson::make_member(admin, canonicaljson::Value{std::int64_t{100}}));
    pl_content.push_back(canonicaljson::make_member("users", canonicaljson::Value{std::move(users)}));
    auto const pl_json = build_event_json(room_id, "m.room.power_levels", std::string{}, admin, std::move(pl_content),
                                          {create_id}, {create_id}, 1, 2);
    seed_accepted_event(runtime, room_id, pl_id, "m.room.power_levels", std::string{}, admin, pl_json, {create_id}, 1U);

    auto const member_id = room_id + ":admin-member";
    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json = build_event_json(room_id, "m.room.member", admin, admin, std::move(member_content),
                                              {pl_id}, {create_id, pl_id}, 2, 3);
    seed_accepted_event(runtime, room_id, member_id, "m.room.member", admin, admin, member_json, {pl_id}, 2U);
    store.memberships.push_back({room_id, admin, "join", 0U});

    auto join_rules_content = merovingian::canonicaljson::Object{};
    join_rules_content.push_back(
        merovingian::canonicaljson::make_member("join_rule", merovingian::canonicaljson::Value{std::string{"public"}}));
    auto const join_rules_id = room_id + ":join-rules";
    auto const join_rules_json =
        build_event_json(room_id, "m.room.join_rules", std::string{}, admin, std::move(join_rules_content), {member_id},
                         {create_id, pl_id, member_id}, 3, 4);
    seed_accepted_event(runtime, room_id, join_rules_id, "m.room.join_rules", std::string{}, admin, join_rules_json,
                        {member_id}, 3U);

    return {create_id, pl_id, member_id, join_rules_id};
}

} // namespace merovingian::tests::membership_acceptor_fixture
