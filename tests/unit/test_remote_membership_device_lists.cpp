// SPDX-License-Identifier: GPL-3.0-or-later

// A remote user joining or leaving a room a local user is in changes what that
// local user has to tell its client about the remote user's devices. Local
// membership changes recorded this already; a membership learned over
// federation (send_join / send_leave through the membership acceptor, or a PDU
// in a /send transaction through ingest_pdu_event) did not, so a local client
// was never told it had stopped sharing a room with a remote user.
// Tags: [device_lists][federation][membership].
//
// Spec: docs/matrix-v1.19-spec/client-server-api.md, "Tracking the device list
// for a user": "Bob's homeserver will add Alice's user ID to the `changed`
// property of the `device_lists` field" when they start sharing a room again,
// and "Bob can also be notified when he stops sharing any room with Alice by
// inspecting the `left` property of the `device_lists` field". The /sync
// `DeviceLists` table: `changed` is the "users who ... now share an encrypted
// room with the client", `left` the "users with whom we do not share any
// encrypted rooms anymore".

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/transactions.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"
#include "merovingian/sync/device_list_delta.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

using merovingian::federation::FederationEndpoint;
using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;

constexpr auto local_admin = std::string_view{"@admin:local.example.org"};
constexpr auto remote_bob = std::string_view{"@bob:remote.example.org"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-remote-device-lists-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
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

[[nodiscard]] auto build_event_json(std::string const& room_id, std::string const& type,
                                    std::optional<std::string> const& state_key, std::string const& sender,
                                    merovingian::canonicaljson::Object content,
                                    std::vector<std::string> const& prev_event_ids,
                                    std::vector<std::string> const& auth_event_ids, std::int64_t depth,
                                    std::int64_t ts) -> std::string
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

    auto const hash = events::make_content_hash(canonicaljson::Value{obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_envelope(std::string const& room_id, std::string const& event_id, std::string const& type,
                                 std::optional<std::string> const& state_key, std::string const& sender,
                                 std::vector<std::string> const& prev_event_ids,
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

auto seed_accepted_event(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id,
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
}

struct Genesis final
{
    std::string create_id{};
    std::string pl_id{};
    std::string admin_member_id{};
    std::string join_rules_id{};
};

// A public room whose only member is the local admin, who is a local account
// and on the room's roster, as a room created through the client API would be.
[[nodiscard]] auto seed_room_genesis(HomeserverRuntime& runtime, std::string const& room_id) -> Genesis
{
    using namespace merovingian;

    auto const admin = std::string{local_admin};
    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, admin});
    runtime.database.rooms.push_back({room_id, admin, {admin}, {}, false});
    if (std::ranges::none_of(runtime.database.users, [&](homeserver::LocalUser const& user) {
            return user.user_id == admin;
        }))
    {
        runtime.database.users.push_back({admin, {}, false, false, false, false});
    }

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

    auto join_rules_content = canonicaljson::Object{};
    join_rules_content.push_back(
        canonicaljson::make_member("join_rule", canonicaljson::Value{std::string{"public"}}));
    auto const join_rules_id = room_id + ":join-rules";
    auto const join_rules_json =
        build_event_json(room_id, "m.room.join_rules", std::string{}, admin, std::move(join_rules_content), {member_id},
                         {create_id, pl_id, member_id}, 3, 4);
    seed_accepted_event(runtime, room_id, join_rules_id, "m.room.join_rules", std::string{}, admin, join_rules_json,
                        {member_id}, 3U);

    return {create_id, pl_id, member_id, join_rules_id};
}

// bob's membership event in the room, built to follow `prev_event_id`.
struct BobsMembership final
{
    std::string event_id{};
    std::string json{};
    std::vector<std::string> prev_event_ids{};
    std::vector<std::string> auth_event_ids{};
    std::int64_t depth{0};
};

[[nodiscard]] auto bobs_join(std::string const& room_id, Genesis const& genesis, std::string const& tag)
    -> BobsMembership
{
    auto content = merovingian::canonicaljson::Object{};
    content.push_back(merovingian::canonicaljson::make_member(
        "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
    auto result = BobsMembership{"$join-" + tag + ":remote.example.org",
                                 {},
                                 {genesis.join_rules_id},
                                 {genesis.create_id, genesis.pl_id, genesis.join_rules_id},
                                 4};
    result.json = build_event_json(room_id, "m.room.member", std::string{remote_bob}, std::string{remote_bob},
                                   std::move(content), result.prev_event_ids, result.auth_event_ids, result.depth, 5);
    return result;
}

[[nodiscard]] auto bobs_leave(std::string const& room_id, Genesis const& genesis, BobsMembership const& join,
                              std::string const& tag) -> BobsMembership
{
    auto content = merovingian::canonicaljson::Object{};
    content.push_back(merovingian::canonicaljson::make_member(
        "membership", merovingian::canonicaljson::Value{std::string{"leave"}}));
    auto result = BobsMembership{"$leave-" + tag + ":remote.example.org",
                                 {},
                                 {join.event_id},
                                 {genesis.create_id, genesis.pl_id, join.event_id},
                                 join.depth + 1};
    result.json = build_event_json(room_id, "m.room.member", std::string{remote_bob}, std::string{remote_bob},
                                   std::move(content), result.prev_event_ids, result.auth_event_ids, result.depth,
                                   join.depth + 2);
    return result;
}

[[nodiscard]] auto envelope_for(std::string const& room_id, BobsMembership const& event) -> InboundPduEnvelope
{
    return make_envelope(room_id, event.event_id, "m.room.member", std::string{remote_bob}, std::string{remote_bob},
                         event.prev_event_ids, event.auth_event_ids, event.depth, event.json);
}

// What the admin's client is told over /sync and /keys/changes, from stream id 0.
[[nodiscard]] auto admin_delta(HomeserverRuntime const& runtime) -> merovingian::sync::DeviceListDelta
{
    return merovingian::sync::collect_device_list_delta(runtime.database.persistent_store, local_admin, 0U);
}

[[nodiscard]] auto contains(std::vector<std::string> const& users, std::string_view user) -> bool
{
    return std::ranges::find(users, user) != users.end();
}

// Accepts bob's join through the membership acceptor, as send_join does.
auto accept_join_through_acceptor(HomeserverRuntime& runtime, std::string const& room_id, BobsMembership const& join)
    -> void
{
    auto const result = runtime.federation.membership_acceptor(FederationEndpoint::send_join, room_id, join.event_id,
                                                               envelope_for(room_id, join));
    REQUIRE(result.accepted);
}

} // namespace

SCENARIO("A remote user joining a local user's room is reported as a device-list change",
         "[device_lists][federation][membership]")
{
    GIVEN("a room the local admin is in")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const room_id = std::string{"!joins:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id);
        auto const join = bobs_join(room_id, genesis, "acceptor");

        WHEN("a remote user's join is accepted through send_join")
        {
            accept_join_through_acceptor(started.runtime, room_id, join);

            THEN("the local user's client is told to refresh the remote user's devices")
            {
                auto const delta = admin_delta(started.runtime);
                REQUIRE(contains(delta.changed, remote_bob));
                REQUIRE_FALSE(contains(delta.left, remote_bob));
            }
        }

        WHEN("a remote user's join arrives as a PDU in a transaction")
        {
            auto const result =
                merovingian::homeserver::ingest_pdu_event(started.runtime, envelope_for(room_id, join));
            REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);

            THEN("the local user's client is told to refresh the remote user's devices")
            {
                auto const delta = admin_delta(started.runtime);
                REQUIRE(contains(delta.changed, remote_bob));
                REQUIRE_FALSE(contains(delta.left, remote_bob));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A remote user leaving the last room they share with a local user is reported as device_lists.left",
         "[device_lists][federation][membership]")
{
    GIVEN("a remote user who has joined a room the local admin is in")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const room_id = std::string{"!leaves:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id);
        auto const join = bobs_join(room_id, genesis, "leave");
        accept_join_through_acceptor(started.runtime, room_id, join);
        auto const leave = bobs_leave(room_id, genesis, join, "leave");

        WHEN("the remote user's leave is accepted through send_leave")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                FederationEndpoint::send_leave, room_id, leave.event_id, envelope_for(room_id, leave));
            REQUIRE(result.accepted);

            THEN("the local user is told they no longer share a room with the remote user")
            {
                auto const delta = admin_delta(started.runtime);
                REQUIRE(contains(delta.left, remote_bob));
                REQUIRE_FALSE(contains(delta.changed, remote_bob));
            }
        }

        WHEN("the remote user's leave arrives as a PDU in a transaction")
        {
            auto const result =
                merovingian::homeserver::ingest_pdu_event(started.runtime, envelope_for(room_id, leave));
            REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);

            THEN("the local user is told they no longer share a room with the remote user")
            {
                auto const delta = admin_delta(started.runtime);
                REQUIRE(contains(delta.left, remote_bob));
                REQUIRE_FALSE(contains(delta.changed, remote_bob));
            }
        }

        WHEN("the remote user leaves and then rejoins")
        {
            auto const left = started.runtime.federation.membership_acceptor(
                FederationEndpoint::send_leave, room_id, leave.event_id, envelope_for(room_id, leave));
            REQUIRE(left.accepted);
            auto rejoin_content = merovingian::canonicaljson::Object{};
            rejoin_content.push_back(merovingian::canonicaljson::make_member(
                "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
            auto rejoin = BobsMembership{"$rejoin:remote.example.org",
                                         {},
                                         {leave.event_id},
                                         {genesis.create_id, genesis.pl_id, genesis.join_rules_id, leave.event_id},
                                         leave.depth + 1};
            rejoin.json = build_event_json(room_id, "m.room.member", std::string{remote_bob},
                                           std::string{remote_bob}, std::move(rejoin_content), rejoin.prev_event_ids,
                                           rejoin.auth_event_ids, rejoin.depth, leave.depth + 2);
            auto const joined = started.runtime.federation.membership_acceptor(
                FederationEndpoint::send_join, room_id, rejoin.event_id, envelope_for(room_id, rejoin));
            REQUIRE(joined.accepted);

            THEN("the local user is told to refresh the remote user's devices again, not that they left")
            {
                // The change log keeps the newest row per user, so the rejoin supersedes the leave.
                auto const delta = admin_delta(started.runtime);
                REQUIRE(contains(delta.changed, remote_bob));
                REQUIRE_FALSE(contains(delta.left, remote_bob));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A remote user leaving one of two shared rooms is not reported as device_lists.left",
         "[device_lists][federation][membership]")
{
    GIVEN("a remote user who has joined two rooms the local admin is in")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const first_room = std::string{"!first:local.example.org"};
        auto const second_room = std::string{"!second:local.example.org"};
        auto const first = seed_room_genesis(started.runtime, first_room);
        auto const second = seed_room_genesis(started.runtime, second_room);
        auto const first_join = bobs_join(first_room, first, "first");
        auto const second_join = bobs_join(second_room, second, "second");
        accept_join_through_acceptor(started.runtime, first_room, first_join);
        accept_join_through_acceptor(started.runtime, second_room, second_join);

        WHEN("the remote user leaves only the first room")
        {
            auto const leave = bobs_leave(first_room, first, first_join, "first");
            auto const result = started.runtime.federation.membership_acceptor(
                FederationEndpoint::send_leave, first_room, leave.event_id, envelope_for(first_room, leave));
            REQUIRE(result.accepted);

            THEN("the local user still shares a room with them, so is not told they left")
            {
                auto const delta = admin_delta(started.runtime);
                REQUIRE_FALSE(contains(delta.left, remote_bob));
            }
        }

        std::filesystem::remove(path);
    }
}
