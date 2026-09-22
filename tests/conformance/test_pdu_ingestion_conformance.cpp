// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-pdu-conformance-" + std::to_string(now) + ".sqlite3");
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

// Builds a room-version-12 PDU body as canonical JSON, with a correct
// content hash.
[[nodiscard]] auto build_event_json(std::string const& room_id, std::string const& type,
                                    std::optional<std::string> const& state_key, std::string const& sender,
                                    merovingian::canonicaljson::Object content,
                                    std::vector<std::string> const& prev_event_ids,
                                    std::vector<std::string> const& auth_event_ids, std::int64_t depth, std::int64_t ts)
    -> std::string
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
    env.room_version = "12";
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

// Directly seeds an event + state-group bookkeeping as if it had already
// been accepted, mirroring tests/unit/test_pdu_ingestion_auth_checks.cpp's
// seed_accepted_event.
auto seed_accepted_event(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id,
                         std::string const& type, std::optional<std::string> const& state_key,
                         std::string const& sender, std::string const& json,
                         std::vector<std::string> const& prev_event_ids, std::uint64_t depth) -> void
{
    using namespace merovingian;

    auto* policy = rooms::find_room_version_policy("12");
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
};

[[nodiscard]] auto seed_room_genesis(HomeserverRuntime& runtime, std::string const& room_id, std::string const& admin)
    -> Genesis
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, admin});
    runtime.database.rooms.push_back({room_id, admin, {}, {}, false});

    auto const create_id = room_id + ":create";
    auto create_content = canonicaljson::Object{};
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"12"}}));
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
                                          {create_id}, {}, 1, 2);
    seed_accepted_event(runtime, room_id, pl_id, "m.room.power_levels", std::string{}, admin, pl_json, {create_id}, 1U);

    auto const member_id = room_id + ":admin-member";
    auto member_content = canonicaljson::Object{};
    member_content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const member_json =
        build_event_json(room_id, "m.room.member", admin, admin, std::move(member_content), {pl_id}, {pl_id}, 2, 3);
    seed_accepted_event(runtime, room_id, member_id, "m.room.member", admin, admin, member_json, {pl_id}, 2U);
    store.memberships.push_back({room_id, admin, "join", 0U});

    return {create_id, pl_id, member_id};
}

} // namespace

// Spec: Matrix rooms/v12.md (MSC4291) — "State resolution"
// URL: ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// "The `m.room.create` event MUST NOT be selected for `auth_events` on
// events. The `room_id` (being the `m.room.create` event's ID) implies this
// instead. This is reflected in a change to rule 3.2 below." — rule 3.2:
// "[Changed in this version] If there are entries whose `type` and
// `state_key` don't match those specified by the auth events selection
// algorithm described in the server specification, reject. Note: In this
// room version, `m.room.create` MUST NOT be selected."
SCENARIO("A room v12 PDU naming m.room.create in auth_events is rejected, not tolerated",
         "[conformance][federation][auth][room-v12]")
{
    GIVEN("a room v12 room and a PDU that (incorrectly) names the create event in its own auth_events")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!v12create:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"hi"}}));
        auto const msg_json = build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org",
                                               std::move(content), {genesis.admin_member_id},
                                               {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 3, 4);
        auto const envelope = make_envelope(room_id, "$badv12:local.example.org", "m.room.message", std::nullopt,
                                            "@admin:local.example.org", {genesis.admin_member_id},
                                            {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 3, msg_json);

        WHEN("the PDU is ingested")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected — rooms/v12.md rule 3.2: m.room.create MUST NOT be selected for auth_events")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }

            THEN("it never reaches current state")
            {
                auto const& state = started.runtime.database.persistent_store.state;
                REQUIRE(std::ranges::none_of(state, [&](merovingian::database::PersistentStateEvent const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.message";
                }));
            }
        }

        WHEN("the same PDU instead omits create from auth_events, as rule 3.2 requires")
        {
            auto content2 = merovingian::canonicaljson::Object{};
            content2.push_back(
                merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"hi"}}));
            auto const msg_json2 = build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org",
                                                    std::move(content2), {genesis.admin_member_id},
                                                    {genesis.pl_id, genesis.admin_member_id}, 3, 4);
            auto const envelope2 = make_envelope(room_id, "$goodv12:local.example.org", "m.room.message", std::nullopt,
                                                 "@admin:local.example.org", {genesis.admin_member_id},
                                                 {genesis.pl_id, genesis.admin_member_id}, 3, msg_json2);
            auto const result2 = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope2);

            THEN("it is accepted")
            {
                REQUIRE(result2.status == PduIngestionStatus::accepted);
            }
        }

        std::filesystem::remove(path);
    }
}
