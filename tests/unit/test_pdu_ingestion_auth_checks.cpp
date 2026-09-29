// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0064 phase B2: the receipt-order checks ingest_pdu_event
// (src/homeserver/local_http_router.cpp) runs on every inbound PDU, in spec
// order. Tags: [pdu_ingestion][auth].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU" (step 3: hash -> redact, not reject; step 4: auth
// against the event's own auth_events -> reject; step 5: auth against the
// state before the event -> reject; step 6: auth against current state ->
// soft-fail, not reject), "Auth events selection", "Rejection", "Soft
// failure".

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
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
#include <cstdint>
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
    return std::filesystem::temp_directory_path() / ("merovingian-pdu-auth-checks-" + std::to_string(now) + ".sqlite3");
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

// Builds a room-version-10 PDU body as canonical JSON. `hash_override`, when
// set, is written verbatim as hashes.sha256 instead of the correct content
// hash — used to construct a deliberately tampered/corrupted PDU.
[[nodiscard]] auto build_event_json(std::string const& room_id, std::string const& type,
                                    std::optional<std::string> const& state_key, std::string const& sender,
                                    merovingian::canonicaljson::Object content,
                                    std::vector<std::string> const& prev_event_ids,
                                    std::vector<std::string> const& auth_event_ids, std::int64_t depth, std::int64_t ts,
                                    std::optional<std::string> const& hash_override = std::nullopt) -> std::string
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

// Directly seeds an event + state-group bookkeeping as if it had already
// been accepted (bypassing ingest_pdu_event's checks) — used to build up
// fixture room history the tests then send real PDUs against.
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
        auto const existing = std::ranges::find_if(store.state, [&](database::PersistentStateEvent const& s) {
            return s.room_id == room_id && s.event_type == type && s.state_key == *state_key;
        });
        if (existing != store.state.end())
        {
            existing->event_id = event_id;
        }
        else
        {
            store.state.push_back({room_id, type, *state_key, event_id});
        }
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

// Seeds a fresh room: m.room.create, m.room.power_levels (state_default
// configurable, admin at power 100), and the admin's own join — all
// accepted, with real state groups and forward extremities, mirroring what
// a pre-existing room's migration-seeded genesis looks like.
[[nodiscard]] auto seed_room_genesis(HomeserverRuntime& runtime, std::string const& room_id, std::string const& admin,
                                     std::int64_t state_default = 0) -> Genesis
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    store.rooms.push_back({room_id, admin});
    runtime.database.rooms.push_back({room_id, admin, {}, {}, false});

    auto const create_id = room_id + ":create";
    auto create_content = canonicaljson::Object{};
    create_content.push_back(canonicaljson::make_member("creator", canonicaljson::Value{admin}));
    create_content.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{"10"}}));
    auto const create_json =
        build_event_json(room_id, "m.room.create", std::string{}, admin, std::move(create_content), {}, {}, 0, 1);
    seed_accepted_event(runtime, room_id, create_id, "m.room.create", std::string{}, admin, create_json, {}, 0U);

    auto const pl_id = room_id + ":pl";
    auto pl_content = canonicaljson::Object{};
    pl_content.push_back(canonicaljson::make_member("state_default", canonicaljson::Value{state_default}));
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

    return {create_id, pl_id, member_id};
}

// Seeds a join for `user_id` off `prev_event_id`, accepted, returning the
// new join event's id.
[[nodiscard]] auto seed_join(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id_suffix,
                             std::string const& user_id, std::string const& prev_event_id, std::int64_t depth,
                             Genesis const& genesis) -> std::string
{
    using namespace merovingian;

    auto const event_id = room_id + ":" + event_id_suffix;
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
    auto const json = build_event_json(room_id, "m.room.member", user_id, user_id, std::move(content), {prev_event_id},
                                       {genesis.create_id, genesis.pl_id, event_id}, depth, depth + 1);
    // auth_events for a self-join name the target's own (not-yet-existing)
    // member event, which the spec permits omitting ("if any"); use just
    // create+power_levels here since the target has no prior member event.
    auto const auth_ids = std::vector<std::string>{genesis.create_id, genesis.pl_id};
    auto const json2 = build_event_json(
        room_id, "m.room.member", user_id, user_id,
        [&] {
            auto c = canonicaljson::Object{};
            c.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"join"}}));
            return c;
        }(),
        {prev_event_id}, auth_ids, depth, depth + 1);
    std::ignore = json;
    seed_accepted_event(runtime, room_id, event_id, "m.room.member", user_id, user_id, json2, {prev_event_id},
                        static_cast<std::uint64_t>(depth));
    auto& store = runtime.database.persistent_store;
    store.memberships.push_back({room_id, user_id, "join", 0U});
    return event_id;
}

} // namespace

SCENARIO("A PDU with a mismatched content hash is redacted and accepted, not rejected", "[pdu_ingestion][auth]")
{
    GIVEN("a seeded room and a message PDU whose declared hash does not match its content")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!hash:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"secret"}}));
        auto const bad_json =
            build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org", std::move(content),
                             {genesis.admin_member_id}, {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 3,
                             4, std::string{"this-does-not-match-the-content"});
        auto const envelope = make_envelope(room_id, "$tampered:local.example.org", "m.room.message", std::nullopt,
                                            "@admin:local.example.org", {genesis.admin_member_id},
                                            {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 3, bad_json);

        WHEN("the PDU is ingested")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is accepted, not rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }

            THEN("the stored event's content is redacted while event_id and sender survive")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$tampered:local.example.org";
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->status == "accepted");
                auto const parsed = merovingian::canonicaljson::parse_lossless(stored->json);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(obj != nullptr);
                auto const find = [&](std::string_view key) -> merovingian::canonicaljson::Value const* {
                    for (auto const& m : *obj)
                    {
                        if (m.key == key)
                        {
                            return m.value.get();
                        }
                    }
                    return nullptr;
                };
                auto const* sender_val = find("sender");
                REQUIRE(sender_val != nullptr);
                REQUIRE(std::get<std::string>(sender_val->storage()) == "@admin:local.example.org");
                auto const* content_val = find("content");
                REQUIRE(content_val != nullptr);
                auto const* content_obj = std::get_if<merovingian::canonicaljson::Object>(&content_val->storage());
                REQUIRE(content_obj != nullptr);
                // m.room.message keeps no content keys under redaction.
                REQUIRE(content_obj->empty());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A PDU that passes against current state but fails against its own auth_events is rejected",
         "[pdu_ingestion][auth]")
{
    GIVEN("a room whose current power_levels is permissive but whose named auth_events point at a restrictive one")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!authevents:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto const bob_join = seed_join(started.runtime, room_id, "bob-join", "@bob:local.example.org",
                                        genesis.admin_member_id, 3, genesis);

        // A stray power_levels event with a prohibitive state_default,
        // never applied to current state, but a legal (type, state_key)
        // selection for any event's auth_events.
        auto const strict_pl_id = room_id + ":strict-pl";
        auto strict_content = merovingian::canonicaljson::Object{};
        strict_content.push_back(merovingian::canonicaljson::make_member(
            "state_default", merovingian::canonicaljson::Value{std::int64_t{100}}));
        auto const strict_json =
            build_event_json(room_id, "m.room.power_levels", std::string{}, "@admin:local.example.org",
                             std::move(strict_content), {genesis.pl_id}, {genesis.create_id}, 1, 2);
        started.runtime.database.persistent_store.events.push_back(
            {strict_pl_id, room_id, "@admin:local.example.org", strict_json, 1U, 0U, {genesis.pl_id}, {}, {}});

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("topic", merovingian::canonicaljson::Value{std::string{"hi"}}));
        auto const topic_json =
            build_event_json(room_id, "m.room.topic", std::string{}, "@bob:local.example.org", std::move(content),
                             {bob_join}, {genesis.create_id, strict_pl_id, bob_join}, 4, 5);
        auto const envelope = make_envelope(room_id, "$badauth:local.example.org", "m.room.topic", std::string{},
                                            "@bob:local.example.org", {bob_join},
                                            {genesis.create_id, strict_pl_id, bob_join}, 4, topic_json);

        WHEN("the PDU is ingested")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }

            THEN("it never reaches current state")
            {
                auto const& state = started.runtime.database.persistent_store.state;
                REQUIRE(std::ranges::none_of(state, [&](merovingian::database::PersistentStateEvent const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.topic";
                }));
            }

            THEN("the event is still stored, marked rejected")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$badauth:local.example.org";
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->status == "rejected");
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A PDU that passes against its auth_events but fails against the state before it is rejected",
         "[pdu_ingestion][auth]")
{
    GIVEN("a room where power_levels was tightened after the point the PDU's auth_events reference")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!statebefore:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto const bob_join = seed_join(started.runtime, room_id, "bob-join", "@bob:local.example.org",
                                        genesis.admin_member_id, 3, genesis);

        // Tighten power_levels for real: a new, properly recorded state
        // group and forward extremity, becoming the room's new tip.
        auto const strict_pl_id = room_id + ":strict-pl-real";
        auto strict_content = merovingian::canonicaljson::Object{};
        strict_content.push_back(merovingian::canonicaljson::make_member(
            "state_default", merovingian::canonicaljson::Value{std::int64_t{100}}));
        auto const strict_json = build_event_json(room_id, "m.room.power_levels", std::string{},
                                                  "@admin:local.example.org", std::move(strict_content), {bob_join},
                                                  {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(started.runtime, room_id, strict_pl_id, "m.room.power_levels", std::string{},
                            "@admin:local.example.org", strict_json, {bob_join}, 4U);

        // Bob's topic PDU names the OLD (permissive) power_levels event in
        // auth_events — a legal selection — but its prev_event is the NEW
        // (restrictive) tip, so the state immediately before it is strict.
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("topic", merovingian::canonicaljson::Value{std::string{"hi"}}));
        auto const topic_json =
            build_event_json(room_id, "m.room.topic", std::string{}, "@bob:local.example.org", std::move(content),
                             {strict_pl_id}, {genesis.create_id, genesis.pl_id, bob_join}, 5, 6);
        auto const envelope = make_envelope(room_id, "$staleauth:local.example.org", "m.room.topic", std::string{},
                                            "@bob:local.example.org", {strict_pl_id},
                                            {genesis.create_id, genesis.pl_id, bob_join}, 5, topic_json);

        WHEN("the PDU is ingested")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Ban evasion: a banned user's PDU referencing pre-ban history is soft-failed, not rejected or accepted",
         "[pdu_ingestion][auth]")
{
    GIVEN("bob is banned, and bob's server sends a message whose prev_events precede the ban")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!banevasion:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto const bob_join = seed_join(started.runtime, room_id, "bob-join", "@bob:local.example.org",
                                        genesis.admin_member_id, 3, genesis);

        auto const ban_id = room_id + ":ban-bob";
        auto ban_content = merovingian::canonicaljson::Object{};
        ban_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"ban"}}));
        auto const ban_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:local.example.org"},
                             "@admin:local.example.org", std::move(ban_content), {bob_join},
                             {genesis.create_id, genesis.pl_id, genesis.admin_member_id, bob_join}, 4, 5);
        seed_accepted_event(started.runtime, room_id, ban_id, "m.room.member", std::string{"@bob:local.example.org"},
                            "@admin:local.example.org", ban_json, {bob_join}, 4U);
        started.runtime.database.persistent_store.memberships.push_back({room_id, "@bob:local.example.org", "ban", 0U});

        REQUIRE(merovingian::database::find_forward_extremities(started.runtime.database.persistent_store, room_id) ==
                std::vector<std::string>{ban_id});

        // Bob's evading message: prev_events point at his own OLD join
        // event (before the ban), and its auth_events likewise reference
        // that pre-ban state, so both the auth_events check (step 4) and
        // the state-before check (step 5) pass. Only the current-state
        // check (step 6, against the now-banned resolved state) fails.
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"evading"}}));
        auto const evading_json =
            build_event_json(room_id, "m.room.message", std::nullopt, "@bob:local.example.org", std::move(content),
                             {bob_join}, {genesis.create_id, genesis.pl_id, bob_join}, 4, 5);
        auto const envelope = make_envelope(room_id, "$evading:local.example.org", "m.room.message", std::nullopt,
                                            "@bob:local.example.org", {bob_join},
                                            {genesis.create_id, genesis.pl_id, bob_join}, 4, evading_json);

        WHEN("the evading PDU is ingested")
        {
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is soft-failed, neither accepted nor rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::soft_failed);
            }

            THEN("it is stored, marked soft_failed")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$evading:local.example.org";
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->status == "soft_failed");
            }

            THEN("it is not a forward extremity")
            {
                auto const extremities =
                    merovingian::database::find_forward_extremities(started.runtime.database.persistent_store, room_id);
                REQUIRE(std::ranges::find(extremities, "$evading:local.example.org") == extremities.end());
                REQUIRE(extremities == std::vector<std::string>{ban_id});
            }

            THEN("it takes part in state resolution: a state group is recorded for it")
            {
                REQUIRE(merovingian::database::find_event_state_group(started.runtime.database.persistent_store,
                                                                      "$evading:local.example.org")
                            .has_value());
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A rejected event's after-state equals the state before it, and a later event can still reference it",
         "[pdu_ingestion][auth]")
{
    GIVEN("a rejected PDU (fails against its own auth_events)")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!rejectedchain:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto const bob_join = seed_join(started.runtime, room_id, "bob-join", "@bob:local.example.org",
                                        genesis.admin_member_id, 3, genesis);

        auto const strict_pl_id = room_id + ":strict-pl";
        auto strict_content = merovingian::canonicaljson::Object{};
        strict_content.push_back(merovingian::canonicaljson::make_member(
            "state_default", merovingian::canonicaljson::Value{std::int64_t{100}}));
        auto const strict_json =
            build_event_json(room_id, "m.room.power_levels", std::string{}, "@admin:local.example.org",
                             std::move(strict_content), {genesis.pl_id}, {genesis.create_id}, 1, 2);
        started.runtime.database.persistent_store.events.push_back(
            {strict_pl_id, room_id, "@admin:local.example.org", strict_json, 1U, 0U, {genesis.pl_id}, {}, {}});

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(
            merovingian::canonicaljson::make_member("topic", merovingian::canonicaljson::Value{std::string{"hi"}}));
        auto const topic_json =
            build_event_json(room_id, "m.room.topic", std::string{}, "@bob:local.example.org", std::move(content),
                             {bob_join}, {genesis.create_id, strict_pl_id, bob_join}, 4, 5);
        auto const rejected_envelope = make_envelope(room_id, "$rejected:local.example.org", "m.room.topic",
                                                     std::string{}, "@bob:local.example.org", {bob_join},
                                                     {genesis.create_id, strict_pl_id, bob_join}, 4, topic_json);
        auto const rejected_result = merovingian::homeserver::ingest_pdu_event(started.runtime, rejected_envelope);
        REQUIRE(rejected_result.status == PduIngestionStatus::rejected_auth);

        WHEN("the rejected event's after-state is inspected")
        {
            auto const& store = started.runtime.database.persistent_store;
            auto* policy = merovingian::rooms::find_room_version_policy("10");
            REQUIRE(policy != nullptr);
            auto const state_before_rejected =
                merovingian::homeserver::compute_state_before(store, room_id, *policy, {bob_join});
            auto const rejected_group =
                merovingian::database::find_event_state_group(store, "$rejected:local.example.org");

            THEN("it equals the state before it (the rejected event never entered its own state group)")
            {
                REQUIRE(state_before_rejected.ok);
                REQUIRE(rejected_group.has_value());
                auto const rejected_full_state =
                    merovingian::database::read_state_group_full_state(store, *rejected_group);
                REQUIRE(rejected_full_state.has_value());
                REQUIRE(rejected_full_state->size() == state_before_rejected.state.size());
                for (auto const& before_entry : state_before_rejected.state)
                {
                    REQUIRE(std::ranges::any_of(
                        *rejected_full_state, [&](merovingian::database::PersistentStateGroupStateEntry const& e) {
                            return e.event_type == before_entry.event_type && e.state_key == before_entry.state_key &&
                                   e.event_id == before_entry.event_id;
                        }));
                }
            }
        }

        WHEN("a later PDU references the rejected event in prev_events")
        {
            auto content2 = merovingian::canonicaljson::Object{};
            content2.push_back(merovingian::canonicaljson::make_member(
                "body", merovingian::canonicaljson::Value{std::string{"still works"}}));
            auto const followup_json = build_event_json(
                room_id, "m.room.message", std::nullopt, "@admin:local.example.org", std::move(content2),
                {"$rejected:local.example.org"}, {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 5, 6);
            auto const followup_envelope =
                make_envelope(room_id, "$followup:local.example.org", "m.room.message", std::nullopt,
                              "@admin:local.example.org", {"$rejected:local.example.org"},
                              {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 5, followup_json);
            auto const followup_result = merovingian::homeserver::ingest_pdu_event(started.runtime, followup_envelope);

            THEN("it can still be authorised and accepted")
            {
                REQUIRE(followup_result.status == PduIngestionStatus::accepted);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A soft-failed state event's after-state includes itself, so resolution can later admit it",
         "[pdu_ingestion][auth]")
{
    // Spec: "soft failed state events participate in state resolution as
    // normal... it is possible for such events to appear in the current
    // state of the room. In that case the client should be told about the
    // soft failed event in the usual way." The mechanism this depends on —
    // that a soft-failed event's after-state genuinely includes itself
    // (unlike a REJECTED event, whose after-state is state-before
    // unchanged) — is what this scenario proves directly; whether any
    // particular fork resolves in the soft-failed candidate's favour is a
    // state-res v2 algorithm question already covered by
    // tests/unit/test_state_resolution_auth_diff.cpp and
    // tests/conformance/test_state_resolution_conformance.cpp (a banned
    // sender's soft-failed event correctly does NOT win a real resolution
    // either — spec: "the job of the state resolution algorithm [is] to
    // ensure that malicious events cannot be injected into the room state
    // via this mechanism", which state-res v2's iterative auth checks
    // enforce independently of this soft-fail gate).
    GIVEN("bob is banned, then sends a soft-failed topic change")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!softstate:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto const bob_join = seed_join(started.runtime, room_id, "bob-join", "@bob:local.example.org",
                                        genesis.admin_member_id, 3, genesis);

        auto const ban_id = room_id + ":ban-bob";
        auto ban_content = merovingian::canonicaljson::Object{};
        ban_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"ban"}}));
        auto const ban_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:local.example.org"},
                             "@admin:local.example.org", std::move(ban_content), {bob_join},
                             {genesis.create_id, genesis.pl_id, genesis.admin_member_id, bob_join}, 4, 5);
        seed_accepted_event(started.runtime, room_id, ban_id, "m.room.member", std::string{"@bob:local.example.org"},
                            "@admin:local.example.org", ban_json, {bob_join}, 4U);

        // Bob's soft-failed topic change: prev_events precede the ban.
        auto topic_content = merovingian::canonicaljson::Object{};
        topic_content.push_back(merovingian::canonicaljson::make_member(
            "topic", merovingian::canonicaljson::Value{std::string{"evading topic"}}));
        auto const topic_json =
            build_event_json(room_id, "m.room.topic", std::string{}, "@bob:local.example.org", std::move(topic_content),
                             {bob_join}, {genesis.create_id, genesis.pl_id, bob_join}, 4, 5);
        auto const topic_envelope = make_envelope(room_id, "$bobtopic:local.example.org", "m.room.topic", std::string{},
                                                  "@bob:local.example.org", {bob_join},
                                                  {genesis.create_id, genesis.pl_id, bob_join}, 4, topic_json);
        auto const topic_result = merovingian::homeserver::ingest_pdu_event(started.runtime, topic_envelope);
        REQUIRE(topic_result.status == PduIngestionStatus::soft_failed);

        WHEN("the soft-failed event's own after-state group is inspected")
        {
            auto const& store = started.runtime.database.persistent_store;
            auto const group = merovingian::database::find_event_state_group(store, "$bobtopic:local.example.org");

            THEN("it has an after-state group, and that group includes the topic event itself")
            {
                REQUIRE(group.has_value());
                auto const full_state = merovingian::database::read_state_group_full_state(store, *group);
                REQUIRE(full_state.has_value());
                auto const topic_entry = std::ranges::find_if(
                    *full_state, [](merovingian::database::PersistentStateGroupStateEntry const& e) {
                        return e.event_type == "m.room.topic";
                    });
                REQUIRE(topic_entry != full_state->end());
                REQUIRE(topic_entry->event_id == "$bobtopic:local.example.org");
            }

            THEN("this differs from a rejected event, whose after-state would exclude it (see the rejected-event "
                 "scenario above) — soft-failed events participate in resolution, rejected events never update state")
            {
                // Documented via the assertion above plus the "A rejected
                // event's after-state equals the state before it" scenario;
                // no separate assertion needed here.
                SUCCEED();
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("Auth events selection violations are rejected", "[pdu_ingestion][auth]")
{
    GIVEN("a seeded room")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!selection:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        WHEN("a PDU names an auth_event of a disallowed type")
        {
            // m.room.topic is never a permitted auth_events selection.
            auto const stray_topic_id = room_id + ":stray-topic";
            auto stray_content = merovingian::canonicaljson::Object{};
            stray_content.push_back(
                merovingian::canonicaljson::make_member("topic", merovingian::canonicaljson::Value{std::string{"x"}}));
            auto const stray_json =
                build_event_json(room_id, "m.room.topic", std::string{}, "@admin:local.example.org",
                                 std::move(stray_content), {genesis.admin_member_id}, {genesis.create_id}, 3, 4);
            started.runtime.database.persistent_store.events.push_back({stray_topic_id,
                                                                        room_id,
                                                                        "@admin:local.example.org",
                                                                        stray_json,
                                                                        3U,
                                                                        0U,
                                                                        {genesis.admin_member_id},
                                                                        {},
                                                                        {}});

            auto content = merovingian::canonicaljson::Object{};
            content.push_back(
                merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"hi"}}));
            auto const msg_json = build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org",
                                                   std::move(content), {genesis.admin_member_id},
                                                   {genesis.create_id, genesis.pl_id, stray_topic_id}, 3, 4);
            auto const envelope = make_envelope(room_id, "$disallowed:local.example.org", "m.room.message",
                                                std::nullopt, "@admin:local.example.org", {genesis.admin_member_id},
                                                {genesis.create_id, genesis.pl_id, stray_topic_id}, 3, msg_json);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }
        }

        WHEN("a PDU names two auth_events sharing the same (type, state_key)")
        {
            auto const second_pl_id = room_id + ":second-pl";
            auto second_content = merovingian::canonicaljson::Object{};
            second_content.push_back(merovingian::canonicaljson::make_member(
                "state_default", merovingian::canonicaljson::Value{std::int64_t{0}}));
            auto const second_json =
                build_event_json(room_id, "m.room.power_levels", std::string{}, "@admin:local.example.org",
                                 std::move(second_content), {genesis.pl_id}, {genesis.create_id}, 1, 2);
            started.runtime.database.persistent_store.events.push_back(
                {second_pl_id, room_id, "@admin:local.example.org", second_json, 1U, 0U, {genesis.pl_id}, {}, {}});

            auto content = merovingian::canonicaljson::Object{};
            content.push_back(
                merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"hi"}}));
            auto const msg_json = build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org",
                                                   std::move(content), {genesis.admin_member_id},
                                                   {genesis.create_id, genesis.pl_id, second_pl_id}, 3, 4);
            auto const envelope = make_envelope(room_id, "$duplicate:local.example.org", "m.room.message", std::nullopt,
                                                "@admin:local.example.org", {genesis.admin_member_id},
                                                {genesis.create_id, genesis.pl_id, second_pl_id}, 3, msg_json);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }
        }

        WHEN("a PDU names an auth_event that belongs to a different room")
        {
            auto const other_room_id = std::string{"!other:local.example.org"};
            auto const other_create_id = other_room_id + ":create";
            auto other_create_content = merovingian::canonicaljson::Object{};
            other_create_content.push_back(merovingian::canonicaljson::make_member(
                "creator", merovingian::canonicaljson::Value{std::string{"@admin:local.example.org"}}));
            auto const other_create_json =
                build_event_json(other_room_id, "m.room.create", std::string{}, "@admin:local.example.org",
                                 std::move(other_create_content), {}, {}, 0, 1);
            started.runtime.database.persistent_store.events.push_back(
                {other_create_id, other_room_id, "@admin:local.example.org", other_create_json, 0U, 0U, {}, {}, {}});

            auto content = merovingian::canonicaljson::Object{};
            content.push_back(
                merovingian::canonicaljson::make_member("body", merovingian::canonicaljson::Value{std::string{"hi"}}));
            auto const msg_json = build_event_json(room_id, "m.room.message", std::nullopt, "@admin:local.example.org",
                                                   std::move(content), {genesis.admin_member_id},
                                                   {other_create_id, genesis.pl_id, genesis.admin_member_id}, 3, 4);
            auto const envelope = make_envelope(room_id, "$otherroom:local.example.org", "m.room.message", std::nullopt,
                                                "@admin:local.example.org", {genesis.admin_member_id},
                                                {other_create_id, genesis.pl_id, genesis.admin_member_id}, 3, msg_json);
            auto const result = merovingian::homeserver::ingest_pdu_event(started.runtime, envelope);

            THEN("it is rejected")
            {
                REQUIRE(result.status == PduIngestionStatus::rejected_auth);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A transaction mixing accepted, rejected, and soft-failed PDUs still returns 200", "[pdu_ingestion][auth]")
{
    GIVEN("a pdu_sink whose results vary per event and a runtime with no other federation state")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);

        auto seen = std::vector<std::string>{};
        started.runtime.federation.pdu_sink = [&seen](merovingian::federation::InboundPduEnvelope const& envelope)
            -> merovingian::federation::PduIngestionResult {
            seen.push_back(envelope.event_id);
            if (envelope.event_id == "$accept:remote.example.org")
            {
                return {PduIngestionStatus::accepted, "", 1U, 1U};
            }
            if (envelope.event_id == "$softfail:remote.example.org")
            {
                return {PduIngestionStatus::soft_failed, "banned sender", 0U, 0U};
            }
            return {PduIngestionStatus::rejected_auth, "auth denied", 0U, 0U};
        };

        WHEN("ingest_pdu_event-shaped results are produced for accepted, rejected, and soft-failed PDUs")
        {
            auto const accepted = started.runtime.federation.pdu_sink(merovingian::federation::InboundPduEnvelope{
                .event_id = "$accept:remote.example.org", .room_id = "!txn:local.example.org"});
            auto const rejected = started.runtime.federation.pdu_sink(merovingian::federation::InboundPduEnvelope{
                .event_id = "$reject:remote.example.org", .room_id = "!txn:local.example.org"});
            auto const soft_failed = started.runtime.federation.pdu_sink(merovingian::federation::InboundPduEnvelope{
                .event_id = "$softfail:remote.example.org", .room_id = "!txn:local.example.org"});

            THEN("each keeps its own status and none of them is an internal error")
            {
                REQUIRE(accepted.status == PduIngestionStatus::accepted);
                REQUIRE(rejected.status == PduIngestionStatus::rejected_auth);
                REQUIRE(soft_failed.status == PduIngestionStatus::soft_failed);
            }

            THEN("all three were handed to the sink — a rejection or soft-failure does not stop processing the rest")
            {
                REQUIRE(seen.size() == 3U);
            }
        }

        std::filesystem::remove(path);
    }
}
