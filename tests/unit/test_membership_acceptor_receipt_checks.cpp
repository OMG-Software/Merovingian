// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0064 phase B2 follow-up: the membership-acceptor path
// (send_join/send_leave/send_knock acceptance, `runtime.federation.
// membership_acceptor` in src/homeserver/local_http_router.cpp) runs the
// same receipt-order checks as the /send transaction path
// (run_pdu_receipt_checks, shared by both). Tags: [pdu_ingestion][auth].
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU" (step 3: hash -> redact, not reject; step 4: auth
// against the event's own auth_events -> reject; step 6: auth against
// current state -> soft-fail, not reject), "Joining rooms".

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
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
using merovingian::homeserver::HomeserverRuntime;

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-membership-acceptor-" + std::to_string(now) + ".sqlite3");
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

    return {create_id, pl_id, member_id};
}

} // namespace

SCENARIO("send_join: a joining event with a mismatched content hash is redacted and accepted, not rejected",
         "[pdu_ingestion][auth]")
{
    GIVEN("a seeded room and a send_join whose declared hash does not match its content")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        REQUIRE(started.runtime.federation.membership_acceptor != nullptr);

        auto const room_id = std::string{"!sjhash:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        // find_room_version_policy("10") for a join event: auth_events are
        // create + join_rules (public join) — no target member yet (bob
        // has never joined before).
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const bad_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                             "@bob:remote.example.org", std::move(content), {genesis.admin_member_id},
                             {genesis.create_id, genesis.pl_id}, 4, 5, std::string{"this-does-not-match"});
        auto const envelope = make_envelope(room_id, "$sjbadhash:remote.example.org", "m.room.member",
                                            std::string{"@bob:remote.example.org"}, "@bob:remote.example.org",
                                            {genesis.admin_member_id}, {genesis.create_id, genesis.pl_id}, 4, bad_json);

        WHEN("the send_join is accepted")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("it is accepted, not rejected with a hash error")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
            }

            THEN("the stored event's content is redacted while event_id and sender survive")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$sjbadhash:remote.example.org";
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
                REQUIRE(std::get<std::string>(sender_val->storage()) == "@bob:remote.example.org");
                // m.room.member keeps only "membership" under redaction, and
                // it is preserved because it did not need stripping.
                auto const* content_val = find("content");
                REQUIRE(content_val != nullptr);
                auto const* content_obj = std::get_if<merovingian::canonicaljson::Object>(&content_val->storage());
                REQUIRE(content_obj != nullptr);
                auto const* membership_val = [&]() -> merovingian::canonicaljson::Value const* {
                    for (auto const& m : *content_obj)
                    {
                        if (m.key == "membership")
                        {
                            return m.value.get();
                        }
                    }
                    return nullptr;
                }();
                REQUIRE(membership_val != nullptr);
                REQUIRE(std::get<std::string>(membership_val->storage()) == "join");
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("send_join: a joining event that fails its own auth_events is rejected", "[pdu_ingestion][auth]")
{
    GIVEN("a send_join whose named auth_events reference a power_levels event with a prohibitive state_default")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!sjauthevents:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        // A stray, never-applied power_levels event with join_rule absent
        // (so join_rules is not "public"), and no join_rules entry at all
        // named — this makes step 4's own-auth_events check deny the join
        // (no public join_rules reachable in the named map).
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                           "@bob:remote.example.org", std::move(content), {genesis.admin_member_id},
                                           {genesis.create_id, genesis.pl_id}, 4, 5);
        // No join_rules named in auth_events at all -> Step 5 of the member
        // auth rules ("cannot join without an invite unless join_rules is
        // public, and public join_rules must be provable via auth_events")
        // denies it.
        auto const envelope = make_envelope(room_id, "$sjbadauth:remote.example.org", "m.room.member",
                                            std::string{"@bob:remote.example.org"}, "@bob:remote.example.org",
                                            {genesis.admin_member_id}, {genesis.create_id, genesis.pl_id}, 4, json);

        WHEN("the send_join is processed")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("it is rejected with a definite error, not silently accepted")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
            }

            THEN("it is still stored, marked rejected, so a later event can reference it")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$sjbadauth:remote.example.org";
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->status == "rejected");
            }

            THEN("it never reaches current state")
            {
                auto const& state = started.runtime.database.persistent_store.state;
                REQUIRE(std::ranges::none_of(state, [&](merovingian::database::PersistentStateEvent const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" &&
                           s.state_key == "@bob:remote.example.org";
                }));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("A membership event passing its auth_events and state-before but failing current state is soft-failed",
         "[pdu_ingestion][auth]")
{
    GIVEN("bob is banned, then a send_join for bob referencing pre-ban history arrives")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!sjsoftfail:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");

        auto const ban_id = room_id + ":ban-bob";
        auto ban_content = merovingian::canonicaljson::Object{};
        ban_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"ban"}}));
        auto const ban_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                             "@admin:local.example.org", std::move(ban_content), {genesis.admin_member_id},
                             {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(started.runtime, room_id, ban_id, "m.room.member", std::string{"@bob:remote.example.org"},
                            "@admin:local.example.org", ban_json, {genesis.admin_member_id}, 4U);

        // Bob's send_join: auth_events reference create/power_levels only
        // (no prior member row for bob at all in the named set, nor in the
        // state before its prev_event, which is the pre-ban admin-member
        // tip) -> both step 4 and step 5 see bob as never-banned (defaults
        // to "leave", not "ban") and allow the join. Only step 6 (current
        // state, where bob IS banned) denies it.
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                           "@bob:remote.example.org", std::move(content), {genesis.admin_member_id},
                                           {genesis.create_id, genesis.pl_id}, 4, 5);
        auto const envelope = make_envelope(room_id, "$sjsoftfail:remote.example.org", "m.room.member",
                                            std::string{"@bob:remote.example.org"}, "@bob:remote.example.org",
                                            {genesis.admin_member_id}, {genesis.create_id, genesis.pl_id}, 4, json);

        WHEN("the send_join is processed")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("it is accepted at the protocol level (200), neither a hard rejection nor silently dropped")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
            }

            THEN("it is stored, marked soft_failed, not accepted")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$sjsoftfail:remote.example.org";
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->status == "soft_failed");
            }

            THEN("it is not a forward extremity — the ban stays the room's sole tip")
            {
                auto const extremities =
                    merovingian::database::find_forward_extremities(started.runtime.database.persistent_store, room_id);
                REQUIRE(extremities == std::vector<std::string>{ban_id});
            }

            THEN("bob's membership cache is not flipped to join — the live view still reflects the ban")
            {
                auto const& memberships = started.runtime.database.persistent_store.memberships;
                auto const bob_membership =
                    std::ranges::find_if(memberships, [&](merovingian::database::PersistentMembership const& m) {
                        return m.room_id == room_id && m.user_id == "@bob:remote.example.org";
                    });
                REQUIRE(bob_membership != memberships.end());
                REQUIRE(bob_membership->membership == "ban");
            }
        }

        std::filesystem::remove(path);
    }
}
