// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Security audit run 2: F-40 (the ADR-0225 fallback event must not rewrite current state from one
// fork) and F-49 (a refused recomputation of current state, and the forward-extremity bound).
// ADRs 0373, 0374 and 0375. Both are proved through ingest_pdu_event, the production federation
// PDU sink, and the store_local_event choke point a local event goes through.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Soft failure": "Soft failure is ... to
// discourage servers from sending events that evade ban or other membership restrictions" and
// current state is "the resolved state across all forward extremities".

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/event_query.hpp"
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
#include <utility>
#include <vector>

namespace
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;
using merovingian::homeserver::HomeserverRuntime;

constexpr auto admin = "@admin:local.example.org";
constexpr auto mod = "@mod:remote.example.org";
constexpr auto user_one = "@a1:remote.example.org";
constexpr auto user_two = "@a2:remote.example.org";

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-state-fallback-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path,
                                      merovingian::config::FederationStateResolutionConfig resolution)
    -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "local.example.org";

    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();

    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;
    security.federation.state_resolution = resolution;

    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

// A room on a started runtime, with its history built the way ingest builds it: every event gets
// its state group, the forward extremities follow, and current state is recomputed.
class Room final
{
public:
    Room(HomeserverRuntime& runtime, std::string room_id)
        : runtime_{runtime}
        , room_id_{std::move(room_id)}
        , policy_{merovingian::rooms::find_room_version_policy("10")}
    {
        REQUIRE(policy_ != nullptr);
        auto& store = runtime_.database.persistent_store;
        store.rooms.push_back({room_id_, admin});
        runtime_.database.rooms.push_back({room_id_, admin, {}, false});
    }

    [[nodiscard]] auto id() const -> std::string const&
    {
        return room_id_;
    }

    [[nodiscard]] auto policy() const -> merovingian::rooms::RoomVersionPolicy const&
    {
        return *policy_;
    }

    [[nodiscard]] auto store() -> merovingian::database::PersistentStore&
    {
        return runtime_.database.persistent_store;
    }

    // Stores `event_id` as already-accepted history on `prev`.
    auto seed(std::string const& event_id, std::string const& type, std::optional<std::string> const& state_key,
              std::string const& sender, std::string const& content_json, std::vector<std::string> const& prev,
              std::vector<std::string> const& auth) -> void
    {
        auto& store = this->store();
        auto event = merovingian::database::PersistentEvent{};
        event.event_id = event_id;
        event.room_id = room_id_;
        event.sender_user_id = sender;
        event.json = event_json(type, state_key, sender, content_json, prev, auth);
        event.depth = ++depth_;
        event.stream_ordering = merovingian::homeserver::allocate_stream_ordering(runtime_.database);
        event.prev_event_ids = prev;
        event.auth_event_ids = auth;
        store.events.push_back(event);
        auto const before = merovingian::homeserver::compute_state_before(store, room_id_, *policy_, prev, limits());
        REQUIRE(before.ok);
        auto const after = merovingian::homeserver::compute_state_after(before.state, event_id, type, state_key);
        REQUIRE(merovingian::homeserver::record_event_state(store, room_id_, event_id, prev, after).has_value());
        if (state_key.has_value())
        {
            REQUIRE(merovingian::database::store_state(store, {room_id_, type, *state_key, event_id}));
        }
        if (type == "m.room.member" && state_key.has_value())
        {
            store.memberships.push_back({room_id_, *state_key, "join", event.stream_ordering});
        }
    }

    [[nodiscard]] auto limits() const -> merovingian::events::StateResolutionLimits
    {
        return merovingian::homeserver::state_resolution_limits(runtime_.config.security().federation.state_resolution);
    }

    // A PDU as a remote server would send it.
    [[nodiscard]] auto pdu(std::string const& event_id, std::string const& type,
                           std::optional<std::string> const& state_key, std::string const& sender,
                           std::string const& content_json, std::vector<std::string> const& prev,
                           std::vector<std::string> const& auth, std::int64_t ts) -> InboundPduEnvelope
    {
        using namespace merovingian;
        auto const content = canonicaljson::parse_lossless(content_json);
        REQUIRE(content.error == canonicaljson::ParseError::none);
        auto const to_array = [](std::vector<std::string> const& ids) {
            auto array = canonicaljson::Array{};
            for (auto const& id : ids)
            {
                array.push_back(canonicaljson::Value{id});
            }
            return canonicaljson::Value{std::move(array)};
        };
        auto obj = canonicaljson::Object{};
        obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{type}));
        if (state_key.has_value())
        {
            obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
        }
        obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id_}));
        obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
        obj.push_back(canonicaljson::make_member("content", content.value));
        obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
        obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{50}}));
        obj.push_back(canonicaljson::make_member("prev_events", to_array(prev)));
        obj.push_back(canonicaljson::make_member("auth_events", to_array(auth)));
        auto const hash = events::make_content_hash(canonicaljson::Value{obj});
        REQUIRE(hash.error.empty());
        auto hashes = canonicaljson::Object{};
        hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
        obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
        auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
        REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);

        auto envelope = InboundPduEnvelope{};
        envelope.event_id = event_id;
        envelope.room_id = room_id_;
        envelope.room_version = "10";
        envelope.sender = sender;
        envelope.event_type = type;
        envelope.state_key = state_key;
        envelope.origin_server_ts = ts;
        envelope.depth = 50U;
        envelope.prev_event_ids = prev;
        envelope.auth_event_ids = auth;
        envelope.json = serialized.output;
        return envelope;
    }

    [[nodiscard]] auto ingest(InboundPduEnvelope const& envelope) -> PduIngestionStatus
    {
        return merovingian::homeserver::ingest_pdu_event(runtime_, envelope).status;
    }

    [[nodiscard]] auto current(std::string const& type, std::string const& state_key) -> std::optional<std::string>
    {
        return merovingian::database::find_current_state_event_id(store(), room_id_, type, state_key);
    }

    [[nodiscard]] auto tips() -> std::vector<std::string>
    {
        auto tips = merovingian::database::find_forward_extremities(store(), room_id_);
        std::ranges::sort(tips);
        return tips;
    }

    [[nodiscard]] auto status_of(std::string const& event_id) -> std::string
    {
        return merovingian::database::find_event_status(store(), event_id).value_or("(not stored)");
    }

private:
    [[nodiscard]] auto event_json(std::string const& type, std::optional<std::string> const& state_key,
                                  std::string const& sender, std::string const& content_json,
                                  std::vector<std::string> const& prev, std::vector<std::string> const& auth) const
        -> std::string
    {
        auto const array = [](std::vector<std::string> const& ids) {
            auto text = std::string{"["};
            for (auto const& id : ids)
            {
                text += (text.size() > 1U ? ",\"" : "\"") + id + "\"";
            }
            return text + "]";
        };
        return "{\"type\":\"" + type + "\"" +
               (state_key.has_value() ? ",\"state_key\":\"" + *state_key + "\"" : std::string{}) + ",\"sender\":\"" +
               sender + "\",\"room_id\":\"" + room_id_ + "\",\"content\":" + content_json +
               ",\"origin_server_ts\":1,\"depth\":" + std::to_string(depth_) + ",\"prev_events\":" + array(prev) +
               ",\"auth_events\":" + array(auth) + "}";
    }

    HomeserverRuntime& runtime_;
    std::string room_id_;
    merovingian::rooms::RoomVersionPolicy const* policy_;
    std::uint64_t depth_{0U};
};

// create, power levels (admin 100, `mod` 50), public join rules, and the given members joined.
auto seed_history(Room& room, std::vector<std::string> const& members, std::string const& power_levels_json) -> void
{
    room.seed("$create", "m.room.create", std::string{}, admin,
              std::string{R"({"creator":")"} + admin + R"(","room_version":"10"})", {}, {});
    room.seed("$pl", "m.room.power_levels", std::string{}, admin, power_levels_json, {"$create"}, {"$create"});
    room.seed("$rules", "m.room.join_rules", std::string{}, admin, R"({"join_rule":"public"})", {"$pl"},
              {"$create", "$pl"});
    auto previous = std::string{"$rules"};
    room.seed("$join_admin", "m.room.member", std::string{admin}, admin, R"({"membership":"join"})", {previous},
              {"$create", "$rules"});
    previous = "$join_admin";
    for (auto const& member : members)
    {
        auto const id = "$join_" + member;
        room.seed(id, "m.room.member", member, member, R"({"membership":"join"})", {previous}, {"$create", "$rules"});
        previous = id;
    }
}

constexpr auto base_power_levels =
    R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,"state_default":50,"users_default":0,)"
    R"("users":{"@admin:local.example.org":100,"@mod:remote.example.org":50}})";

} // namespace

// F-40, ADR-0373. State resolution fails (the state budget), so the next local event cannot cite
// both tips and takes the ADR-0225 fallback. The fork it builds on predates the ban.
SCENARIO("A banned user stays banned after a local event takes the fallback and after a further inbound PDU",
         "[pdu_ingestion][state_groups][fallback][f40]")
{
    GIVEN("a room where a ban tip sits beside a newer fork that predates it, and the tips cannot be resolved")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto resolution = merovingian::config::FederationStateResolutionConfig{};
        // Six state entries per tip: two distinct tips need 12.
        resolution.max_total_state_events = 11U;
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, resolution));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto room = Room{started.runtime, "!fallback:local.example.org"};
        seed_history(room, {user_one, user_two}, base_power_levels);
        auto const join_one = std::string{"$join_"} + user_one;
        auto const join_two = std::string{"$join_"} + user_two;
        auto const tip = join_two;

        auto const ban = room.pdu("$ban", "m.room.member", std::string{user_one}, admin, R"({"membership":"ban"})",
                                  {tip}, {"$create", "$pl", "$join_admin", join_one}, 100);
        REQUIRE(room.ingest(ban) == PduIngestionStatus::accepted);
        REQUIRE(room.current("m.room.member", user_one) == std::optional<std::string>{"$ban"});

        // user_two is still joined, so a message citing the event before the ban is accepted.
        auto const fork = room.pdu("$fork", "m.room.message", std::nullopt, user_two,
                                   R"({"body":"x","msgtype":"m.text"})", {tip}, {"$create", "$pl", join_two}, 110);
        REQUIRE(room.ingest(fork) == PduIngestionStatus::accepted);
        REQUIRE(room.tips() == std::vector<std::string>{"$ban", "$fork"});
        REQUIRE(room.current("m.room.member", user_one) == std::optional<std::string>{"$ban"});

        WHEN("a local event is stored after the fallback, and the first inbound PDU after it is accepted")
        {
            auto const basis =
                merovingian::homeserver::basis_for_new_event(room.store(), room.id(), room.policy(), room.limits());
            REQUIRE(basis.ok);
            REQUIRE(basis.prev_event_ids == std::vector<std::string>{"$fork"});
            REQUIRE(basis.retired_extremities == std::vector<std::string>{"$ban"});

            auto local = merovingian::database::PersistentEvent{};
            local.event_id = "$local";
            local.room_id = room.id();
            local.sender_user_id = admin;
            local.json = std::string{R"({"type":"m.room.message","sender":")"} + admin +
                         R"(","content":{"body":"hi","msgtype":"m.text"}})";
            local.depth = 60U;
            local.prev_event_ids = basis.prev_event_ids;
            REQUIRE(merovingian::homeserver::store_local_event(room.store(), room.policy(), local, std::nullopt, basis,
                                                               room.limits()));
            auto const after_local = room.current("m.room.member", user_one);

            auto const topic = room.pdu("$topic", "m.room.topic", std::string{}, admin, R"({"topic":"t"})", {"$local"},
                                        {"$create", "$pl", "$join_admin"}, 120);
            auto const topic_status = room.ingest(topic);

            THEN("the user stays banned in current state after the local event")
            {
                REQUIRE(after_local == std::optional<std::string>{"$ban"});
            }

            THEN("the user stays banned after the next accepted inbound PDU recomputes current state")
            {
                REQUIRE(topic_status == PduIngestionStatus::accepted);
                REQUIRE(room.tips() == std::vector<std::string>{"$topic"});
                REQUIRE(room.current("m.room.member", user_one) == std::optional<std::string>{"$ban"});
            }

            THEN("the banned user's next PDU, citing the local event's descendant, is not accepted")
            {
                auto const evasion =
                    room.pdu("$evasion", "m.room.message", std::nullopt, user_one,
                             R"({"body":"back","msgtype":"m.text"})", {"$topic"}, {"$create", "$pl", join_one}, 130);
                auto const status = room.ingest(evasion);
                REQUIRE((status == PduIngestionStatus::soft_failed || status == PduIngestionStatus::rejected_auth));
                REQUIRE(room.status_of("$evasion") != "accepted");
                REQUIRE(room.tips() == std::vector<std::string>{"$topic"});
            }
        }

        std::filesystem::remove(path);
    }
}

// F-49, ADR-0374. A flood of messages that cite one old event must not stop a demotion from
// reverting what the demoted moderator did concurrently.
SCENARIO("A demotion still reverts the demoted sender's concurrent state past the forward-extremity limit",
         "[pdu_ingestion][state_groups][f49]")
{
    GIVEN("a room whose moderator set the topic on a fork that honest servers never saw, and a message flood")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto resolution = merovingian::config::FederationStateResolutionConfig{};
        resolution.max_state_groups = 3U;
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, resolution));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto room = Room{started.runtime, "!flood:local.example.org"};
        seed_history(room, {mod}, base_power_levels);
        room.seed("$topic_admin", "m.room.topic", std::string{}, admin, R"({"topic":"admin"})",
                  {std::string{"$join_"} + mod}, {"$create", "$pl", "$join_admin"});
        auto const base = std::string{"$topic_admin"};
        auto const join_mod = std::string{"$join_"} + mod;
        auto const mod_auth = std::vector<std::string>{"$create", "$pl", join_mod};

        auto const concurrent =
            room.pdu("$topic_mod", "m.room.topic", std::string{}, mod, R"({"topic":"mod"})", {base}, mod_auth, 100);
        REQUIRE(room.ingest(concurrent) == PduIngestionStatus::accepted);
        REQUIRE(room.current("m.room.topic", "") == std::optional<std::string>{"$topic_mod"});

        WHEN("more messages than the limit cite the old event, then the admin demotes the moderator")
        {
            auto statuses = std::vector<PduIngestionStatus>{};
            for (auto index = 0; index < 6; ++index)
            {
                statuses.push_back(
                    room.ingest(room.pdu("$flood" + std::to_string(index), "m.room.message", std::nullopt, mod,
                                         R"({"body":"spam","msgtype":"m.text"})", {base}, mod_auth, 110 + index)));
            }
            auto const tips_after_flood = room.tips().size();
            auto const demotion = room.pdu("$demotion", "m.room.power_levels", std::string{}, admin,
                                           R"({"ban":50,"events_default":0,"invite":0,"kick":50,"redact":50,)"
                                           R"("state_default":50,"users_default":0,)"
                                           R"("users":{"@admin:local.example.org":100}})",
                                           {base}, {"$create", "$pl", "$join_admin"}, 200);
            auto const demotion_status = room.ingest(demotion);

            THEN("every message is accepted, but only as many become tips as the limit allows")
            {
                REQUIRE(std::ranges::all_of(statuses, [](auto status) {
                    return status == PduIngestionStatus::accepted;
                }));
                REQUIRE(tips_after_flood <= 3U);
                REQUIRE(room.status_of("$flood5") == "accepted");
            }

            THEN("the demotion is accepted and becomes current")
            {
                REQUIRE(demotion_status == PduIngestionStatus::accepted);
                REQUIRE(room.current("m.room.power_levels", "") == std::optional<std::string>{"$demotion"});
                auto const tips = room.tips();
                REQUIRE(std::ranges::find(tips, "$demotion") != tips.end());
            }

            THEN("the topic the demoted moderator set is reverted to the admin's")
            {
                REQUIRE(room.current("m.room.topic", "") == std::optional<std::string>{"$topic_admin"});
            }
        }

        std::filesystem::remove(path);
    }
}

// Rooms where resolution succeeds behave as before: a message fork is a tip, and a state fork
// resolves.
SCENARIO("A room below the forward-extremity limit keeps every fork as a tip and resolves them",
         "[pdu_ingestion][state_groups][f49]")
{
    GIVEN("a room with default limits")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(
            config_with_sqlite(path, merovingian::config::FederationStateResolutionConfig{}));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto room = Room{started.runtime, "!ordinary:local.example.org"};
        seed_history(room, {mod}, base_power_levels);
        auto const join_mod = std::string{"$join_"} + mod;
        auto const mod_auth = std::vector<std::string>{"$create", "$pl", join_mod};

        WHEN("two messages and a topic cite the same event")
        {
            auto const first = room.ingest(room.pdu("$m1", "m.room.message", std::nullopt, mod,
                                                    R"({"body":"1","msgtype":"m.text"})", {join_mod}, mod_auth, 100));
            auto const second = room.ingest(room.pdu("$m2", "m.room.message", std::nullopt, mod,
                                                     R"({"body":"2","msgtype":"m.text"})", {join_mod}, mod_auth, 110));
            auto const topic = room.ingest(
                room.pdu("$t", "m.room.topic", std::string{}, mod, R"({"topic":"t"})", {join_mod}, mod_auth, 120));

            THEN("all three are accepted and each is a forward extremity")
            {
                REQUIRE(first == PduIngestionStatus::accepted);
                REQUIRE(second == PduIngestionStatus::accepted);
                REQUIRE(topic == PduIngestionStatus::accepted);
                REQUIRE(room.tips() == std::vector<std::string>{"$m1", "$m2", "$t"});
                REQUIRE(room.current("m.room.topic", "") == std::optional<std::string>{"$t"});
            }
        }

        std::filesystem::remove(path);
    }
}

// F-40, ADR-0373. What /state and /state_ids answer for a fallback event must be what this server
// recorded for it, whether the event is a message or a state event. The state before a state event
// is its own group without the event, not the group of the fork it cites, which predates the ban.
SCENARIO("The state read at a fallback state event agrees with the state recorded for it",
         "[pdu_ingestion][state_groups][fallback][f40]")
{
    GIVEN("a room with a topic, a ban tip and a newer fork that predates the ban, whose tips cannot be resolved")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto resolution = merovingian::config::FederationStateResolutionConfig{};
        // Seven state entries per tip: two distinct tips need 14.
        resolution.max_total_state_events = 13U;
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, resolution));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto room = Room{started.runtime, "!fallbackread:local.example.org"};
        seed_history(room, {user_one, user_two}, base_power_levels);
        auto const join_one = std::string{"$join_"} + user_one;
        auto const join_two = std::string{"$join_"} + user_two;

        auto const old_topic = room.pdu("$old_topic", "m.room.topic", std::string{}, admin, R"({"topic":"old"})",
                                        {join_two}, {"$create", "$pl", "$join_admin"}, 90);
        REQUIRE(room.ingest(old_topic) == PduIngestionStatus::accepted);
        auto const ban = room.pdu("$ban", "m.room.member", std::string{user_one}, admin, R"({"membership":"ban"})",
                                  {"$old_topic"}, {"$create", "$pl", "$join_admin", join_one}, 100);
        REQUIRE(room.ingest(ban) == PduIngestionStatus::accepted);
        auto const fork = room.pdu("$fork", "m.room.message", std::nullopt, user_two,
                                   R"({"body":"x","msgtype":"m.text"})", {"$old_topic"}, {"$create", "$pl", join_two},
                                   110);
        REQUIRE(room.ingest(fork) == PduIngestionStatus::accepted);
        REQUIRE(room.tips() == std::vector<std::string>{"$ban", "$fork"});

        WHEN("a local state event is stored through the fallback")
        {
            auto const basis =
                merovingian::homeserver::basis_for_new_event(room.store(), room.id(), room.policy(), room.limits());
            REQUIRE(basis.ok);
            REQUIRE(basis.prev_event_ids == std::vector<std::string>{"$fork"});

            auto local = merovingian::database::PersistentEvent{};
            local.event_id = "$local_topic";
            local.room_id = room.id();
            local.sender_user_id = admin;
            local.json = std::string{R"({"type":"m.room.topic","state_key":"","sender":")"} + admin +
                         R"(","content":{"topic":"new"}})";
            local.depth = 60U;
            local.prev_event_ids = basis.prev_event_ids;
            REQUIRE(merovingian::homeserver::store_local_event(
                room.store(), room.policy(), local,
                merovingian::database::PersistentStateEvent{room.id(), "m.room.topic", "", "$local_topic"}, basis,
                room.limits()));

            auto const before = merovingian::federation::state_before_event(room.store(), room.id(), "$local_topic");
            auto const holds = [&before](std::string const& event_id) {
                return std::ranges::find(before.event_ids, event_id) != before.event_ids.end();
            };

            THEN("the state before it holds the ban the fork lacks, and the banned user's old join is gone")
            {
                REQUIRE(before.known);
                REQUIRE(holds("$ban"));
                REQUIRE_FALSE(holds(join_one));
            }
            AND_THEN("the event is not in its own state before, and the value it replaced is")
            {
                REQUIRE_FALSE(holds("$local_topic"));
                REQUIRE(holds("$old_topic"));
            }
        }

        std::filesystem::remove(path);
    }
}
