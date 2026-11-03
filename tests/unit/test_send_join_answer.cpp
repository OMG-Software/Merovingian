// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Security audit run 2, F-23 (ADR-0366) and F-19 (ADR-0367): this server as the resident of a room a
// remote server joins.
//
//   * A join whose answer cannot be delivered is refused, retryably, BEFORE it is stored or sent on.
//   * `omit_members` gives a reduced answer that fits where the full one does not.
//   * A join sent twice is answered twice, not refused the second time.
//   * What a make_join and a restricted-join decision read follows the room, not the server.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, PUT /send_join (query parameter `omit_members`;
// response `auth_chain`, `members_omitted`, `servers_in_room`, `state`), GET /make_join, "Restricted
// rooms"; docs/matrix-v1.19-spec/rooms/v11.md `prev_events` ("Must contain less than or equal to 20
// events").

#include "../support/master_key.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/dispatch_worker.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/restricted_join.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/send_join_answer.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

namespace
{

namespace cj = merovingian::canonicaljson;
using merovingian::federation::FederationEndpoint;
using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;

auto constexpr our_server = std::string_view{"local.example.org"};
auto constexpr admin = std::string_view{"@admin:local.example.org"};
auto constexpr bob = std::string_view{"@bob:remote.example.org"};
auto constexpr carol = std::string_view{"@carol:other.example.org"};

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("merovingian-send-join-answer-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path, std::string join_response_max_size)
    -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::string{our_server};
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;
    security.federation.join_response_max_size = std::move(join_response_max_size);
    return {server,   merovingian::config::ListenersConfig{},        database,
            security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{}};
}

[[nodiscard]] auto event_json(std::string const& room_id, std::string const& type,
                              std::optional<std::string> const& state_key, std::string const& sender,
                              std::string const& content_json, std::vector<std::string> const& prev_event_ids,
                              std::vector<std::string> const& auth_event_ids, std::int64_t depth) -> std::string
{
    using namespace merovingian;
    auto const content = canonicaljson::parse_lossless(content_json);
    REQUIRE(content.error == canonicaljson::ParseError::none);
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{type}));
    if (state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
    }
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
    obj.push_back(canonicaljson::make_member("content", content.value));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{depth + 100}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    auto prev = canonicaljson::Array{};
    for (auto const& id : prev_event_ids)
    {
        prev.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{std::move(prev)}));
    auto auth = canonicaljson::Array{};
    for (auto const& id : auth_event_ids)
    {
        auth.push_back(canonicaljson::Value{id});
    }
    obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{std::move(auth)}));
    auto const hash = events::make_content_hash(canonicaljson::Value{obj});
    REQUIRE(hash.error.empty());
    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

auto seed(HomeserverRuntime& runtime, std::string const& room_id, std::string const& event_id, std::string const& type,
          std::optional<std::string> const& state_key, std::string const& sender, std::string const& content_json,
          std::vector<std::string> const& prev_event_ids, std::vector<std::string> const& auth_event_ids,
          std::uint64_t depth) -> void
{
    using namespace merovingian;
    auto const* policy = rooms::find_room_version_policy("10");
    REQUIRE(policy != nullptr);
    auto& store = runtime.database.persistent_store;
    auto const json = event_json(room_id, type, state_key, sender, content_json, prev_event_ids, auth_event_ids,
                                 static_cast<std::int64_t>(depth));
    store.events.push_back({event_id, room_id, sender, json, depth, 0U, prev_event_ids, auth_event_ids, {}});
    if (state_key.has_value())
    {
        store.state.push_back({room_id, type, *state_key, event_id});
    }
    auto const before = homeserver::compute_state_before(store, room_id, *policy, prev_event_ids);
    REQUIRE(before.ok);
    auto const after = homeserver::compute_state_after(before.state, event_id, type, state_key);
    REQUIRE(homeserver::record_event_state(store, room_id, event_id, prev_event_ids, after, true).has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));
    if (type == "m.room.member" && state_key.has_value())
    {
        auto const parsed = canonicaljson::parse_lossless(json);
        store.memberships.push_back(
            {room_id, *state_key, std::string{events::extract_content_membership(parsed.value)}, 0U});
    }
}

struct SeededRoom final
{
    std::string room_id{};
    std::string create_id{};
    std::string pl_id{};
    std::string admin_member_id{};
    std::string join_rules_id{};
    // The latest event: what a join's prev_events name.
    std::string tip_id{};
    std::uint64_t depth{4U};
};

// A v10 room on this server with the local admin joined at power 100 and the given join rules.
[[nodiscard]] auto seed_room(HomeserverRuntime& runtime, std::string const& room_id,
                             std::string const& join_rules_content) -> SeededRoom
{
    auto const a = std::string{admin};
    runtime.database.persistent_store.rooms.push_back({room_id, a});
    runtime.database.rooms.push_back({room_id, a, {std::string{admin}}, {}, false});
    auto room = SeededRoom{room_id,
                           room_id + "/create",
                           room_id + "/pl",
                           room_id + "/admin",
                           room_id + "/join_rules",
                           room_id + "/join_rules",
                           4U};
    seed(runtime, room_id, room.create_id, "m.room.create", std::string{}, a,
         R"({"creator":"@admin:local.example.org","room_version":"10"})", {}, {}, 1U);
    seed(runtime, room_id, room.admin_member_id, "m.room.member", a, a, R"({"membership":"join"})", {room.create_id},
         {room.create_id}, 2U);
    seed(runtime, room_id, room.pl_id, "m.room.power_levels", std::string{}, a,
         R"({"users":{"@admin:local.example.org":100}})", {room.admin_member_id},
         {room.create_id, room.admin_member_id}, 3U);
    seed(runtime, room_id, room.join_rules_id, "m.room.join_rules", std::string{}, a, join_rules_content, {room.pl_id},
         {room.create_id, room.pl_id, room.admin_member_id}, 4U);
    return room;
}

// Appends one more state event to the room, after its current tip.
auto seed_state_after(HomeserverRuntime& runtime, SeededRoom& room, std::string const& event_id,
                      std::string const& type, std::string const& state_key, std::string const& sender,
                      std::string const& content_json) -> void
{
    seed(runtime, room.room_id, event_id, type, state_key, sender, content_json, {room.tip_id},
         {room.create_id, room.pl_id, room.admin_member_id}, ++room.depth);
    room.tip_id = event_id;
}

auto add_to_roster(HomeserverRuntime& runtime, std::string const& room_id, std::string const& user) -> void
{
    auto const room = std::ranges::find_if(runtime.database.rooms, [&](auto const& current) {
        return current.room_id == room_id;
    });
    REQUIRE(room != runtime.database.rooms.end());
    room->members.push_back(user);
}

// A dispatch worker that is never started: every transaction the server enqueues stays in
// store.federation_transactions for the test to read.
auto install_unstarted_dispatch_worker(HomeserverRuntime& runtime) -> void
{
    REQUIRE(runtime.outbound_client != nullptr);
    auto config = merovingian::federation::DispatchWorkerConfig{};
    config.origin = runtime.config.server().server_name;
    config.key_id = "ed25519:test";
    runtime.dispatch_worker = std::make_unique<merovingian::federation::DispatchWorker>(
        std::move(config), *runtime.outbound_client,
        [](std::string_view) {
            return std::optional<merovingian::federation::ServerDiscoveryResult>{};
        },
        merovingian::federation::DispatchClock{}, merovingian::federation::DispatchSleep{},
        &runtime.database.persistent_store);
}

[[nodiscard]] auto join_envelope(SeededRoom const& room, std::string const& user, std::string const& event_id,
                                 std::vector<std::string> const& auth, bool omit_members = false) -> InboundPduEnvelope
{
    auto envelope = InboundPduEnvelope{};
    envelope.event_id = event_id;
    envelope.room_id = room.room_id;
    envelope.room_version = "10";
    envelope.sender = user;
    envelope.event_type = "m.room.member";
    envelope.state_key = user;
    envelope.depth = room.depth + 1U;
    envelope.prev_event_ids = {room.tip_id};
    envelope.auth_event_ids = auth;
    envelope.json = event_json(room.room_id, "m.room.member", user, user, R"({"membership":"join"})", {room.tip_id},
                               auth, static_cast<std::int64_t>(room.depth + 1U));
    envelope.omit_members = omit_members;
    return envelope;
}

[[nodiscard]] auto public_join_auth(SeededRoom const& room) -> std::vector<std::string>
{
    return {room.create_id, room.pl_id, room.join_rules_id};
}

[[nodiscard]] auto accept(HomeserverRuntime& runtime, InboundPduEnvelope const& envelope)
    -> merovingian::federation::MembershipAcceptResult
{
    return runtime.federation.membership_acceptor(FederationEndpoint::send_join, envelope.room_id, envelope.event_id,
                                                  envelope);
}

[[nodiscard]] auto string_member(cj::Object const& object, std::string_view key) -> std::string
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            auto const* text = std::get_if<std::string>(&member.value->storage());
            return text == nullptr ? std::string{} : *text;
        }
    }
    return {};
}

// The "type" of each event JSON, and the "type|state_key" of each, for comparing answers.
[[nodiscard]] auto described(std::vector<std::string> const& events) -> std::multiset<std::string>
{
    auto out = std::multiset<std::string>{};
    for (auto const& json : events)
    {
        auto const parsed = cj::parse_lossless(json);
        REQUIRE(parsed.error == cj::ParseError::none);
        auto const* object = std::get_if<cj::Object>(&parsed.value.storage());
        REQUIRE(object != nullptr);
        out.insert(string_member(*object, "type") + "|" + string_member(*object, "state_key"));
    }
    return out;
}

[[nodiscard]] auto event_count(HomeserverRuntime const& runtime, std::string const& event_id) -> std::size_t
{
    return static_cast<std::size_t>(
        std::ranges::count_if(runtime.database.persistent_store.events.rows(), [&](auto const& event) {
            return event.event_id == event_id;
        }));
}

// A displayname of `bytes` bytes, to make a member event as big as a test needs.
[[nodiscard]] auto padded_member_content(std::size_t bytes) -> std::string
{
    return R"({"membership":"join","displayname":")" + std::string(bytes, 'x') + R"("})";
}

} // namespace

// Spec: PUT /send_join 200 response: `state` is "The resolved current room state prior to the join
// event" and `auth_chain` "All events in the auth chain for the new join event". A resident that
// cannot send that answer must say so BEFORE it stores the join and tells the room's other servers
// of it (F-23): the join would be committed and fanned out, then lost to the server that sent it.
SCENARIO("A send_join whose answer cannot be delivered is refused with nothing stored or sent on",
         "[homeserver][send_join_answer][f23][security]")
{
    GIVEN("a public room whose state holds two 400 KiB events, a 1 MiB join response limit and a remote member")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "1MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        install_unstarted_dispatch_worker(runtime);
        auto room = seed_room(runtime, "!big:local.example.org", R"({"join_rule":"public"})");
        seed_state_after(runtime, room, "$pad1:local.example.org", "org.example.pad", "one", std::string{admin},
                         R"({"pad":")" + std::string(400U * 1024U, 'x') + R"("})");
        seed_state_after(runtime, room, "$pad2:local.example.org", "org.example.pad", "two", std::string{admin},
                         R"({"pad":")" + std::string(400U * 1024U, 'y') + R"("})");
        add_to_roster(runtime, room.room_id, std::string{carol});
        auto& store = runtime.database.persistent_store;
        auto const ordering_before = runtime.database.next_stream_ordering;
        auto const memberships_before = store.memberships.size();
        auto const queued_before = store.federation_transactions.size();
        auto const join_id = std::string{"$bobjoin:remote.example.org"};

        WHEN("bob's join is submitted")
        {
            auto const result = accept(runtime, join_envelope(room, std::string{bob}, join_id, public_join_auth(room)));

            THEN("it is refused 503, a status a joining server retries, and the reason names omit_members")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 503U);
                REQUIRE(result.reason.find("omit_members") != std::string::npos);
            }
            AND_THEN("nothing was stored: no event, no membership row, no stream ordering taken")
            {
                REQUIRE(event_count(runtime, join_id) == 0U);
                REQUIRE(store.memberships.size() == memberships_before);
                REQUIRE(runtime.database.next_stream_ordering == ordering_before);
            }
            AND_THEN("nothing was sent on to the room's other servers")
            {
                REQUIRE(store.federation_transactions.size() == queued_before);
            }
        }

        WHEN("bob's join asks for omit_members, which cannot shrink events that are not memberships")
        {
            auto const result =
                accept(runtime, join_envelope(room, std::string{bob}, join_id, public_join_auth(room), true));

            THEN("it is still refused with nothing stored")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 503U);
                REQUIRE(event_count(runtime, join_id) == 0U);
                REQUIRE(store.federation_transactions.size() == queued_before);
            }
        }

        WHEN("the limit allows the answer")
        {
            runtime.config.security().federation.join_response_max_size = "64MiB";
            auto const result = accept(runtime, join_envelope(room, std::string{bob}, join_id, public_join_auth(room)));

            THEN("the join is accepted, stored and sent on to the other server (the refusal above is not vacuous)")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
                REQUIRE(event_count(runtime, join_id) == 1U);
                REQUIRE(store.federation_transactions.size() > queued_before);
            }
            AND_THEN("the answer holds the state before the join, not the join")
            {
                REQUIRE(described(result.state_json).contains("org.example.pad|one"));
                REQUIRE_FALSE(described(result.state_json).contains("m.room.member|" + std::string{bob}));
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: PUT /send_join, query parameter `omit_members`: "membership events are omitted from `state`
// and redundant events are omitted from `auth_chain`"; with no m.room.name or m.room.canonical_alias,
// "the resident server should include [the heroes'] membership events in the response `state` field,
// and include the auth chains for these membership events in the response `auth_chain` field".
// Response: `members_omitted` "true if m.room.member events have been omitted from state";
// `servers_in_room` "Required if members_omitted is true"; "any events that are returned in `state`
// may be omitted from `auth_chain`".
SCENARIO("omit_members gives a reduced answer that fits where the full one does not",
         "[homeserver][send_join_answer][f23][omit_members]")
{
    GIVEN("a public room with 40 members whose events total over 1 MiB, bob invited, and a 1 MiB limit")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "1MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto room = seed_room(runtime, "!crowd:local.example.org", R"({"join_rule":"public"})");
        auto members = std::vector<std::string>{};
        for (auto index = 0; index < 39; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":" + (index % 2 == 0 ? "a" : "b") + ".example.org";
            seed_state_after(runtime, room, "$m" + std::to_string(index) + ":local.example.org", "m.room.member", user,
                             user, padded_member_content(30'000U));
            add_to_roster(runtime, room.room_id, user);
            members.push_back(user);
        }
        // bob holds an invite: his join names it in auth_events, and it is a membership event.
        seed_state_after(runtime, room, "$bobinvite:local.example.org", "m.room.member", std::string{bob},
                         std::string{admin}, R"({"membership":"invite"})");
        auto const join_auth =
            std::vector<std::string>{room.create_id, room.pl_id, room.join_rules_id, "$bobinvite:local.example.org"};
        auto const join_id = std::string{"$bobjoin:remote.example.org"};

        WHEN("the join does not ask for omit_members")
        {
            auto const result = accept(runtime, join_envelope(room, std::string{bob}, join_id, join_auth));

            THEN("it is refused: the full answer does not fit, and members_omitted could not be true")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 503U);
                REQUIRE(event_count(runtime, join_id) == 0U);
            }
        }

        WHEN("the join asks for omit_members")
        {
            auto const result = accept(runtime, join_envelope(room, std::string{bob}, join_id, join_auth, true));

            THEN("it is accepted and stored")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
                REQUIRE(event_count(runtime, join_id) == 1U);
            }
            AND_THEN("members_omitted is true and servers_in_room lists the servers with joined members")
            {
                REQUIRE(result.members_omitted);
                auto const servers =
                    std::set<std::string>{result.servers_in_room.begin(), result.servers_in_room.end()};
                REQUIRE(servers == std::set<std::string>{"local.example.org", "a.example.org", "b.example.org"});
            }
            AND_THEN("state keeps the room's non-membership events and only the heroes' membership events")
            {
                auto const state = described(result.state_json);
                REQUIRE(state.contains("m.room.create|"));
                REQUIRE(state.contains("m.room.power_levels|"));
                REQUIRE(state.contains("m.room.join_rules|"));
                // No name and no alias: the first five joined members other than bob are the heroes, the
                // admin and the first four seeded members, in roster order.
                REQUIRE(state.count("m.room.member|" + std::string{admin}) == 1U);
                for (auto index = 0; index < 4; ++index)
                {
                    REQUIRE(state.count("m.room.member|" + members[static_cast<std::size_t>(index)]) == 1U);
                }
                auto const member_events = std::ranges::count_if(state, [](std::string const& entry) {
                    return entry.starts_with("m.room.member|");
                });
                REQUIRE(member_events == 5);
                REQUIRE_FALSE(state.contains("m.room.member|" + std::string{bob}));
            }
            AND_THEN("auth_chain carries the join's own auth event that state leaves out, and nothing state holds")
            {
                auto const chain = described(result.auth_chain_json);
                // bob's invite is a membership event, so state omits it, but the join names it.
                REQUIRE(chain.contains("m.room.member|" + std::string{bob}));
                REQUIRE_FALSE(chain.contains("m.room.create|"));
                REQUIRE_FALSE(chain.contains("m.room.power_levels|"));
                REQUIRE_FALSE(chain.contains("m.room.join_rules|"));
                REQUIRE(std::ranges::none_of(result.state_json, [&](std::string const& json) {
                    return std::ranges::find(result.auth_chain_json, json) != result.auth_chain_json.end();
                }));
            }
        }

        std::filesystem::remove(path);
    }
}

// Without omit_members the answer is complete: every membership event is in `state`, and
// `members_omitted` is false.
SCENARIO("Without omit_members every membership event is in the answer and members_omitted is false",
         "[homeserver][send_join_answer][omit_members]")
{
    GIVEN("a public room with 8 members and the default limits")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto room = seed_room(runtime, "!few:local.example.org", R"({"join_rule":"public"})");
        for (auto index = 0; index < 8; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":a.example.org";
            seed_state_after(runtime, room, "$m" + std::to_string(index) + ":local.example.org", "m.room.member", user,
                             user, R"({"membership":"join"})");
            add_to_roster(runtime, room.room_id, user);
        }

        WHEN("bob joins without omit_members")
        {
            auto const result = accept(
                runtime, join_envelope(room, std::string{bob}, "$bobjoin:remote.example.org", public_join_auth(room)));

            THEN("state holds all nine membership events and members_omitted is false")
            {
                REQUIRE(result.accepted);
                REQUIRE_FALSE(result.members_omitted);
                REQUIRE(result.servers_in_room.empty());
                REQUIRE(described(result.state_json).count("m.room.member|@u3:a.example.org") == 1U);
                auto const member_events =
                    std::ranges::count_if(described(result.state_json), [](std::string const& entry) {
                        return entry.starts_with("m.room.member|");
                    });
                REQUIRE(member_events == 9);
            }
            AND_THEN("auth_chain repeats the state events, as this server has always answered")
            {
                REQUIRE(described(result.auth_chain_json).count("m.room.create|") == 1U);
                REQUIRE(described(result.auth_chain_json).count("m.room.power_levels|") == 1U);
            }
        }

        WHEN("bob joins asking for omit_members although the room is small enough that heroes cover its members")
        {
            auto small = seed_room(runtime, "!tiny:local.example.org", R"({"join_rule":"public"})");
            seed_state_after(runtime, small, "$tm:local.example.org", "m.room.member", "@t:a.example.org",
                             "@t:a.example.org", R"({"membership":"join"})");
            add_to_roster(runtime, small.room_id, "@t:a.example.org");
            auto const result = accept(runtime, join_envelope(small, std::string{bob}, "$tinyjoin:remote.example.org",
                                                              public_join_auth(small), true));

            THEN("no membership event was left out, so members_omitted is false")
            {
                REQUIRE(result.accepted);
                REQUIRE_FALSE(result.members_omitted);
            }
        }

        std::filesystem::remove(path);
    }
}

// The projection that decides a refusal must be an upper bound of the frame main really builds,
// where each event is a JSON string in an array (src/ipc/AGENTS.md).
SCENARIO("The projected answer size bounds the escaped size of the events it names",
         "[homeserver][send_join_answer][f23]")
{
    GIVEN("a room whose events are full of quotes and backslashes")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto room = seed_room(runtime, "!quotes:local.example.org", R"({"join_rule":"public"})");
        seed_state_after(
            runtime, room, "$q:local.example.org", "org.example.q", "", std::string{admin}, R"({"q":")" + [] {
                auto text = std::string{};
                for (auto index = 0; index < 4000; ++index)
                {
                    text += R"(\"\\)";
                }
                return text;
            }() + R"("})");
        auto& store = runtime.database.persistent_store;

        WHEN("the answer for a join is planned and collected")
        {
            auto const plan = merovingian::homeserver::plan_send_join_answer(
                runtime, room.room_id, bob, merovingian::homeserver::current_room_state_entries(store, room.room_id),
                public_join_auth(room), false);
            auto const events = merovingian::homeserver::collect_send_join_answer(store, room.room_id, plan);

            THEN("the projected frame is at least the size of every event as an escaped JSON string")
            {
                auto escaped = std::uint64_t{0U};
                auto raw = std::uint64_t{0U};
                for (auto const* list : {&events.state_json, &events.auth_chain_json})
                {
                    for (auto const& json : *list)
                    {
                        escaped += merovingian::ipc::ipc_json_str(json).size() + 1U;
                        raw += json.size() + 1U;
                    }
                }
                REQUIRE(plan.event_count == events.state_json.size() + events.auth_chain_json.size());
                REQUIRE(plan.projected_frame_bytes >= escaped);
                REQUIRE(plan.projected_body_bytes >= raw);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: PUT /send_join describes no re-send. A join stored already is the same event (its ID is the
// reference hash of its content), so answering it again is harmless and is what a server whose first
// answer was lost needs: the 500 it got before ("event persistence failed") never gave it the room.
SCENARIO("A join sent a second time is answered again, not refused", "[homeserver][send_join_answer][f23][resend]")
{
    GIVEN("a public room, an unstarted dispatch worker and a remote member, and bob's join already accepted")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        install_unstarted_dispatch_worker(runtime);
        auto room = seed_room(runtime, "!again:local.example.org", R"({"join_rule":"public"})");
        add_to_roster(runtime, room.room_id, std::string{carol});
        for (auto index = 0; index < 7; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":a.example.org";
            seed_state_after(runtime, room, "$m" + std::to_string(index) + ":local.example.org", "m.room.member", user,
                             user, R"({"membership":"join"})");
            add_to_roster(runtime, room.room_id, user);
        }
        auto& store = runtime.database.persistent_store;
        auto const join_id = std::string{"$bobjoin:remote.example.org"};
        auto const envelope = join_envelope(room, std::string{bob}, join_id, public_join_auth(room));
        auto const first = accept(runtime, envelope);
        REQUIRE(first.accepted);
        auto const ordering_after_first = runtime.database.next_stream_ordering;
        auto const queued_after_first = store.federation_transactions.size();

        WHEN("the same join is sent again")
        {
            auto const second = accept(runtime, envelope);

            THEN("it is answered 200 with the same state, the stored event and the room version")
            {
                REQUIRE(second.accepted);
                REQUIRE(second.status == 200U);
                REQUIRE(second.signed_event_json == first.signed_event_json);
                REQUIRE(described(second.state_json) == described(first.state_json));
                REQUIRE(described(second.auth_chain_json) == described(first.auth_chain_json));
                REQUIRE(second.room_version == "10");
            }
            AND_THEN("the answer is the state before the join, which the join is not in")
            {
                REQUIRE_FALSE(described(second.state_json).contains("m.room.member|" + std::string{bob}));
            }
            AND_THEN("nothing was stored or sent on a second time")
            {
                REQUIRE(event_count(runtime, join_id) == 1U);
                REQUIRE(runtime.database.next_stream_ordering == ordering_after_first);
                REQUIRE(store.federation_transactions.size() == queued_after_first);
            }
        }

        WHEN("the same join is sent again asking for omit_members")
        {
            auto resend = envelope;
            resend.omit_members = true;
            auto const second = accept(runtime, resend);

            THEN("the second answer honours the request")
            {
                REQUIRE(second.accepted);
                REQUIRE(second.members_omitted);
                REQUIRE(second.servers_in_room.size() >= 1U);
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("an invite-only room that refused bob's join on receipt")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room = seed_room(runtime, "!closed:local.example.org", R"({"join_rule":"invite"})");
        auto const envelope =
            join_envelope(room, std::string{bob}, "$bobjoin:remote.example.org", public_join_auth(room));
        auto const first = accept(runtime, envelope);
        REQUIRE_FALSE(first.accepted);
        REQUIRE(first.status == 403U);

        WHEN("the same join is sent again")
        {
            auto const second = accept(runtime, envelope);

            THEN("it is refused 403 again, not 500 and not accepted")
            {
                REQUIRE_FALSE(second.accepted);
                REQUIRE(second.status == 403U);
            }
        }

        std::filesystem::remove(path);
    }
}

// F-19. make_join builds its template from lookups by key and the room's own forward extremities:
// at most 20 prev_events (rooms/v11.md), never a rejected event, and the same template however many
// rooms the server holds.
SCENARIO("A make_join template is built from the room's own state and tips",
         "[homeserver][send_join_answer][f19][make_join]")
{
    GIVEN("a public room with 25 tips and a rejected event that names the real tip")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room = seed_room(runtime, "!tips:local.example.org", R"({"join_rule":"public"})");
        auto tips = std::set<std::string>{};
        for (auto index = 0; index < 25; ++index)
        {
            auto const id = "$tip" + std::to_string(index) + ":local.example.org";
            seed(runtime, room.room_id, id, "m.room.message", std::nullopt, std::string{admin}, R"({"body":"x"})",
                 {room.join_rules_id}, {room.create_id, room.pl_id, room.admin_member_id},
                 5U + static_cast<std::uint64_t>(index));
            tips.insert(id);
        }
        auto rejected = merovingian::database::PersistentEvent{};
        rejected.event_id = "$rejected:remote.example.org";
        rejected.room_id = room.room_id;
        rejected.sender_user_id = "@x:remote.example.org";
        rejected.json = "{}";
        rejected.depth = 900'000U;
        rejected.prev_event_ids = {"$tip0:local.example.org"};
        rejected.status = "rejected";
        runtime.database.persistent_store.events.push_back(rejected);
        auto const& provider = runtime.federation.membership_template_provider;
        REQUIRE(provider != nullptr);

        WHEN("bob's server asks for a join template")
        {
            auto const tmpl = provider(FederationEndpoint::make_join, room.room_id, bob, {});

            THEN("prev_events names at most 20 of the room's tips, never the rejected event")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->reason.empty());
                REQUIRE(tmpl->prev_events.size() == 20U);
                REQUIRE(std::ranges::all_of(tmpl->prev_events, [&](std::string const& id) {
                    return tips.contains(id);
                }));
            }
            AND_THEN("depth follows the events it was built on, not the rejected event's depth")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->depth < 100);
            }
            AND_THEN("auth_events names the create, join rules and power levels events")
            {
                REQUIRE(tmpl.has_value());
                auto const auth = std::set<std::string>{tmpl->auth_events.begin(), tmpl->auth_events.end()};
                REQUIRE(auth == std::set<std::string>{room.create_id, room.join_rules_id, room.pl_id});
            }
        }

        WHEN("thirty unrelated rooms are added and the template is asked for again")
        {
            auto const before = provider(FederationEndpoint::make_join, room.room_id, bob, {});
            for (auto index = 0; index < 30; ++index)
            {
                std::ignore = seed_room(runtime, "!other" + std::to_string(index) + ":local.example.org",
                                        R"({"join_rule":"public"})");
            }
            auto const after = provider(FederationEndpoint::make_join, room.room_id, bob, {});

            THEN("the template is the same: its auth_events and prev_events follow the room")
            {
                REQUIRE(before.has_value());
                REQUIRE(after.has_value());
                REQUIRE(after->auth_events == before->auth_events);
                REQUIRE(std::set<std::string>{after->prev_events.begin(), after->prev_events.end()} ==
                        std::set<std::string>{before->prev_events.begin(), before->prev_events.end()});
                REQUIRE(after->depth == before->depth);
            }
        }

        WHEN("a user who has an invite asks for a join template")
        {
            seed(runtime, room.room_id, "$bobinvite:local.example.org", "m.room.member", std::string{bob},
                 std::string{admin}, R"({"membership":"invite"})", {room.join_rules_id},
                 {room.create_id, room.pl_id, room.admin_member_id}, 9U);
            auto const tmpl = provider(FederationEndpoint::make_join, room.room_id, bob, {});

            THEN("the template's auth_events also names the user's own membership event")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(std::ranges::find(tmpl->auth_events, "$bobinvite:local.example.org") !=
                        tmpl->auth_events.end());
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("a room this server holds state for but no tips (ADR-0301: it left the room)")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const room = seed_room(runtime, "!left:local.example.org", R"({"join_rule":"public"})");
        std::erase_if(runtime.database.persistent_store.forward_extremities, [&](auto const& extremity) {
            return extremity.room_id == room.room_id;
        });

        WHEN("a join template is asked for")
        {
            auto const tmpl =
                runtime.federation.membership_template_provider(FederationEndpoint::make_join, room.room_id, bob, {});

            THEN("there is none: an empty prev_events would detach the join from the room's graph")
            {
                REQUIRE_FALSE(tmpl.has_value());
            }
        }

        std::filesystem::remove(path);
    }
}

namespace
{

// A hand-built store, for decide_restricted_join on its own. Rows are appended to `state` directly, so the
// state index is out of step and every lookup falls back to a scan that still visits only one room's rows.
struct StoreBuilder final
{
    merovingian::database::PersistentStore store{};
    std::size_t next{0U};

    auto state(std::string const& room_id, std::string const& type, std::string const& state_key,
               std::string const& content_json) -> std::string
    {
        auto const event_id = "$e" + std::to_string(++next) + ":test";
        auto event = merovingian::database::PersistentEvent{};
        event.event_id = event_id;
        event.room_id = room_id;
        event.json = R"({"content":)" + content_json + R"(,"room_id":")" + room_id + R"(","state_key":")" + state_key +
                     R"(","type":")" + type + R"("})";
        store.events.push_back(std::move(event));
        store.state.push_back({room_id, type, state_key, event_id});
        return event_id;
    }

    auto member(std::string const& room_id, std::string_view user, std::string_view membership) -> std::string
    {
        return state(room_id, "m.room.member", std::string{user},
                     std::string{R"({"membership":")"} + std::string{membership} + R"("})");
    }

    auto room(std::string const& room_id) -> void
    {
        std::ignore =
            state(room_id, "m.room.create", "", R"({"creator":"@admin:local.example.org","room_version":"10"})");
    }
};

// A v10 room "!r:local.example.org" allowing members of the rooms named in `allowed`, with the local admin
// joined at 100 and bob joined to every allowed room. `unrelated` other rooms of `rows` members each follow.
[[nodiscard]] auto restricted_store(std::vector<std::string> const& allowed, std::size_t unrelated, std::size_t rows)
    -> StoreBuilder
{
    auto builder = StoreBuilder{};
    builder.room("!r:local.example.org");
    std::ignore = builder.state("!r:local.example.org", "m.room.power_levels", "",
                                R"({"invite":50,"users":{"@admin:local.example.org":100}})");
    auto conditions = std::string{};
    for (auto const& room : allowed)
    {
        conditions += (conditions.empty() ? "" : ",") + std::string{R"({"room_id":")"} + room +
                      R"(","type":"m.room_membership"})";
    }
    std::ignore = builder.state("!r:local.example.org", "m.room.join_rules", "",
                                R"({"allow":[)" + conditions + R"(],"join_rule":"restricted"})");
    std::ignore = builder.member("!r:local.example.org", admin, "join");
    for (auto const& room : std::set<std::string>{allowed.begin(), allowed.end()})
    {
        builder.room(room);
        std::ignore = builder.member(room, admin, "join");
        std::ignore = builder.member(room, bob, "join");
    }
    for (auto index = std::size_t{0U}; index < unrelated; ++index)
    {
        auto const room = "!unrelated" + std::to_string(index) + ":local.example.org";
        builder.room(room);
        for (auto member = std::size_t{0U}; member < rows; ++member)
        {
            std::ignore = builder.member(room, "@u" + std::to_string(member) + ":local.example.org", "join");
        }
    }
    return builder;
}

} // namespace

// F-19. A make_join runs this for every request, under runtime.mutex: what it reads follows the room and the rooms its
// join rule names, never the rest of the server (src/homeserver/AGENTS.md, "Work under the runtime lock is bounded by
// the request"). Spec: server-server-api.md "Restricted rooms" and GET /make_join `join_authorised_via_users_server`.
SCENARIO("A restricted-join decision reads the rooms it names, not the server",
         "[homeserver][send_join_answer][f19][restricted_join]")
{
    GIVEN("a restricted room that allows one room, in a store with no other room")
    {
        auto const alone = restricted_store({"!a:local.example.org"}, 0U, 0U);
        auto const baseline =
            merovingian::homeserver::decide_restricted_join(alone.store, "!r:local.example.org", bob, our_server);

        WHEN("forty unrelated rooms of fifty members each are added and the same join is decided")
        {
            auto const crowded = restricted_store({"!a:local.example.org"}, 40U, 50U);
            auto const decision =
                merovingian::homeserver::decide_restricted_join(crowded.store, "!r:local.example.org", bob, our_server);

            THEN("the verdict and the authorising user are the same")
            {
                REQUIRE(baseline.verdict == merovingian::homeserver::RestrictedJoinVerdict::authorised);
                REQUIRE(decision.verdict == baseline.verdict);
                REQUIRE(decision.authorising_user == admin);
            }
            AND_THEN("it visited the same state rows and parsed the same events, a handful of each")
            {
                REQUIRE(decision.work.state_rows_visited == baseline.work.state_rows_visited);
                REQUIRE(decision.work.events_parsed == baseline.work.events_parsed);
                REQUIRE(decision.work.state_rows_visited <= 8U);
                REQUIRE(decision.work.events_parsed <= 8U);
            }
        }

        WHEN("the join rule names the same allowed room three times")
        {
            auto const repeated =
                restricted_store({"!a:local.example.org", "!a:local.example.org", "!a:local.example.org"}, 0U, 0U);
            auto const decision = merovingian::homeserver::decide_restricted_join(
                repeated.store, "!r:local.example.org", bob, our_server);

            THEN("the room is read once")
            {
                REQUIRE(decision.verdict == merovingian::homeserver::RestrictedJoinVerdict::authorised);
                REQUIRE(decision.work.state_rows_visited == baseline.work.state_rows_visited);
            }
        }

        WHEN("the join already names the local admin as its authoriser")
        {
            auto const decision = merovingian::homeserver::decide_restricted_join(alone.store, "!r:local.example.org",
                                                                                  bob, our_server, admin);

            THEN("it is authorised from one lookup, without walking the room's own members")
            {
                REQUIRE(decision.verdict == merovingian::homeserver::RestrictedJoinVerdict::authorised);
                REQUIRE(decision.authorising_user == admin);
                REQUIRE(decision.work.state_rows_visited < baseline.work.state_rows_visited);
            }
        }

        WHEN("the join names a user of another server as its authoriser")
        {
            auto const decision = merovingian::homeserver::decide_restricted_join(
                alone.store, "!r:local.example.org", bob, our_server, "@someone:remote.example.org");

            THEN("no local user can authorise it: M_UNABLE_TO_GRANT_JOIN")
            {
                REQUIRE(decision.verdict == merovingian::homeserver::RestrictedJoinVerdict::unable_to_grant);
            }
        }

        WHEN("the joining user is in none of the allowed rooms")
        {
            auto const decision =
                merovingian::homeserver::decide_restricted_join(alone.store, "!r:local.example.org", carol, our_server);

            THEN("every condition was checked and none held: 403 M_FORBIDDEN")
            {
                REQUIRE(decision.verdict == merovingian::homeserver::RestrictedJoinVerdict::forbidden);
            }
        }
    }
}

// Spec: PUT /send_join, `state`: "The resolved current room state prior to the join event";
// `servers_in_room`: "those with joined members ... before the join". The spec has no separate
// answer for a repeated request, so a server whose first answer was lost is owed the same thing.
SCENARIO("A join sent again after the room moved on is not answered with older state",
         "[homeserver][send_join_answer][f23][resend]")
{
    auto const holds_membership = [](std::vector<std::string> const& events, std::string const& membership) {
        auto const wanted = R"("membership":")" + membership + "\"";
        return std::ranges::any_of(events, [&wanted](std::string const& json) {
            return json.find(wanted) != std::string::npos;
        });
    };

    GIVEN("a join built on the room's tip, and then carol banned before the join arrives")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        install_unstarted_dispatch_worker(runtime);
        auto room = seed_room(runtime, "!moved:local.example.org", R"({"join_rule":"public"})");
        auto const carol_user = std::string{carol};
        seed_state_after(runtime, room, "$carol:local.example.org", "m.room.member", carol_user, carol_user,
                         R"({"membership":"join"})");
        add_to_roster(runtime, room.room_id, carol_user);
        for (auto index = 0; index < 7; ++index)
        {
            auto const user = "@u" + std::to_string(index) + ":a.example.org";
            seed_state_after(runtime, room, "$m" + std::to_string(index) + ":local.example.org", "m.room.member", user,
                             user, R"({"membership":"join"})");
            add_to_roster(runtime, room.room_id, user);
        }
        auto envelope = join_envelope(room, std::string{bob}, "$bobjoin:remote.example.org", public_join_auth(room));
        seed_state_after(runtime, room, "$ban:local.example.org", "m.room.member", carol_user, std::string{admin},
                         R"({"membership":"ban"})");

        WHEN("the join is accepted and sent again")
        {
            auto const first = accept(runtime, envelope);
            REQUIRE(first.accepted);
            auto const second = accept(runtime, envelope);

            THEN("the second answer holds the ban the first answer held, and is otherwise the same")
            {
                REQUIRE(holds_membership(first.state_json, "ban"));
                REQUIRE(second.accepted);
                REQUIRE(holds_membership(second.state_json, "ban"));
                REQUIRE(described(second.state_json) == described(first.state_json));
            }
            AND_THEN("the joiner's own join is not in the state before it")
            {
                REQUIRE_FALSE(described(second.state_json).contains("m.room.member|" + std::string{bob}));
            }
        }

        WHEN("the join asks for omit_members and is sent again")
        {
            envelope.omit_members = true;
            auto const first = accept(runtime, envelope);
            REQUIRE(first.accepted);
            REQUIRE(first.members_omitted);
            auto const second = accept(runtime, envelope);

            THEN("servers_in_room still lists only the servers joined before the join")
            {
                REQUIRE(second.accepted);
                REQUIRE(second.members_omitted);
                REQUIRE(std::ranges::find(first.servers_in_room, "remote.example.org") == first.servers_in_room.end());
                REQUIRE(second.servers_in_room == first.servers_in_room);
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("bob, who left the room, joining it again")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        install_unstarted_dispatch_worker(runtime);
        auto room = seed_room(runtime, "!back:local.example.org", R"({"join_rule":"public"})");
        auto const bob_user = std::string{bob};
        seed_state_after(runtime, room, "$bobleft:remote.example.org", "m.room.member", bob_user, bob_user,
                         R"({"membership":"leave"})");
        auto const envelope = join_envelope(room, bob_user, "$bobback:remote.example.org", public_join_auth(room));

        WHEN("the join is accepted and sent again")
        {
            auto const first = accept(runtime, envelope);
            REQUIRE(first.accepted);
            auto const second = accept(runtime, envelope);

            THEN("both answers give bob's membership as it was before the join")
            {
                REQUIRE(holds_membership(first.state_json, "leave"));
                REQUIRE(second.accepted);
                REQUIRE(holds_membership(second.state_json, "leave"));
                REQUIRE(described(second.state_json) == described(first.state_json));
            }
        }

        std::filesystem::remove(path);
    }

    GIVEN("bob banned after his join was built, so that his join does not change the room's state")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path, "64MiB"));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        install_unstarted_dispatch_worker(runtime);
        auto room = seed_room(runtime, "!barred:local.example.org", R"({"join_rule":"public"})");
        auto const bob_user = std::string{bob};
        auto const envelope = join_envelope(room, bob_user, "$bobjoin:remote.example.org", public_join_auth(room));
        seed_state_after(runtime, room, "$bobban:local.example.org", "m.room.member", bob_user, std::string{admin},
                         R"({"membership":"ban"})");

        WHEN("the join is answered and sent again")
        {
            auto const first = accept(runtime, envelope);
            auto const second = accept(runtime, envelope);

            THEN("the second answer does not lose his ban")
            {
                REQUIRE(second.accepted == first.accepted);
                REQUIRE(holds_membership(second.state_json, "ban") == holds_membership(first.state_json, "ban"));
            }
        }

        std::filesystem::remove(path);
    }
}
