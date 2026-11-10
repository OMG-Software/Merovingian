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
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/MembershipAcceptResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/restricted_join.hpp"
#include "merovingian/homeserver/send_join_answer.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

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
{using merovingian::federation::FederationEndpoint;
using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;

auto constexpr our_server = std::string_view{"local.example.org"};
auto constexpr admin = std::string_view{"@admin:local.example.org"};
auto constexpr bob = std::string_view{"@bob:remote.example.org"};
auto constexpr carol = std::string_view{"@carol:other.example.org"};

} // namespace

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
