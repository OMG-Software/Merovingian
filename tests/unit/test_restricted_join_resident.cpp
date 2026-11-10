// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Audit R04 (conformance audit 2026-10-17, wave 2; ADR-0185): this server as the
// resident of a restricted room. It decides whether a joining user meets an allow
// condition, names one of its own users in the make_join template, and co-signs the
// join it receives through send_join.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Restricted rooms",
// GET /make_join, PUT /send_join; docs/matrix-v1.19-spec/client-server-api.md —
// "Restricted rooms"; docs/matrix-v1.19-spec/rooms/v10.md — auth rules 4.2.1 and
// 4.3.5.

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
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/VerificationKeyResolution.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerPool.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/restricted_join.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/ipc/federation_ipc_frames.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <variant>
#include <vector>

namespace
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;
using merovingian::homeserver::RestrictedJoinVerdict;

auto constexpr our_server = std::string_view{"local.example.org"};
auto constexpr admin = std::string_view{"@admin:local.example.org"};
auto constexpr bob = std::string_view{"@bob:remote.example.org"};
auto constexpr carol = std::string_view{"@carol:remote.example.org"};

// --- a hand-built store, for decide_restricted_join on its own --------------

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
        std::erase_if(store.state, [&](merovingian::database::PersistentStateEvent const& row) {
            return row.room_id == room_id && row.event_type == type && row.state_key == state_key;
        });
        store.state.push_back({room_id, type, state_key, event_id});
        return event_id;
    }

    auto member(std::string const& room_id, std::string_view user, std::string_view membership) -> std::string
    {
        return state(room_id, "m.room.member", std::string{user},
                     std::string{R"({"membership":")"} + std::string{membership} + R"("})");
    }

    auto room(std::string const& room_id, std::string const& version) -> void
    {
        std::ignore =
            state(room_id, "m.room.create", "",
                  std::string{R"({"creator":"@admin:local.example.org","room_version":")"} + version + R"("})");
    }
};

// A v10 restricted room "!r:local.example.org" allowing members of "!a:local.example.org",
// with the local admin joined at 100 and an invite level of 50. Bob is joined to the
// allowed room; carol is not. The admin is joined to the allowed room too, so this server
// is resident there and its state for that room is current.
[[nodiscard]] auto restricted_room_store() -> StoreBuilder
{
    auto builder = StoreBuilder{};
    builder.room("!r:local.example.org", "10");
    std::ignore = builder.state("!r:local.example.org", "m.room.power_levels", "",
                                R"({"invite":50,"users":{"@admin:local.example.org":100}})");
    std::ignore = builder.state(
        "!r:local.example.org", "m.room.join_rules", "",
        R"({"allow":[{"room_id":"!a:local.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
    std::ignore = builder.member("!r:local.example.org", admin, "join");
    builder.room("!a:local.example.org", "10");
    std::ignore = builder.member("!a:local.example.org", admin, "join");
    std::ignore = builder.member("!a:local.example.org", bob, "join");
    return builder;
}

} // namespace

// Spec: client-server-api.md "Restricted rooms" — "When joining without an invite, the
// server MUST verify that the requesting user meets at least one of the conditions. If no
// conditions can be verified or no conditions are satisfied, the user will not be able to
// join." server-server-api.md "Restricted rooms" — 400 M_UNABLE_TO_AUTHORISE_JOIN, 400
// M_UNABLE_TO_GRANT_JOIN, 403 M_FORBIDDEN. rooms/v10.md 4.3.5.2: the authorising user must
// be "a user with sufficient permission to invite other users" and "a joined member".
SCENARIO("A resident decides a restricted join from the allow conditions and its own users",
         "[homeserver][restricted_join][r04]")
{
    GIVEN("a restricted room, an allowed room bob is joined to, and a local admin who can invite")
    {
        auto builder = restricted_room_store();
        // decide runs the resident decision for one user, optionally with the authorising user the joining server
        // named.
        auto const decide = [&](std::string_view user, std::string_view named = {}) {
            return merovingian::homeserver::decide_restricted_join(builder.store, "!r:local.example.org", user,
                                                                   our_server, named);
        };

        WHEN("bob, who meets the condition, asks to join")
        {
            auto const decision = decide(bob);

            THEN("the join is authorised by the local admin, with the admin's member event named")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::authorised);
                REQUIRE(decision.authorising_user == admin);
                auto const member_row = std::ranges::find_if(builder.store.state, [](auto const& row) {
                    return row.room_id == "!r:local.example.org" && row.event_type == "m.room.member" &&
                           row.state_key == admin;
                });
                REQUIRE(member_row != builder.store.state.end());
                REQUIRE(decision.authorising_member_event_id == member_row->event_id);
            }
        }

        WHEN("carol, who is not joined to the allowed room, asks to join")
        {
            auto const decision = decide(carol);

            THEN("she fails every condition: 403 M_FORBIDDEN")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::forbidden);
                REQUIRE(merovingian::homeserver::restricted_join_refusal_status(decision.verdict) == 403U);
                REQUIRE(merovingian::homeserver::restricted_join_refusal_errcode(decision.verdict) == "M_FORBIDDEN");
            }
        }

        WHEN("carol is invited")
        {
            std::ignore = builder.member("!r:local.example.org", carol, "invite");
            auto const decision = decide(carol);

            THEN("the restrictions do not affect her")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::already_permitted);
            }
        }

        // A ban outranks every condition, so the restricted-room logic must never reach it.
        WHEN("bob is banned")
        {
            std::ignore = builder.member("!r:local.example.org", bob, "ban");
            auto const decision = decide(bob);

            THEN("he is refused, whatever the conditions say")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::forbidden);
            }
        }

        WHEN("the only allowed room is one this server holds no state for")
        {
            std::ignore = builder.state(
                "!r:local.example.org", "m.room.join_rules", "",
                R"({"allow":[{"room_id":"!unknown:elsewhere.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
            auto const decision = decide(bob);

            THEN("no condition can be validated: 400 M_UNABLE_TO_AUTHORISE_JOIN")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::unable_to_authorise);
                REQUIRE(merovingian::homeserver::restricted_join_refusal_status(decision.verdict) == 400U);
                REQUIRE(merovingian::homeserver::restricted_join_refusal_errcode(decision.verdict) ==
                        "M_UNABLE_TO_AUTHORISE_JOIN");
            }
        }

        WHEN("this server has left the allowed room, whose stale state still shows bob joined")
        {
            std::ignore = builder.member("!a:local.example.org", admin, "leave");
            auto const decision = decide(bob);

            THEN("the condition cannot be validated from current state: 400 M_UNABLE_TO_AUTHORISE_JOIN")
            {
                // server-server-api.md "Restricted rooms": the resident "does not have state
                // information about rooms required by the conditions".
                REQUIRE(decision.verdict == RestrictedJoinVerdict::unable_to_authorise);
            }
        }

        // Conditions the server cannot parse count as unmet, never as satisfied.
        WHEN("no condition matches the required schema")
        {
            std::ignore = builder.state("!r:local.example.org", "m.room.join_rules", "",
                                        R"({"allow":[{"type":"m.room_membership"},{"room_id":"!a:local.example.org",)"
                                        R"("type":"org.example.other"}],"join_rule":"restricted"})");
            auto const decision = decide(bob);

            THEN("the user is considered to have failed all conditions")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::forbidden);
            }
        }

        // The bound caps the work an attacker-chosen join_rule can cost; the condition beyond it is ignored.
        WHEN("the condition bob meets is listed past the bound on considered conditions")
        {
            auto allow = std::string{};
            for (auto i = std::size_t{0U}; i < merovingian::homeserver::max_restricted_join_conditions; ++i)
            {
                builder.room("!filler" + std::to_string(i) + ":local.example.org", "10");
                std::ignore = builder.member("!filler" + std::to_string(i) + ":local.example.org", admin, "join");
                allow += R"({"room_id":"!filler)" + std::to_string(i) +
                         R"(:local.example.org","type":"m.room_membership"},)";
            }
            allow += R"({"room_id":"!a:local.example.org","type":"m.room_membership"})";
            std::ignore = builder.state("!r:local.example.org", "m.room.join_rules", "",
                                        R"({"allow":[)" + allow + R"(],"join_rule":"restricted"})");
            auto const decision = decide(bob);

            THEN("it is not considered, and the join fails closed")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::forbidden);
            }
        }

        // Meeting a condition is not enough: someone local must also be able to invite and so authorise the join.
        WHEN("the only local member lacks the invite power level")
        {
            std::ignore = builder.state("!r:local.example.org", "m.room.power_levels", "",
                                        R"({"invite":50,"users":{"@admin:local.example.org":10}})");
            auto const decision = decide(bob);

            THEN("the condition holds but no local user can authorise: 400 M_UNABLE_TO_GRANT_JOIN")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::unable_to_grant);
                REQUIRE(merovingian::homeserver::restricted_join_refusal_errcode(decision.verdict) ==
                        "M_UNABLE_TO_GRANT_JOIN");
            }
        }

        WHEN("the local admin has left the room")
        {
            std::ignore = builder.member("!r:local.example.org", admin, "leave");
            auto const decision = decide(bob);

            THEN("no joined local user remains to authorise the join")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::unable_to_grant);
            }
        }

        // The authorising user comes from the joining server, so it is validated against local state rather than
        // trusted.
        WHEN("a submitted join names a local user who is not a member, or a remote user")
        {
            auto const not_member = decide(bob, "@nobody:local.example.org");
            auto const remote = decide(bob, "@admin:remote.example.org");

            THEN("neither can authorise it")
            {
                REQUIRE(not_member.verdict == RestrictedJoinVerdict::unable_to_grant);
                REQUIRE(remote.verdict == RestrictedJoinVerdict::unable_to_grant);
            }
        }

        WHEN("the room's join rule is public")
        {
            std::ignore = builder.state("!r:local.example.org", "m.room.join_rules", "", R"({"join_rule":"public"})");
            auto const decision = decide(carol);

            THEN("join_authorised_via_users_server plays no part")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::not_restricted);
            }
        }
    }

    GIVEN("a room of version 7, which defines no restricted join rule")
    {
        auto builder = StoreBuilder{};
        builder.room("!old:local.example.org", "7");
        std::ignore = builder.state(
            "!old:local.example.org", "m.room.join_rules", "",
            R"({"allow":[{"room_id":"!a:local.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
        std::ignore = builder.member("!old:local.example.org", admin, "join");

        WHEN("a join is decided")
        {
            auto const decision = merovingian::homeserver::decide_restricted_join(
                builder.store, "!old:local.example.org", bob, our_server);

            THEN("the room is not treated as restricted")
            {
                REQUIRE(decision.verdict == RestrictedJoinVerdict::not_restricted);
            }
        }
    }
}

// Spec: server-server-api.md "Restricted rooms" — "The resident server uses a 400
// `M_UNABLE_TO_GRANT_JOIN` error on `/make_join` and `/send_join` to denote that the
// joining server should try a different server." ADR-0287: a resident whose own users cannot
// authorise a local user's join (the same case, seen from the joining side) tries another
// resident through the federated join handshake, among a small bounded list of servers.
SCENARIO("A resident that cannot authorise a local join picks other resident servers in a bounded order",
         "[homeserver][restricted_join][fallback][adr-0287]")
{
    GIVEN("a client that names two servers and a room with three more servers holding joined members")
    {
        auto const via = std::vector<std::string>{"via1.example.org", "local.example.org", "via2.example.org"};
        auto const residents =
            std::vector<std::string>{"via2.example.org", "res1.example.org", "res2.example.org", "res3.example.org"};

        WHEN("the candidates are chosen with room for them all")
        {
            auto const candidates =
                merovingian::homeserver::restricted_join_fallback_candidates(via, residents, our_server, 10U);

            THEN("the named servers come first, then the other residents, each once and never this server")
            {
                REQUIRE(candidates == std::vector<std::string>{"via1.example.org", "via2.example.org",
                                                               "res1.example.org", "res2.example.org",
                                                               "res3.example.org"});
            }
        }

        WHEN("the candidates are chosen with a bound of three")
        {
            auto const candidates =
                merovingian::homeserver::restricted_join_fallback_candidates(via, residents, our_server, 3U);

            THEN("only the first three are kept, so the named servers are never cut for a resident")
            {
                REQUIRE(candidates ==
                        std::vector<std::string>{"via1.example.org", "via2.example.org", "res1.example.org"});
            }
        }

        WHEN("the client names no server and this server is the room's only resident")
        {
            auto const candidates = merovingian::homeserver::restricted_join_fallback_candidates(
                {}, {std::string{our_server}, std::string{}}, our_server, 4U);

            THEN("there is no candidate to try")
            {
                REQUIRE(candidates.empty());
            }
        }

        WHEN("the fixed bound is looked at")
        {
            THEN("it is small, so a room with many servers costs a bounded number of make_join calls")
            {
                REQUIRE(merovingian::homeserver::max_restricted_join_fallback_candidates >= 1U);
                REQUIRE(merovingian::homeserver::max_restricted_join_fallback_candidates <= 8U);
            }
        }
    }
}
