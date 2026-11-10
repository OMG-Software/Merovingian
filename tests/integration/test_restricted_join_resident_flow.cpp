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

#include "../support/MasterKey.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/Parser.hpp"
#include "merovingian/canonicaljson/Serializer.hpp"
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
#include "merovingian/events/Authorization.hpp"
#include "merovingian/events/EventId.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/VerificationKeyResolution.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/federation/RemoteKeyCache.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RestrictedJoinVerdict.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/WorkerPool.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"
#include "merovingian/homeserver/RestrictedJoin.hpp"
#include "merovingian/homeserver/StateBookkeeping.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"
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

} // namespace

// --- a started runtime, for the make_join template and the send_join acceptor ----

namespace
{

[[nodiscard]] auto unique_sqlite_path() -> std::filesystem::path
{
    auto const now = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() / ("merovingian-restricted-join-" + std::to_string(now) + ".sqlite3");
}

[[nodiscard]] auto config_with_sqlite(std::filesystem::path const& path) -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::string{our_server};
    auto database = merovingian::config::DatabaseConfig{};
    database.backend = merovingian::config::DatabaseBackend::sqlite;
    database.sqlite_path = path.string();
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.federation.enabled = true;
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
    auto* policy = rooms::find_room_version_policy("10");
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
    std::string create_id{};
    std::string pl_id{};
    std::string admin_member_id{};
    std::string join_rules_id{};
};

// A v10 room on this server with the local admin joined at power 100.
[[nodiscard]] auto seed_room(HomeserverRuntime& runtime, std::string const& room_id,
                             std::string const& join_rules_content) -> SeededRoom
{
    auto const a = std::string{admin};
    runtime.database.persistent_store.rooms.push_back({room_id, a});
    runtime.database.rooms.push_back({room_id, a, {}, false});
    auto ids = SeededRoom{room_id + "/create", room_id + "/pl", room_id + "/admin", room_id + "/join_rules"};
    seed(runtime, room_id, ids.create_id, "m.room.create", std::string{}, a,
         R"({"creator":"@admin:local.example.org","room_version":"10"})", {}, {}, 1U);
    seed(runtime, room_id, ids.admin_member_id, "m.room.member", a, a, R"({"membership":"join"})", {ids.create_id},
         {ids.create_id}, 2U);
    seed(runtime, room_id, ids.pl_id, "m.room.power_levels", std::string{}, a,
         R"({"users":{"@admin:local.example.org":100}})", {ids.admin_member_id}, {ids.create_id, ids.admin_member_id},
         3U);
    seed(runtime, room_id, ids.join_rules_id, "m.room.join_rules", std::string{}, a, join_rules_content, {ids.pl_id},
         {ids.create_id, ids.pl_id, ids.admin_member_id}, 4U);
    return ids;
}

[[nodiscard]] auto envelope_for(std::string const& room_id, std::string const& event_id, std::string const& user,
                                std::vector<std::string> const& prev, std::vector<std::string> const& auth,
                                std::string const& json) -> InboundPduEnvelope
{
    auto envelope = InboundPduEnvelope{};
    envelope.event_id = event_id;
    envelope.room_id = room_id;
    envelope.room_version = "10";
    envelope.sender = user;
    envelope.event_type = "m.room.member";
    envelope.state_key = user;
    envelope.depth = 5U;
    envelope.prev_event_ids = prev;
    envelope.auth_event_ids = auth;
    envelope.json = json;
    return envelope;
}

[[nodiscard]] auto member_of(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

} // namespace

// Spec: server-server-api.md GET /make_join, 200 response, `join_authorised_via_users_server`:
// "Required if the room is restricted and is joining through one of the conditions available
// ... An arbitrary user ID belonging to the resident server in the room being joined that is
// able to issue invites to other users." "Restricted rooms": the resident refuses with 400
// M_UNABLE_TO_AUTHORISE_JOIN / M_UNABLE_TO_GRANT_JOIN or 403 M_FORBIDDEN.
// "Auth events selection": the join also names that user's m.room.member event.
SCENARIO("make_join for a restricted room names a local user who can invite, or refuses",
         "[homeserver][restricted_join][make_join][r04]")
{
    GIVEN("this server as the only resident of a restricted room, and bob joined to the allowed room")
    {
        // The server is the only resident, with bob joined to the allowed room, so its own users can authorise him.
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const allowed = seed_room(started.runtime, "!a:local.example.org", R"({"join_rule":"public"})");
        seed(started.runtime, "!a:local.example.org", "!a/bob", "m.room.member", std::string{bob}, std::string{bob},
             R"({"membership":"join"})", {allowed.join_rules_id},
             {allowed.create_id, allowed.pl_id, allowed.join_rules_id}, 5U);
        auto const room = seed_room(
            started.runtime, "!r:local.example.org",
            R"({"allow":[{"room_id":"!a:local.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
        auto const& provider = started.runtime.federation.membership_template_provider;
        REQUIRE(provider != nullptr);

        WHEN("bob's server asks for a join template")
        {
            auto const tmpl =
                provider(merovingian::federation::FederationEndpoint::make_join, "!r:local.example.org", bob, {});

            THEN("the template names the local admin and lists the admin's member event in auth_events")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->reason.empty());
                auto const content = merovingian::canonicaljson::parse_lossless(tmpl->content_json);
                REQUIRE(content.error == merovingian::canonicaljson::ParseError::none);
                auto const* object = std::get_if<merovingian::canonicaljson::Object>(&content.value.storage());
                REQUIRE(object != nullptr);
                auto const* authoriser = member_of(*object, "join_authorised_via_users_server");
                REQUIRE(authoriser != nullptr);
                REQUIRE(std::get<std::string>(authoriser->storage()) == admin);
                REQUIRE(std::ranges::find(tmpl->auth_events, room.admin_member_id) != tmpl->auth_events.end());
            }
        }

        WHEN("carol's server, whose user meets no condition, asks for a join template")
        {
            auto const tmpl =
                provider(merovingian::federation::FederationEndpoint::make_join, "!r:local.example.org", carol, {});

            THEN("the request is refused with 403 M_FORBIDDEN")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->error_status == 403U);
                REQUIRE(tmpl->reason.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        // The worker relays through the IPC frame handler; main must return the same decision it would for a local
        // call.
        WHEN("a federation worker relays bob's make_join to main")
        {
            auto const reply = merovingian::homeserver::handle_membership_template_ingest_request(
                started.runtime, merovingian::ipc::serialize_membership_template_ingest({
                                     "!r:local.example.org", std::string{bob},
                                      {"10", "11", "12"}
            }));
            auto const tmpl = merovingian::ipc::deserialize_membership_template_ingest_result(reply);

            THEN("main answers with the same template, naming the local admin")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->reason.empty());
                REQUIRE(tmpl->room_version == "10");
                REQUIRE(tmpl->content_json.find("join_authorised_via_users_server") != std::string::npos);
                REQUIRE(std::ranges::find(tmpl->auth_events, room.admin_member_id) != tmpl->auth_events.end());
            }
        }

        // Malformed relay frames are answered with no template rather than guessed at.
        WHEN("a worker relays a make_join frame without a user")
        {
            auto const reply = merovingian::homeserver::handle_membership_template_ingest_request(
                started.runtime, R"({"type":"membership_template_ingest","room_id":"!r:local.example.org"})");

            THEN("main answers with no template")
            {
                REQUIRE_FALSE(merovingian::ipc::deserialize_membership_template_ingest_result(reply).has_value());
            }
        }

        // make_join is how another server's user joins, so a frame naming a local user is refused.
        WHEN("a worker relays a make_join frame naming a user of this server, or a malformed user ID")
        {
            auto const local = merovingian::homeserver::handle_membership_template_ingest_request(
                started.runtime, merovingian::ipc::serialize_membership_template_ingest(
                                     {"!r:local.example.org", "@someone:local.example.org", {}}));
            auto const malformed = merovingian::homeserver::handle_membership_template_ingest_request(
                started.runtime,
                merovingian::ipc::serialize_membership_template_ingest({"!r:local.example.org", "bob", {}}));

            THEN("main answers with no template: make_join is how another server's user joins")
            {
                REQUIRE_FALSE(merovingian::ipc::deserialize_membership_template_ingest_result(local).has_value());
                REQUIRE_FALSE(merovingian::ipc::deserialize_membership_template_ingest_result(malformed).has_value());
            }
        }

        WHEN("a worker relays carol's make_join to main")
        {
            auto const reply = merovingian::homeserver::handle_membership_template_ingest_request(
                started.runtime, merovingian::ipc::serialize_membership_template_ingest(
                                     {"!r:local.example.org", std::string{carol}, {}}));
            auto const tmpl = merovingian::ipc::deserialize_membership_template_ingest_result(reply);

            THEN("the refusal and its status survive the relay")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->error_status == 403U);
                REQUIRE(tmpl->reason.find("M_FORBIDDEN") != std::string::npos);
            }
        }

        // With no state for the allowed room no condition can be checked, so the request fails closed.
        WHEN("a template is asked for in a restricted room whose allowed room this server does not know")
        {
            std::ignore = seed_room(
                started.runtime, "!u:local.example.org",
                R"({"allow":[{"room_id":"!x:elsewhere.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
            auto const tmpl =
                provider(merovingian::federation::FederationEndpoint::make_join, "!u:local.example.org", bob, {});

            THEN("the request is refused with 400 M_UNABLE_TO_AUTHORISE_JOIN")
            {
                REQUIRE(tmpl.has_value());
                REQUIRE(tmpl->error_status == 400U);
                REQUIRE(tmpl->reason.find("M_UNABLE_TO_AUTHORISE_JOIN") != std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: server-server-api.md PUT /send_join, `join_authorised_via_users_server`: "The
// resident server which owns the provided user ID must have a valid signature on the event.
// If the resident server is receiving the /send_join request, the signature must be added
// before sending or persisting the event to other servers." rooms/v10.md 4.2.1: "If the event
// is not validly signed by the homeserver of the user ID denoted by the key, reject."
SCENARIO("send_join co-signs a restricted join this server authorises, and refuses one it does not",
         "[homeserver][restricted_join][send_join][r04]")
{
    GIVEN("this server as the only resident of a restricted room, and bob joined to the allowed room")
    {
        // Same fixture as make_join: the only resident, with bob joined to the allowed room.
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const allowed = seed_room(started.runtime, "!a:local.example.org", R"({"join_rule":"public"})");
        seed(started.runtime, "!a:local.example.org", "!a/bob", "m.room.member", std::string{bob}, std::string{bob},
             R"({"membership":"join"})", {allowed.join_rules_id},
             {allowed.create_id, allowed.pl_id, allowed.join_rules_id}, 5U);
        auto const room = seed_room(
            started.runtime, "!r:local.example.org",
            R"({"allow":[{"room_id":"!a:local.example.org","type":"m.room_membership"}],"join_rule":"restricted"})");
        auto const auth =
            std::vector<std::string>{room.create_id, room.pl_id, room.join_rules_id, room.admin_member_id};
        // join_by builds a member join event, signed only by the joining user's server, as a remote server would submit
        // it.
        auto const join_by = [&](std::string_view user, std::string const& event_id) {
            auto const json = event_json("!r:local.example.org", "m.room.member", std::string{user}, std::string{user},
                                         R"({"join_authorised_via_users_server":"@admin:local.example.org",)"
                                         R"("membership":"join"})",
                                         {room.join_rules_id}, auth, 5);
            return envelope_for("!r:local.example.org", event_id, std::string{user}, {room.join_rules_id}, auth, json);
        };
        auto const stored = [&](std::string const& event_id) {
            auto const& events = started.runtime.database.persistent_store.events;
            return std::ranges::find_if(events, [&](auto const& event) {
                return event.event_id == event_id;
            });
        };

        // The resident must add its own signature for the authorising user, since the spec requires the event to carry
        // it.
        WHEN("bob's join, naming the local admin and signed only by bob's server, is submitted")
        {
            auto const envelope = join_by(bob, "$bobjoin:remote.example.org");
            auto const result =
                started.runtime.federation.membership_acceptor(merovingian::federation::FederationEndpoint::send_join,
                                                               "!r:local.example.org", envelope.event_id, envelope);

            THEN("it is accepted, and the stored and returned event carry this server's valid signature")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
                auto const event = stored(envelope.event_id);
                REQUIRE(event != started.runtime.database.persistent_store.events.end());
                REQUIRE(event->status == "accepted");
                REQUIRE(event->json == result.signed_event_json);
                auto const parsed = merovingian::canonicaljson::parse_lossless(result.signed_event_json);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* policy = merovingian::rooms::find_room_version_policy("10");
                REQUIRE(policy != nullptr);
                auto& store = started.runtime.database.persistent_store;
                auto const verified = merovingian::federation::verify_join_authorising_server_signature(
                    parsed.value, *policy, [&store](std::string_view server_name, std::string_view key_id) {
                        return merovingian::federation::VerificationKeyResolution{
                            merovingian::federation::find_own_server_signing_key(store, server_name, key_id)};
                    });
                REQUIRE(verified.accepted);
            }

            THEN("bob is joined")
            {
                REQUIRE(result.accepted);
                auto const& memberships = started.runtime.database.persistent_store.memberships;
                REQUIRE(std::ranges::any_of(memberships, [](auto const& membership) {
                    return membership.room_id == "!r:local.example.org" && membership.user_id == bob &&
                           membership.membership == "join";
                }));
            }
        }

        // A signature already present under this server name must not be trusted or kept; only the one added here
        // counts.
        WHEN("bob's join also carries a signature planted under this server's name")
        {
            namespace cj = merovingian::canonicaljson;
            auto envelope = join_by(bob, "$bobplanted:remote.example.org");
            auto const parsed = cj::parse_lossless(envelope.json);
            REQUIRE(parsed.error == cj::ParseError::none);
            auto const* object = std::get_if<cj::Object>(&parsed.value.storage());
            REQUIRE(object != nullptr);
            auto with_planted = cj::Object{};
            for (auto const& member : *object)
            {
                with_planted.push_back(cj::make_member(member.key, *member.value));
            }
            auto planted = cj::Object{};
            planted.push_back(cj::make_member("ed25519:planted", cj::Value{std::string(86U, 'A')}));
            auto signatures = cj::Object{};
            signatures.push_back(cj::make_member(std::string{our_server}, cj::Value{std::move(planted)}));
            with_planted.push_back(cj::make_member("signatures", cj::Value{std::move(signatures)}));
            auto const serialized = cj::serialize_canonical(cj::Value{std::move(with_planted)});
            REQUIRE(serialized.error == cj::CanonicalJsonError::none);
            envelope.json = serialized.output;
            auto const result =
                started.runtime.federation.membership_acceptor(merovingian::federation::FederationEndpoint::send_join,
                                                               "!r:local.example.org", envelope.event_id, envelope);

            THEN("the event it stores and returns carries only the signature this server added under its name")
            {
                REQUIRE(result.accepted);
                auto const signed_event = cj::parse_lossless(result.signed_event_json);
                REQUIRE(signed_event.error == cj::ParseError::none);
                auto const* root = std::get_if<cj::Object>(&signed_event.value.storage());
                REQUIRE(root != nullptr);
                auto const* all = member_of(*root, "signatures");
                REQUIRE(all != nullptr);
                auto const* by_server = std::get_if<cj::Object>(&all->storage());
                REQUIRE(by_server != nullptr);
                auto const* ours = member_of(*by_server, our_server);
                REQUIRE(ours != nullptr);
                auto const* our_keys = std::get_if<cj::Object>(&ours->storage());
                REQUIRE(our_keys != nullptr);
                REQUIRE(our_keys->size() == 1U);
                REQUIRE(member_of(*our_keys, "ed25519:planted") == nullptr);
            }
        }

        // Naming an authorising user does not help a user who meets no condition.
        WHEN("carol's join, naming the local admin although she meets no condition, is submitted")
        {
            auto const envelope = join_by(carol, "$caroljoin:remote.example.org");
            auto const result =
                started.runtime.federation.membership_acceptor(merovingian::federation::FederationEndpoint::send_join,
                                                               "!r:local.example.org", envelope.event_id, envelope);

            THEN("it is refused with 403 M_FORBIDDEN, unsigned and not stored")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                REQUIRE(result.reason.find("M_FORBIDDEN") != std::string::npos);
                REQUIRE(stored(envelope.event_id) == started.runtime.database.persistent_store.events.end());
            }
        }

        // This server must not co-sign events that need no authorisation, or it would vouch for joins it did not
        // decide.
        WHEN("a join naming the local admin is submitted into a public room, where no authorisation is needed")
        {
            auto const open = seed_room(started.runtime, "!p:local.example.org", R"({"join_rule":"public"})");
            auto const open_auth = std::vector<std::string>{open.create_id, open.pl_id, open.join_rules_id};
            auto const json =
                event_json("!p:local.example.org", "m.room.member", std::string{carol}, std::string{carol},
                           R"({"join_authorised_via_users_server":"@admin:local.example.org",)"
                           R"("membership":"join"})",
                           {open.join_rules_id}, open_auth, 5);
            auto const envelope = envelope_for("!p:local.example.org", "$openjoin:remote.example.org",
                                               std::string{carol}, {open.join_rules_id}, open_auth, json);
            auto const result =
                started.runtime.federation.membership_acceptor(merovingian::federation::FederationEndpoint::send_join,
                                                               "!p:local.example.org", envelope.event_id, envelope);

            THEN("this server does not lend its signature to it")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                REQUIRE(stored(envelope.event_id) == started.runtime.database.persistent_store.events.end());
            }
        }

        std::filesystem::remove(path);
    }
}
