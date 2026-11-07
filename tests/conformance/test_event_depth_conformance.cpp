// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/remote_room_fixture.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <string>
#include <tuple>
#include <vector>

namespace
{

// The largest integer canonical JSON can carry (2^53 - 1).
constexpr auto depth_limit = std::int64_t{9007199254740991LL};

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct AliceRoom final
{
    std::string alice_token{};
    std::string room_id{};
};

[[nodiscard]] auto make_alice_room(merovingian::homeserver::HomeserverRuntime& runtime) -> AliceRoom
{
    auto const reg = merovingian::homeserver::register_local_user(runtime, "alice", "CorrectHorse7!",
                                                                  merovingian::tests::registration_token);
    REQUIRE(reg.ok);
    auto const login = merovingian::homeserver::login_local_user(runtime, reg.value, "CorrectHorse7!", "DEVICE1");
    REQUIRE(login.ok);
    auto const room = merovingian::homeserver::create_room(runtime, login.value);
    REQUIRE(room.ok);
    return {login.value, room.value};
}

[[nodiscard]] auto make_message_pdu(std::string const& room_id, std::string const& event_id, std::string const& sender,
                                    std::vector<std::string> const& prev_event_ids,
                                    std::vector<std::string> const& auth_event_ids, std::int64_t depth)
    -> merovingian::federation::InboundPduEnvelope
{
    using namespace merovingian;

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{sender}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{canonicaljson::Object{}}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{std::int64_t{5000}}));
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

    auto env = federation::InboundPduEnvelope{};
    env.event_id = event_id;
    env.room_id = room_id;
    env.room_version = "12";
    env.sender = sender;
    env.event_type = "m.room.message";
    env.origin_server_ts = 5000;
    env.depth = static_cast<std::uint64_t>(depth);
    env.prev_event_ids = prev_event_ids;
    env.auth_event_ids = auth_event_ids;
    env.json = serialized.output;
    return env;
}

[[nodiscard]] auto alice_auth_event_ids(merovingian::homeserver::HomeserverRuntime const& runtime,
                                        std::string const& room_id) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    for (auto const& state : runtime.database.persistent_store.state)
    {
        if (state.room_id == room_id &&
            ((state.event_type == "m.room.power_levels" && state.state_key.empty()) ||
             (state.event_type == "m.room.member" && state.state_key == "@alice:example.org")))
        {
            ids.push_back(state.event_id);
        }
    }
    return ids;
}

[[nodiscard]] auto stored_depth(merovingian::homeserver::HomeserverRuntime const& runtime, std::string const& event_id)
    -> std::uint64_t
{
    auto const stored = runtime.database.persistent_store.events.find(event_id);
    REQUIRE(stored != runtime.database.persistent_store.events.end());
    return stored->depth;
}

} // namespace

// Spec: Matrix Room Version 11 (the PDU format of rooms v4 and later)
// Section: Event format, `depth`
// URL: ../../docs/matrix-v1.19-spec/rooms/v11.md
//
// "The maximum depth of the prev_events, plus one. Must be less than the maximum value for an
// integer (2^53 - 1). If the room's depth is already at the limit, the depth must be set to the
// limit."
SCENARIO("A locally composed event's depth comes from its prev_events and stops at the limit",
         "[conformance][federation][depth][event-format]")
{
    GIVEN("a room with a local member")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);
        auto constexpr message = R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"hi"}})";

        WHEN("a local event is sent")
        {
            auto const tips = merovingian::homeserver::forward_extremities_for_new_event(
                runtime.database.persistent_store, ctx.room_id);
            // Fixture: one forward extremity, so this event has a single prev_event to take its depth from.
            REQUIRE(tips.size() == 1U);
            auto const tip_depth = stored_depth(runtime, tips.front());

            auto const sent = merovingian::homeserver::send_event(runtime, ctx.alice_token, ctx.room_id, message);
            // Spec MUST: `depth` is required on every PDU, so the send has to produce one.
            REQUIRE(sent.ok);

            THEN("its depth is the depth of its prev_event plus one")
            {
                // Spec MUST: "The maximum depth of the prev_events, plus one."
                REQUIRE(stored_depth(runtime, sent.value) == tip_depth + 1U);
            }
        }

        WHEN("a joined server's accepted event is at the limit and local events follow it")
        {
            auto const tips = merovingian::homeserver::forward_extremities_for_new_event(
                runtime.database.persistent_store, ctx.room_id);
            auto const at_limit = make_message_pdu(ctx.room_id, "$at-limit:example.org", "@alice:example.org", tips,
                                                   alice_auth_event_ids(runtime, ctx.room_id), depth_limit);
            auto const ingested = merovingian::homeserver::ingest_pdu_event(runtime, at_limit);
            // Spec MUST: 2^53 - 1 is a valid depth, the limit a room’s depth can reach.
            REQUIRE(ingested.status == merovingian::federation::PduIngestionStatus::accepted);

            auto const first = merovingian::homeserver::send_event(runtime, ctx.alice_token, ctx.room_id, message);
            auto const second = merovingian::homeserver::send_event(runtime, ctx.alice_token, ctx.room_id, message);

            THEN("each is stored at the limit and none goes above it")
            {
                // Spec MUST: "If the room’s depth is already at the limit, the depth must be set to the limit."
                REQUIRE(first.ok);
                // Spec MUST: "If the room’s depth is already at the limit, the depth must be set to the limit."
                REQUIRE(second.ok);
                // Spec MUST: "If the room's depth is already at the limit, the depth must be set to the limit."
                REQUIRE(stored_depth(runtime, first.value) == static_cast<std::uint64_t>(depth_limit));
                REQUIRE(stored_depth(runtime, second.value) == static_cast<std::uint64_t>(depth_limit));
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Section: Rejection
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#rejection
//
// "If an event is rejected it should neither be relayed to clients nor be included as a prev event
// in any new events generated by the server." A rejected event is not a prev event, so its depth
// says nothing about the depth of a local event. Before this was enforced, one signed PDU from any
// server (no membership, no event IDs from the room) stopped every local event in the room.
SCENARIO("A rejected PDU claiming the largest depth does not affect local events in the room",
         "[conformance][federation][depth][rejection]")
{
    GIVEN("a room with a local member and a rejected PDU from a stranger at depth 2^53 - 1")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);
        auto const tips =
            merovingian::homeserver::forward_extremities_for_new_event(runtime.database.persistent_store, ctx.room_id);
        // Fixture: one forward extremity, the tip the local events below must build on.
        REQUIRE(tips.size() == 1U);
        auto const tip_depth = stored_depth(runtime, tips.front());

        auto const hostile =
            make_message_pdu(ctx.room_id, "$hostile:evil.example", "@mallory:evil.example", {}, {}, depth_limit);
        std::ignore = merovingian::homeserver::ingest_pdu_event(runtime, hostile);
        auto const rejected = runtime.database.persistent_store.events.find("$hostile:evil.example");
        // Fixture: the event reached this server, so a later check on it means something.
        REQUIRE(rejected != runtime.database.persistent_store.events.end());
        // Spec MUST: an event that fails the authorisation rules "is rejected"; the sender is not in the room.
        REQUIRE(rejected->status == "rejected");

        WHEN("a local user sends a message, then sets the room's topic")
        {
            auto const sent = merovingian::homeserver::send_event(
                runtime, ctx.alice_token, ctx.room_id,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"still here"}})");
            auto const topic = merovingian::homeserver::send_event(
                runtime, ctx.alice_token, ctx.room_id,
                R"({"type":"m.room.topic","state_key":"","content":{"topic":"t"}})");

            THEN("both are stored, built on the room's real tip and not on the rejected event")
            {
                // Spec SHOULD: a rejected event is not "included as a prev event", so it cannot stop a local send.
                REQUIRE(sent.ok);
                // Spec SHOULD: a rejected event is not "included as a prev event", so it cannot stop a local send.
                REQUIRE(topic.ok);
                // Spec MUST: "The maximum depth of the `prev_events`, plus one"; a rejected event is not one of them.
                REQUIRE(stored_depth(runtime, sent.value) == tip_depth + 1U);
                // Spec MUST: "The maximum depth of the `prev_events`, plus one"; a rejected event is not one of them.
                REQUIRE(stored_depth(runtime, topic.value) == tip_depth + 2U);
                // Spec SHOULD: a rejected event should not "be included as a prev event in any new events".
                auto const stored = runtime.database.persistent_store.events.find(sent.value);
                REQUIRE(std::ranges::find(stored->prev_event_ids, "$hostile:evil.example") ==
                        stored->prev_event_ids.end());
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19, GET /_matrix/federation/v1/make_join/{roomId}/{userId}
// and the same `depth` rule: the joining server is given the depth to sign.
SCENARIO("A make_join template never offers a depth above the limit", "[conformance][federation][depth][membership]")
{
    GIVEN("a room whose newest event is at depth 2^53 - 1")
    {
        namespace fixture = merovingian::tests::remote_room;
        auto const path = fixture::unique_sqlite_path("merovingian-depth-template-");
        std::filesystem::remove(path);
        {
            auto started = merovingian::homeserver::start_runtime(fixture::config_with_sqlite(path));
            REQUIRE(started.started);
            auto& runtime = started.runtime;
            auto const room_id = std::string{"!depth-template:local.example.org"};
            fixture::seed_room_with_genesis_state_group(runtime, room_id);
            auto deepest = merovingian::database::PersistentEvent{};
            deepest.event_id = room_id + ":deepest";
            deepest.room_id = room_id;
            deepest.json = "{}";
            deepest.depth = static_cast<std::uint64_t>(depth_limit);
            REQUIRE(merovingian::database::store_event(runtime.database.persistent_store, deepest));
            REQUIRE(merovingian::database::update_forward_extremities(runtime.database.persistent_store, room_id,
                                                                      deepest.event_id, {}, true));
            merovingian::homeserver::wire_federation_callbacks(runtime);
            REQUIRE(runtime.federation.membership_template_provider);

            WHEN("a template is built for a remote joiner")
            {
                auto const tmpl = runtime.federation.membership_template_provider(
                    merovingian::federation::FederationEndpoint::make_join, room_id, "@carol:remote.example.org", {});

                THEN("its depth is the limit")
                {
                    // Spec MUST: make_join answers an allowed joiner with a template event, which carries a `depth`.
                    REQUIRE(tmpl.has_value());
                    // Spec MUST: "Must be less than the maximum value for an integer"; held at the limit.
                    REQUIRE(tmpl->depth == depth_limit);
                }
            }
        }
        std::filesystem::remove(path);
    }
}

// Spec: Matrix Server-Server API v1.19, "Rejection": a rejected event should not be "included as a prev
// event in any new events generated by the server". Room version event format: `prev_events` "Must
// contain less than or equal to 20 events". GET /make_join 404: the room "is unknown to the receiving
// server". Audit run-2 F-06: the template listed every unreferenced row, so a server outside the room
// could block joins with 21 rejected PDUs, and a rejected PDU citing the tip removed the tip.
SCENARIO("A membership template offers only the room's accepted tips",
         "[conformance][federation][depth][rejection][membership][template-prev-events]")
{
    GIVEN("a room with one tip and 21 rejected PDUs from a stranger at depth 2^53 - 1, some citing the tip")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto& store = runtime.database.persistent_store;
        auto const tips = merovingian::homeserver::forward_extremities_for_new_event(store, ctx.room_id);
        // Fixture: one forward extremity, the only event a template may offer.
        REQUIRE(tips.size() == 1U);
        auto const tip_depth = stored_depth(runtime, tips.front());
        for (auto index = 0; index < 21; ++index)
        {
            auto const event_id = "$hostile-" + std::to_string(index) + ":evil.example";
            auto const prev_events = index % 2 == 0 ? tips : std::vector<std::string>{};
            std::ignore = merovingian::homeserver::ingest_pdu_event(
                runtime,
                make_message_pdu(ctx.room_id, event_id, "@mallory:evil.example", prev_events, {}, depth_limit));
            auto const stored = store.events.find(event_id);
            // Fixture: the event reached this server, so a later check on it means something.
            REQUIRE(stored != store.events.end());
            // Spec MUST: an event that fails the authorisation rules "is rejected"; the sender is not in the room.
            REQUIRE(stored->status == "rejected");
        }

        WHEN("a template is built for a remote joiner")
        {
            auto const tmpl = runtime.federation.membership_template_provider(
                merovingian::federation::FederationEndpoint::make_join, ctx.room_id, "@carol:remote.example.org", {});

            THEN("it offers the room's tip, even though rejected events cite it, and no rejected event")
            {
                // Spec MUST: make_join answers an allowed joiner with a template event, which carries `prev_events`.
                REQUIRE(tmpl.has_value());
                // Spec SHOULD: a rejected event is not "included as a prev event in any new events".
                REQUIRE(tmpl->prev_events == tips);
                // Spec MUST: `prev_events` "Must contain less than or equal to 20 events".
                REQUIRE(tmpl->prev_events.size() <= 20U);
                // Spec MUST: "The maximum depth of the `prev_events`, plus one"; a rejected event is not one of them.
                REQUIRE(tmpl->depth == static_cast<std::int64_t>(tip_depth + 1U));
            }
        }

        WHEN("the room has no tips to build on and a template is requested")
        {
            std::erase_if(store.forward_extremities, [&](auto const& extremity) {
                return extremity.room_id == ctx.room_id;
            });
            auto const tmpl = runtime.federation.membership_template_provider(
                merovingian::federation::FederationEndpoint::make_join, ctx.room_id, "@carol:remote.example.org", {});

            THEN("no template is offered, rather than one with empty prev_events")
            {
                // Project rule (ADR-0318): no template, which GET /make_join answers as 404; the spec leaves this open.
                REQUIRE_FALSE(tmpl.has_value());
            }
        }
    }
}
