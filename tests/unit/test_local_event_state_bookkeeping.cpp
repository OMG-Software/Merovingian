// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0064 phase B1 (continued): proves locally created events participate
// in the same state-group / forward-extremity bookkeeping as inbound PDUs.
// Without this, a locally sent event has no after-state group and never
// becomes a forward extremity, so the next inbound PDU that lists it as a
// prev_event fails closed with missing_prev_state and is dropped — a
// federation regression, since main (pre-ADR-0064) accepted it. Tags:
// [pdu_ingestion][state_groups].
//
// Spec: docs/matrix-v1.19-spec/rooms/v10.md — prev_events "Must contain
// less than or equal to 20 events"; server-server-api.md, "Checks
// performed on receipt of a PDU".

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <vector>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

struct AliceRoom final
{
    std::string alice_token{};
    std::string alice_id{};
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
    return {login.value, "@alice:example.org", room.value};
}

// Builds a well-formed inbound PDU envelope naming `prev_event_ids`,
// "sent" by alice (the room creator, so power-level auth trivially
// succeeds) — matching the pattern
// tests/unit/test_federation_pdu_ingest_concurrency.cpp's make_message_pdu
// uses to exercise ingest_pdu_event directly, without a real X-Matrix
// signature (ingest_pdu_event's trust boundary does not re-verify it; see
// the comment above ingest_pdu_event itself).
[[nodiscard]] auto make_inbound_pdu(std::string const& room_id, std::string const& event_id,
                                    std::string const& event_type, std::optional<std::string> const& state_key,
                                    std::vector<std::string> const& prev_event_ids, std::int64_t ts,
                                    merovingian::canonicaljson::Object content = {},
                                    std::vector<std::string> const& auth_event_ids = {})
    -> merovingian::federation::InboundPduEnvelope
{
    using namespace merovingian;

    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{event_type}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{room_id}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{"@alice:example.org"}}));
    obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{std::int64_t{10}}));
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
    if (state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*state_key}));
    }

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
    // create_room defaults new rooms to version 12 (compose_signed_event's
    // m.room.create default) when no explicit room_version is requested;
    // match that so the inbound PDU's auth checks use the same rule set as
    // the room it targets.
    env.room_version = "12";
    env.sender = "@alice:example.org";
    env.event_type = event_type;
    env.state_key = state_key;
    env.origin_server_ts = ts;
    env.depth = 10U;
    env.prev_event_ids = prev_event_ids;
    env.auth_event_ids = auth_event_ids;
    env.json = serialized.output;
    return env;
}

} // namespace

SCENARIO("THE REGRESSION: a remote PDU referencing a locally sent message is accepted, not missing_prev_state",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a room created locally, with a local message sent into it")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);

        auto const sent = merovingian::homeserver::send_event(
            runtime, ctx.alice_token, ctx.room_id,
            R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"hello"}})");
        REQUIRE(sent.ok);
        auto const local_message_event_id = sent.value;

        WHEN("a remote PDU listing the local message as its prev_event is ingested")
        {
            // ADR-0064 phase B2: ingest_pdu_event now authorises against the
            // PDU's own named auth_events (spec step 4), so this fixture
            // needs the room's real create/power_levels events, matching
            // what a real federating server would send.
            auto const auth_event_ids = [&]() -> std::vector<std::string> {
                auto ids = std::vector<std::string>{};
                for (auto const& s : runtime.database.persistent_store.state)
                {
                    if (s.room_id != ctx.room_id)
                    {
                        continue;
                    }
                    if ((s.event_type == "m.room.create" || s.event_type == "m.room.power_levels") &&
                        s.state_key.empty())
                    {
                        ids.push_back(s.event_id);
                    }
                }
                return ids;
            }();
            auto const envelope = make_inbound_pdu(ctx.room_id, "$remote_reply:remote.example.org", "m.room.message",
                                                   std::nullopt, {local_message_event_id}, 5000, {}, auth_event_ids);
            auto const result = merovingian::homeserver::ingest_pdu_event(runtime, envelope);

            THEN("it is accepted, not missing_prev_state — the local message must have its own state group")
            {
                REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);
            }
        }
    }
}

SCENARIO("A local send after an inbound fork lists both fork tips as prev_events, "
         "and its state before is their resolution",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a room whose current tip forks into two inbound m.room.topic events")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);

        auto const tip = [&]() -> std::string {
            auto const extremities =
                merovingian::database::find_forward_extremities(runtime.database.persistent_store, ctx.room_id);
            REQUIRE(extremities.size() == 1U);
            return extremities.front();
        }();

        // Room v12 (this room's default) runs state-res v2.1: the iterative
        // auth checks start from an EMPTY map, so a conflicted candidate
        // whose own auth_events cannot supply power_levels/create is denied
        // and silently dropped from the resolved state, not treated as
        // "unresolvable". Give both topic events real auth_events so the
        // resolver can find the room's actual power level for alice.
        auto const auth_event_ids = [&]() -> std::vector<std::string> {
            auto ids = std::vector<std::string>{};
            for (auto const& s : runtime.database.persistent_store.state)
            {
                if (s.room_id != ctx.room_id)
                {
                    continue;
                }
                if ((s.event_type == "m.room.create" || s.event_type == "m.room.power_levels") && s.state_key.empty())
                {
                    ids.push_back(s.event_id);
                }
            }
            return ids;
        }();

        auto topic_a_content = merovingian::canonicaljson::Object{};
        topic_a_content.push_back(merovingian::canonicaljson::make_member(
            "topic", merovingian::canonicaljson::Value{std::string{"topic-a"}}));
        auto const topic_a = make_inbound_pdu(ctx.room_id, "$topic_a:remote.example.org", "m.room.topic", std::string{},
                                              {tip}, 6000, std::move(topic_a_content), auth_event_ids);
        auto const result_a = merovingian::homeserver::ingest_pdu_event(runtime, topic_a);
        REQUIRE(result_a.status == merovingian::federation::PduIngestionStatus::accepted);

        auto topic_b_content = merovingian::canonicaljson::Object{};
        topic_b_content.push_back(merovingian::canonicaljson::make_member(
            "topic", merovingian::canonicaljson::Value{std::string{"topic-b"}}));
        auto const topic_b = make_inbound_pdu(ctx.room_id, "$topic_b:remote.example.org", "m.room.topic", std::string{},
                                              {tip}, 7000, std::move(topic_b_content), auth_event_ids);
        auto const result_b = merovingian::homeserver::ingest_pdu_event(runtime, topic_b);
        REQUIRE(result_b.status == merovingian::federation::PduIngestionStatus::accepted);

        auto const extremities_after_fork =
            merovingian::database::find_forward_extremities(runtime.database.persistent_store, ctx.room_id);
        REQUIRE(extremities_after_fork.size() == 2U);

        WHEN("alice sends an ordinary message locally")
        {
            auto const sent = merovingian::homeserver::send_event(
                runtime, ctx.alice_token, ctx.room_id,
                R"({"type":"m.room.message","content":{"msgtype":"m.text","body":"after the fork"}})");
            REQUIRE(sent.ok);

            THEN("the stored event's prev_event_ids are exactly both fork tips")
            {
                auto const& events = runtime.database.persistent_store.events;
                auto const it = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == sent.value;
                });
                REQUIRE(it != events.end());
                auto prev_sorted = it->prev_event_ids;
                std::ranges::sort(prev_sorted);
                auto expected = extremities_after_fork;
                std::ranges::sort(expected);
                REQUIRE(prev_sorted == expected);
            }

            THEN("its state before is the resolution of both tips (current_state agrees)")
            {
                auto const group =
                    merovingian::database::find_event_state_group(runtime.database.persistent_store, sent.value);
                REQUIRE(group.has_value());
                auto const full =
                    merovingian::database::read_state_group_full_state(runtime.database.persistent_store, *group);
                REQUIRE(full.has_value());
                auto const topic_entry =
                    std::ranges::find_if(*full, [](merovingian::database::PersistentStateGroupStateEntry const& e) {
                        return e.event_type == "m.room.topic";
                    });
                REQUIRE(topic_entry != full->end());

                auto const& current_state = runtime.database.persistent_store.state;
                auto const current_topic =
                    std::ranges::find_if(current_state, [&](merovingian::database::PersistentStateEvent const& s) {
                        return s.room_id == ctx.room_id && s.event_type == "m.room.topic";
                    });
                REQUIRE(current_topic != current_state.end());
                REQUIRE(topic_entry->event_id == current_topic->event_id);
            }
        }
    }
}

SCENARIO("Room creation: every initial event has a correct after-state group, "
         "and the room's forward extremity is the last one",
         "[pdu_ingestion][state_groups]")
{
    GIVEN("a freshly created room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const ctx = make_alice_room(runtime);

        THEN("every event this room's genesis stored has a recorded after-state group")
        {
            auto const& store = runtime.database.persistent_store;
            auto initial_events = std::vector<merovingian::database::PersistentEvent const*>{};
            for (auto const& event : store.events)
            {
                if (event.room_id == ctx.room_id)
                {
                    initial_events.push_back(&event);
                }
            }
            REQUIRE(initial_events.size() >= 3U); // at least create, member, power_levels

            for (auto const* event : initial_events)
            {
                auto const group = merovingian::database::find_event_state_group(store, event->event_id);
                REQUIRE(group.has_value());
                auto const full = merovingian::database::read_state_group_full_state(store, *group);
                REQUIRE(full.has_value());
            }
        }

        THEN("the room's sole forward extremity is the last-depth initial event")
        {
            auto const& store = runtime.database.persistent_store;
            auto const extremities = merovingian::database::find_forward_extremities(store, ctx.room_id);
            REQUIRE(extremities.size() == 1U);

            auto max_depth = std::uint64_t{0U};
            auto expected_tip = std::string{};
            for (auto const& event : store.events)
            {
                if (event.room_id == ctx.room_id && event.depth >= max_depth)
                {
                    max_depth = event.depth;
                    expected_tip = event.event_id;
                }
            }
            REQUIRE(extremities.front() == expected_tip);
        }
    }
}
