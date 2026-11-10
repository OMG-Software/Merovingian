// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/CanonicalJsonError.hpp"
#include "merovingian/canonicaljson/ObjectMember.hpp"
#include "merovingian/canonicaljson/ParseError.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/ExaminedRows.hpp"
#include "merovingian/database/PersistentFederationTransaction.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/DispatchWorker.hpp"
#include "merovingian/federation/DispatchWorkerConfig.hpp"
#include "merovingian/federation/EduIdempotenceWindow.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/PduIngestionStatus.hpp"
#include "merovingian/federation/ServerDiscoveryResult.hpp"
#include "merovingian/homeserver/ClientServerClock.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/LocalDatabase.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/http/OutboundClient.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto make_seed_event_json(std::string_view event_type, std::string_view state_key,
                                        std::string_view sender, std::string_view room_id,
                                        merovingian::canonicaljson::Object content, std::int64_t depth,
                                        std::int64_t origin_server_ts) -> std::string
{
    using namespace merovingian;

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{std::string{"hash"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{depth}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));
    event_obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{origin_server_ts}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
    event_obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{std::string{state_key}}));
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{event_type}}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto make_message_pdu_json(std::string_view room_id, std::string_view sender) -> std::string
{
    using namespace merovingian;

    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("body", canonicaljson::Value{std::string{"hello"}}));
    content.push_back(canonicaljson::make_member("msgtype", canonicaljson::Value{std::string{"m.text"}}));

    auto event_obj = canonicaljson::Object{};
    event_obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"m.room.message"}}));
    event_obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{std::string{room_id}}));
    event_obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{std::string{sender}}));
    event_obj.push_back(canonicaljson::make_member("content", canonicaljson::Value{std::move(content)}));
    event_obj.push_back(
        canonicaljson::make_member("origin_server_ts", canonicaljson::Value{static_cast<std::int64_t>(1000)}));
    event_obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(2)}));
    event_obj.push_back(canonicaljson::make_member("prev_events", canonicaljson::Value{canonicaljson::Array{}}));
    event_obj.push_back(canonicaljson::make_member("auth_events", canonicaljson::Value{canonicaljson::Array{}}));

    auto const hash = events::make_content_hash(canonicaljson::Value{event_obj});
    REQUIRE(hash.error.empty());

    auto hashes = canonicaljson::Object{};
    hashes.push_back(canonicaljson::make_member("sha256", canonicaljson::Value{hash.sha256}));
    event_obj.push_back(canonicaljson::make_member("hashes", canonicaljson::Value{std::move(hashes)}));

    auto value = canonicaljson::Value{std::move(event_obj)};
    auto const serialized = canonicaljson::serialize_canonical(value);
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

} // namespace

SCENARIO("Inbound PDU sink assigns stream ordering and notifies sync", "[homeserver][outbound-dispatch][inbound-sync]")
{
    GIVEN("a homeserver runtime with a wired pdu_sink and sync notifier")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto& homeserver = runtime.homeserver;

        // Wire the sync notifier via the proper accessor
        std::ignore = merovingian::homeserver::ensure_sync_notifier(runtime);

        // Wire federation callbacks (creates pdu_sink, dispatch_worker, etc.)
        merovingian::homeserver::wire_federation_callbacks(homeserver);

        // pdu_sink should now be wired
        REQUIRE(homeserver.federation.pdu_sink);
        REQUIRE(homeserver.sync_notifier != nullptr);

        auto const ordering_before = homeserver.database.next_stream_ordering;

        // Pre-populate the room state so the pdu_sink's auth check (SS API
        // §authorization-rules) finds the create and sender-member events it
        // needs. The pdu_sink persists state from store.state on every ingest,
        // and the auth map is built from the same source — both must agree.
        auto const room_id_str = std::string{"!inbound_test:remote.example.org"};
        auto const bob_sender = std::string{"@bob:remote.example.org"};

        auto create_content = merovingian::canonicaljson::Object{};
        create_content.push_back(merovingian::canonicaljson::make_member(
            "creator", merovingian::canonicaljson::Value{std::string{bob_sender}}));
        create_content.push_back(merovingian::canonicaljson::make_member(
            "room_version", merovingian::canonicaljson::Value{std::string{"12"}}));
        auto const create_json =
            make_seed_event_json("m.room.create", "", bob_sender, room_id_str, std::move(create_content), 0, 1);

        auto member_content = merovingian::canonicaljson::Object{};
        member_content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const member_json =
            make_seed_event_json("m.room.member", bob_sender, bob_sender, room_id_str, std::move(member_content), 1, 2);

        homeserver.database.persistent_store.events.push_back({.event_id = "$inbound_create",
                                                               .room_id = room_id_str,
                                                               .sender_user_id = bob_sender,
                                                               .json = create_json,
                                                               .depth = 0U});
        homeserver.database.persistent_store.events.push_back({.event_id = "$inbound_bob_member",
                                                               .room_id = room_id_str,
                                                               .sender_user_id = bob_sender,
                                                               .json = member_json,
                                                               .depth = 1U});
        homeserver.database.persistent_store.state.push_back(
            {.room_id = room_id_str, .event_type = "m.room.create", .state_key = "", .event_id = "$inbound_create"});
        homeserver.database.persistent_store.state.push_back({.room_id = room_id_str,
                                                              .event_type = "m.room.member",
                                                              .state_key = bob_sender,
                                                              .event_id = "$inbound_bob_member"});

        // ADR-0064 phase B2: ingest_pdu_event now also authorises against the
        // PDU's own auth_events (spec step 4) and the state before it (step
        // 5, via compute_state_before), so this fixture needs a real state
        // group for $inbound_bob_member — not just the naive store.state
        // rows above — matching what seed_room_with_genesis_state_group does
        // in tests/unit/test_pdu_ingestion_state_groups.cpp.
        {
            auto& store = homeserver.database.persistent_store;
            auto const genesis_state = std::vector<merovingian::database::PersistentStateGroupStateEntry>{
                {"", "m.room.create", "",         "$inbound_create"    },
                {"", "m.room.member", bob_sender, "$inbound_bob_member"},
            };
            auto const group_id = merovingian::database::create_or_reuse_state_group(
                store, room_id_str, room_id_str + ":genesis-group", std::nullopt, genesis_state);
            REQUIRE(group_id.has_value());
            REQUIRE(merovingian::database::set_event_state_group(store, "$inbound_bob_member", *group_id));
            REQUIRE(
                merovingian::database::update_forward_extremities(store, room_id_str, "$inbound_bob_member", {}, true));
        }

        // FED-11 admission gate: the pdu_sink now rejects PDUs for rooms that
        // have no local member. Seed a local join so the message PDU is admitted.
        {
            auto const local_user = std::string{"@alice:example.org"};
            auto local_member_content = merovingian::canonicaljson::Object{};
            local_member_content.push_back(merovingian::canonicaljson::make_member(
                "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
            auto const local_member_json = make_seed_event_json("m.room.member", local_user, local_user, room_id_str,
                                                                std::move(local_member_content), 2, 3);
            auto& store = homeserver.database.persistent_store;
            store.events.push_back({.event_id = "$inbound_local_member",
                                    .room_id = room_id_str,
                                    .sender_user_id = local_user,
                                    .json = local_member_json,
                                    .depth = 2U});
            store.state.push_back({.room_id = room_id_str,
                                   .event_type = "m.room.member",
                                   .state_key = local_user,
                                   .event_id = "$inbound_local_member"});
            store.memberships.push_back({.room_id = room_id_str, .user_id = local_user, .membership = "join"});
            auto const local_state = std::vector<merovingian::database::PersistentStateGroupStateEntry>{
                {"", "m.room.create", "",         "$inbound_create"      },
                {"", "m.room.member", bob_sender, "$inbound_bob_member"  },
                {"", "m.room.member", local_user, "$inbound_local_member"},
            };
            auto const group_id = merovingian::database::create_or_reuse_state_group(
                store, room_id_str, room_id_str + ":local-member-group", std::nullopt, local_state);
            REQUIRE(group_id.has_value());
            REQUIRE(merovingian::database::set_event_state_group(store, "$inbound_local_member", *group_id));
            REQUIRE(merovingian::database::update_forward_extremities(store, room_id_str, "$inbound_local_member",
                                                                      {"$inbound_bob_member"}, false));
        }

        WHEN("an inbound PDU is ingested through the pdu_sink")
        {
            auto envelope = merovingian::federation::InboundPduEnvelope{};
            envelope.event_id = "$test_inbound_event";
            envelope.room_id = room_id_str;
            // Matches the create event's own content.room_version above.
            // Left implicit before, but explicit here matters now: v12
            // (MSC4291) is why m.room.create is NOT named in auth_events
            // below — its event id is implicit in the room ID, and naming
            // it is itself an ADR-0064 phase B2 selection violation.
            envelope.room_version = "12";
            envelope.sender = bob_sender;
            envelope.event_type = "m.room.message";
            envelope.depth = 2U;
            envelope.origin_server_ts = static_cast<std::int64_t>(1000);
            envelope.prev_event_ids = {"$inbound_bob_member"};
            envelope.auth_event_ids = {"$inbound_bob_member"};
            // The auth check parses this JSON to read the event's sender/type,
            // so it must carry the same fields the envelope advertises, and the
            // ingest path now verifies the content hash.
            envelope.json = make_message_pdu_json(room_id_str, bob_sender);

            auto const result = homeserver.federation.pdu_sink(envelope);

            THEN("the event is accepted with a non-zero stream ordering")
            {
                REQUIRE(result.status == merovingian::federation::PduIngestionStatus::accepted);
                REQUIRE(homeserver.database.next_stream_ordering > ordering_before);
                auto const& events = homeserver.database.persistent_store.events;
                REQUIRE_FALSE(events.empty());
                REQUIRE(events.back().stream_ordering > 0U);
            }
        }
    }
}
