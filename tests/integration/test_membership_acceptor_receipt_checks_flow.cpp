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

#include "../support/MembershipGenesis.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_acceptor_fixture.hpp"
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
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/federation/InboundPduEnvelope.hpp"
#include "merovingian/federation/InviteRequest.hpp"
#include "merovingian/federation/VerificationKeyResolution.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/remote_key_cache.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/RoomVersionPolicy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace
{

using merovingian::federation::InboundPduEnvelope;
using merovingian::homeserver::HomeserverRuntime;

using merovingian::tests::membership_acceptor_fixture::build_event_json;
using merovingian::tests::membership_acceptor_fixture::config_with_sqlite;
using merovingian::tests::membership_acceptor_fixture::Genesis;
using merovingian::tests::membership_acceptor_fixture::make_envelope;
using merovingian::tests::membership_acceptor_fixture::seed_accepted_event;
using merovingian::tests::membership_acceptor_fixture::seed_room_genesis;
using merovingian::tests::membership_acceptor_fixture::unique_sqlite_path;

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
        // has never joined before). prev_events must point at the current
        // forward extremity so compute_state_before resolves the public
        // join_rules state; admin_member_id's state group predates join_rules.
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const bad_json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                               "@bob:remote.example.org", std::move(content), {genesis.join_rules_id},
                                               {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, 5,
                                               std::string{"this-does-not-match"});
        auto const envelope =
            make_envelope(room_id, "$sjbadhash:remote.example.org", "m.room.member",
                          std::string{"@bob:remote.example.org"}, "@bob:remote.example.org", {genesis.join_rules_id},
                          {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, bad_json);

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

// A send_join, send_leave or send_knock is usually accepted by a federation worker and relayed
// to main, which stores it. The worker answers the room's next make_join, make_leave or
// send_leave from its own snapshot of the room, so main must tell it the room changed, as it
// does for a relayed /send PDU. Without that the worker built a make_leave template whose
// auth_events lacked the leaver's join, then refused the leave against them (Complement
// TestRestrictedRoomsRemoteJoin, rule 7: "self-leave requires current membership").
SCENARIO("An accepted send_join tells the federation worker that the room changed", "[pdu_ingestion][worker-room-sync]")
{
    GIVEN("a seeded room and a valid send_join from a remote user")
    {
        // Declared before the runtime so it outlives it.
        auto changed_rooms = std::vector<std::string>{};
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        started.runtime.test_room_changed_log = &changed_rooms;

        auto const room_id = std::string{"!sjnotify:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                           "@bob:remote.example.org", std::move(content), {genesis.join_rules_id},
                                           {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, 5);
        auto const envelope =
            make_envelope(room_id, "$sjnotify:remote.example.org", "m.room.member",
                          std::string{"@bob:remote.example.org"}, "@bob:remote.example.org", {genesis.join_rules_id},
                          {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, json);

        WHEN("the membership acceptor accepts it")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("the join is accepted and the worker is told about the room")
            {
                REQUIRE(result.accepted);
                REQUIRE(std::ranges::find(changed_rooms, room_id) != changed_rooms.end());
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

        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                           "@bob:remote.example.org", std::move(content), {genesis.join_rules_id},
                                           {genesis.create_id, genesis.pl_id}, 4, 5);
        // No join_rules named in auth_events at all -> Step 4 of the member
        // auth rules ("cannot join without an invite unless join_rules is
        // public, and public join_rules must be provable via auth_events")
        // denies it. prev_events still point at the current forward extremity
        // so the state-before check would otherwise pass.
        auto const envelope = make_envelope(room_id, "$sjbadauth:remote.example.org", "m.room.member",
                                            std::string{"@bob:remote.example.org"}, "@bob:remote.example.org",
                                            {genesis.join_rules_id}, {genesis.create_id, genesis.pl_id}, 4, json);

        WHEN("the send_join is processed")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("it is rejected with a definite error, not silently accepted")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
            }

            THEN("it is not stored at all: the request is refused, so this server never takes the event (F-12, "
                 "ADR-0591)")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                REQUIRE(std::ranges::none_of(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$sjbadauth:remote.example.org";
                }));
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
        // Both the ban and the subsequent join must point at the current
        // forward extremity (join_rules) so their state-before resolves to
        // the public room state. The join then soft-fails because the
        // resolved current state contains the ban.
        auto const ban_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                             "@admin:local.example.org", std::move(ban_content), {genesis.join_rules_id},
                             {genesis.create_id, genesis.pl_id, genesis.admin_member_id}, 4, 5);
        seed_accepted_event(started.runtime, room_id, ban_id, "m.room.member", std::string{"@bob:remote.example.org"},
                            "@admin:local.example.org", ban_json, {genesis.join_rules_id}, 4U);

        // Bob's send_join: auth_events include public join_rules, and
        // prev_events point at the same pre-ban tip as the ban so step 5
        // authorises the join. Step 6 (current state, where bob IS banned)
        // denies it -> soft failure.
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                           "@bob:remote.example.org", std::move(content), {genesis.join_rules_id},
                                           {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, 5);
        auto const envelope =
            make_envelope(room_id, "$sjsoftfail:remote.example.org", "m.room.member",
                          std::string{"@bob:remote.example.org"}, "@bob:remote.example.org", {genesis.join_rules_id},
                          {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, json);

        WHEN("the send_join is processed")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("it is refused 403 and carries no room state (F-10, ADR-0591)")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 403U);
                REQUIRE(result.state_json.empty());
                REQUIRE(result.auth_chain_json.empty());
            }

            THEN("it is not stored: a soft-failed membership of send_join is never taken into the DAG (ADR-0591)")
            {
                auto const& events = started.runtime.database.persistent_store.events;
                REQUIRE(std::ranges::none_of(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == "$sjsoftfail:remote.example.org";
                }));
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

namespace
{

[[nodiscard]] auto object_member_value(merovingian::canonicaljson::Object const& object, std::string_view key)
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

// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU", step 3: "Passes hash checks, otherwise it is redacted
// before being processed further", and "Validating hashes and signatures on
// received events": "the receiving server should use the redacted copy it
// calculated rather than the full copy it received". PUT /invite lists only a
// signature failure as a reason to refuse. Audit R06.
SCENARIO("invite: an invite with a mismatched content hash is redacted before it is signed and stored",
         "[pdu_ingestion][invite][r06]")
{
    GIVEN("a local user invited to a room this server does not hold, by an event whose hash does not match")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        REQUIRE(started.runtime.federation.invite_handler != nullptr);
        started.runtime.database.users.push_back({"@bob:local.example.org", {}, false, false, false, false});

        auto const room_id = std::string{"!elsewhere:remote.example.org"};
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "displayname", merovingian::canonicaljson::Value{std::string{"Mallory"}}));
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"invite"}}));
        auto const invite_json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:local.example.org"},
                             "@alice:remote.example.org", std::move(content), {"$prev:remote.example.org"},
                             {"$create:remote.example.org"}, 4, 5, std::string{"this-does-not-match"});
        auto request = merovingian::federation::InviteRequest{};
        request.room_id = room_id;
        request.event_id = "$invitebadhash:remote.example.org";
        request.room_version = "10";
        request.invite_event_json = invite_json;
        request.origin = "remote.example.org";

        WHEN("the invite is handled")
        {
            auto const result = started.runtime.federation.invite_handler(request);

            THEN("it is accepted, not refused for its hash")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.status == 200U);
            }

            THEN("the event this server signs and keeps is the redacted copy")
            {
                REQUIRE(result.accepted);
                auto const parsed = merovingian::canonicaljson::parse_lossless(result.signed_event_json);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* content_value = object_member_value(*root, "content");
                REQUIRE(content_value != nullptr);
                auto const* content_object = std::get_if<merovingian::canonicaljson::Object>(&content_value->storage());
                REQUIRE(content_object != nullptr);
                REQUIRE(object_member_value(*content_object, "displayname") == nullptr);
                REQUIRE(object_member_value(*content_object, "membership") != nullptr);
                auto const* signatures = object_member_value(*root, "signatures");
                REQUIRE(signatures != nullptr);
                auto const* signatures_object = std::get_if<merovingian::canonicaljson::Object>(&signatures->storage());
                REQUIRE(signatures_object != nullptr);
                REQUIRE(object_member_value(*signatures_object, "local.example.org") != nullptr);

                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == request.event_id;
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->json.find("Mallory") == std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: docs/matrix-v1.19-spec/server-server-api.md — PUT /v2/invite: the
// request's `room_version` is "The version of the room where the user is being
// invited to". A room this server does not hold has no create event to read a
// version from, so the invite is redacted and signed under the version the
// request names. Redaction differs by version: from rooms/v11.md, the top-level
// `origin` key is no longer kept, while v10 keeps it. Audit R06 (review of PR
// #520).
SCENARIO(
    "invite: an invite for a room this server does not hold is redacted and signed under the request's room version",
    "[pdu_ingestion][invite][r06]")
{
    GIVEN("a local user invited to an unheld room version 12 room, by an event with a top-level origin and a bad hash")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        REQUIRE(started.runtime.federation.invite_handler != nullptr);
        REQUIRE(started.runtime.crypto_provider != nullptr);
        started.runtime.database.users.push_back({"@bob:local.example.org", {}, false, false, false, false});

        auto const room_id = std::string{"!v12room:remote.example.org"};
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"invite"}}));
        auto const built =
            build_event_json(room_id, "m.room.member", std::string{"@bob:local.example.org"},
                             "@alice:remote.example.org", std::move(content), {"$prev:remote.example.org"},
                             {"$create:remote.example.org"}, 4, 5, std::string{"this-does-not-match"});
        auto const parsed_built = merovingian::canonicaljson::parse_lossless(built);
        REQUIRE(parsed_built.error == merovingian::canonicaljson::ParseError::none);
        auto const* built_object = std::get_if<merovingian::canonicaljson::Object>(&parsed_built.value.storage());
        REQUIRE(built_object != nullptr);
        auto with_origin = merovingian::canonicaljson::Object{};
        for (auto const& member : *built_object)
        {
            with_origin.push_back(merovingian::canonicaljson::make_member(member.key, *member.value));
        }
        with_origin.push_back(merovingian::canonicaljson::make_member(
            "origin", merovingian::canonicaljson::Value{std::string{"remote.example.org"}}));
        auto const invite_json =
            merovingian::canonicaljson::serialize_canonical(merovingian::canonicaljson::Value{std::move(with_origin)});
        REQUIRE(invite_json.error == merovingian::canonicaljson::CanonicalJsonError::none);
        auto request = merovingian::federation::InviteRequest{};
        request.room_id = room_id;
        request.event_id = "$invitev12:remote.example.org";
        request.room_version = "12";
        request.invite_event_json = invite_json.output;
        request.origin = "remote.example.org";

        WHEN("the invite is handled")
        {
            auto const result = started.runtime.federation.invite_handler(request);

            THEN("the copy it keeps is redacted under version 12 and carries a signature valid under version 12")
            {
                REQUIRE(result.accepted);
                auto const parsed = merovingian::canonicaljson::parse_lossless(result.signed_event_json);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                // rooms/v11.md redaction: top-level `origin` is no longer preserved.
                REQUIRE(object_member_value(*root, "origin") == nullptr);
                auto const* policy = merovingian::rooms::find_room_version_policy("12");
                REQUIRE(policy != nullptr);
                auto const envelope = merovingian::events::parse_event_envelope(parsed.value);
                REQUIRE(envelope.error.empty());
                auto& store = started.runtime.database.persistent_store;
                auto const verified = merovingian::federation::verify_server_signatures_on_event(
                    parsed.value, *policy, "local.example.org", envelope.event.signatures,
                    [&store](std::string_view server_name, std::string_view key_id) {
                        return merovingian::federation::VerificationKeyResolution{
                            merovingian::federation::find_own_server_signing_key(store, server_name, key_id)};
                    },
                    *started.runtime.crypto_provider);
                REQUIRE(verified.accepted);
            }
        }

        std::filesystem::remove(path);
    }
}

// Spec: docs/matrix-v1.19-spec/server-server-api.md — PUT /v2/send_join, 200
// response `event`: "The membership event sent to other servers by the resident
// server". After a hash mismatch that is the redacted copy the resident kept,
// never the full copy it received. Audit R06.
SCENARIO("send_join: the event returned for a hash-mismatched join is the redacted copy this server stored",
         "[pdu_ingestion][auth][r06]")
{
    GIVEN("a seeded public room and a send_join whose content carries an extra key the hash does not cover")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);

        auto const room_id = std::string{"!sjhashreturn:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "displayname", merovingian::canonicaljson::Value{std::string{"Mallory"}}));
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const bad_json = build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                                               "@bob:remote.example.org", std::move(content), {genesis.join_rules_id},
                                               {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, 5,
                                               std::string{"this-does-not-match"});
        auto const envelope =
            make_envelope(room_id, "$sjhashreturn:remote.example.org", "m.room.member",
                          std::string{"@bob:remote.example.org"}, "@bob:remote.example.org", {genesis.join_rules_id},
                          {genesis.create_id, genesis.pl_id, genesis.join_rules_id}, 4, bad_json);

        WHEN("the send_join is accepted")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("the event handed back is the redacted copy, identical to the stored one")
            {
                REQUIRE(result.accepted);
                REQUIRE(result.signed_event_json.find("Mallory") == std::string::npos);
                auto const& events = started.runtime.database.persistent_store.events;
                auto const stored = std::ranges::find_if(events, [&](merovingian::database::PersistentEvent const& e) {
                    return e.event_id == envelope.event_id;
                });
                REQUIRE(stored != events.end());
                REQUIRE(stored->json == result.signed_event_json);
            }
        }

        std::filesystem::remove(path);
    }
}

// ADR-0315: the acceptor stores the event and then takes sync positions for it, the roster and the
// notification. Past the counter's limit it must refuse before storing, or the peer gets no answer about
// an event this server has kept.
SCENARIO("send_join at the sync stream counter's limit is refused and stores nothing",
         "[pdu_ingestion][sync-stream][security]")
{
    GIVEN("a seeded room, a server whose sync stream counter is at its ceiling, and a valid send_join")
    {
        auto const path = unique_sqlite_path();
        std::filesystem::remove(path);
        auto started = merovingian::homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        merovingian::homeserver::wire_federation_callbacks(started.runtime);
        auto const room_id = std::string{"!sjceiling:local.example.org"};
        auto const genesis = seed_room_genesis(started.runtime, room_id, "@admin:local.example.org");
        auto content = merovingian::canonicaljson::Object{};
        content.push_back(merovingian::canonicaljson::make_member(
            "membership", merovingian::canonicaljson::Value{std::string{"join"}}));
        auto const auth_ids = std::vector<std::string>{genesis.create_id, genesis.pl_id, genesis.join_rules_id};
        auto const json =
            build_event_json(room_id, "m.room.member", std::string{"@bob:remote.example.org"},
                             "@bob:remote.example.org", std::move(content), {genesis.join_rules_id}, auth_ids, 4, 5);
        auto const envelope = make_envelope(room_id, "$sjceiling:remote.example.org", "m.room.member",
                                            std::string{"@bob:remote.example.org"}, "@bob:remote.example.org",
                                            {genesis.join_rules_id}, auth_ids, 4, json);
        auto& store = started.runtime.database.persistent_store;
        store.next_sync_stream_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());

        WHEN("the send_join arrives")
        {
            auto const result = started.runtime.federation.membership_acceptor(
                merovingian::federation::FederationEndpoint::send_join, room_id, envelope.event_id, envelope);

            THEN("the peer is told it failed")
            {
                REQUIRE_FALSE(result.accepted);
                REQUIRE(result.status == 500U);
            }

            THEN("the event and the membership were not stored")
            {
                REQUIRE_FALSE(store.events.contains(envelope.event_id));
                REQUIRE(std::ranges::none_of(store.memberships, [](auto const& row) {
                    return row.user_id == "@bob:remote.example.org";
                }));
            }
        }
        std::filesystem::remove(path);
    }
}
