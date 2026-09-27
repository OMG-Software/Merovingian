// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Decision D2 of the 0.12.13 handover (ADR-0071): main re-verifies the
// signature on every PDU a federation worker relays to it, with main's own
// remote_key_resolver, before anything is persisted. A compromised worker can
// otherwise inject events impersonating any sender the room's state
// authorises.
//
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Validating hashes and
// signatures on received events" (room versions 3 and later: the signature of
// the server the sender belongs to is required) and "Checks performed on
// receipt of a PDU", step 2 ("Passes signature checks, or else it is
// dropped").
//
// Each negative case runs in a room where the relayed event would otherwise be
// accepted; each has a correctly signed positive control.
// Tags: [worker_relay_signature].

#include "../federation_signing_test_support.hpp"
#include "../support/remote_room_fixture.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_ingestion.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/worker_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian;
using namespace merovingian::tests::remote_room;
using merovingian::federation::InboundPduEnvelope;
using merovingian::federation::PduIngestionStatus;

constexpr auto attacker_key_seed = "worker-relay-attacker-seed";

[[nodiscard]] auto string_array(std::vector<std::string> const& values) -> canonicaljson::Value
{
    auto array = canonicaljson::Array{};
    for (auto const& value : values)
    {
        array.push_back(canonicaljson::Value{value});
    }
    return canonicaljson::Value{std::move(array)};
}

// The wire frame a worker sends for pdu_ingest / membership_ingest, built from
// an envelope the way worker_event_loop.cpp's append_envelope_fields does.
// `type` is the frame type; `endpoint` is set for membership_ingest.
[[nodiscard]] auto envelope_frame(std::string_view type, InboundPduEnvelope const& env,
                                  std::optional<std::string> const& endpoint = std::nullopt) -> std::string
{
    auto obj = canonicaljson::Object{};
    obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{type}}));
    if (endpoint.has_value())
    {
        obj.push_back(canonicaljson::make_member("endpoint", canonicaljson::Value{*endpoint}));
    }
    obj.push_back(canonicaljson::make_member("event_id", canonicaljson::Value{env.event_id}));
    obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{env.room_id}));
    obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
    obj.push_back(canonicaljson::make_member("sender", canonicaljson::Value{env.sender}));
    obj.push_back(canonicaljson::make_member("event_type", canonicaljson::Value{env.event_type}));
    obj.push_back(canonicaljson::make_member("origin_server_ts", canonicaljson::Value{env.origin_server_ts}));
    obj.push_back(canonicaljson::make_member("depth", canonicaljson::Value{static_cast<std::int64_t>(env.depth)}));
    obj.push_back(canonicaljson::make_member("json", canonicaljson::Value{env.json}));
    obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{remote_server}}));
    if (env.state_key.has_value())
    {
        obj.push_back(canonicaljson::make_member("state_key", canonicaljson::Value{*env.state_key}));
    }
    obj.push_back(canonicaljson::make_member("auth_event_ids", string_array(env.auth_event_ids)));
    obj.push_back(canonicaljson::make_member("prev_event_ids", string_array(env.prev_event_ids)));
    obj.push_back(canonicaljson::make_member("signatures", canonicaljson::Value{canonicaljson::Array{}}));
    auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
    REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
    return serialized.output;
}

[[nodiscard]] auto parse_envelope(std::string const& signed_json) -> InboundPduEnvelope
{
    REQUIRE(!signed_json.empty());
    auto envelope = federation::parse_inbound_pdu_envelope(signed_json, room_version);
    REQUIRE(envelope.has_value());
    envelope->origin = remote_server;
    return *envelope;
}

[[nodiscard]] auto event_stored(homeserver::HomeserverRuntime const& runtime, std::string_view event_id) -> bool
{
    return std::ranges::any_of(runtime.database.persistent_store.events, [&](database::PersistentEvent const& e) {
        return e.event_id == event_id;
    });
}

[[nodiscard]] auto membership_of(homeserver::HomeserverRuntime const& runtime, std::string_view room_id,
                                 std::string_view user_id) -> std::string
{
    auto const& memberships = runtime.database.persistent_store.memberships;
    auto const it = std::ranges::find_if(memberships, [&](database::PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id;
    });
    return it == memberships.end() ? std::string{} : it->membership;
}

struct RemoteRoom final
{
    std::string room_id;

    [[nodiscard]] auto auth_event_ids() const -> std::vector<std::string>
    {
        return {room_id + ":create", room_id + ":pl", room_id + ":member:bob"};
    }
    [[nodiscard]] auto prev_event_ids() const -> std::vector<std::string>
    {
        return {room_id + ":member"};
    }
};

// The runtime stays where the scenario started it: wire_federation_callbacks
// captures its address, so it must never be moved afterwards.
[[nodiscard]] auto seed_remote_room(homeserver::HomeserverRuntime& runtime, std::string room_id) -> RemoteRoom
{
    homeserver::wire_federation_callbacks(runtime);
    seed_room_with_genesis_state_group(runtime, room_id);
    runtime.federation.remote_key_resolver = genuine_key_resolver();
    return RemoteRoom{std::move(room_id)};
}

[[nodiscard]] auto leave_json(RemoteRoom const& room, std::string_view key_seed) -> std::string
{
    auto content = canonicaljson::Object{};
    content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"leave"}}));
    return make_remote_event_json(room.room_id, "m.room.member", std::string{remote_member}, remote_member,
                                  std::move(content), room.prev_event_ids(), room.auth_event_ids(), 4, 50, key_seed);
}

} // namespace

SCENARIO("main re-verifies the signature of a /send PDU relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a room in which the remote member may post, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = seed_remote_room(runtime, "!relay-sig-send:local.example.org");

        WHEN("the worker relays a message signed with the sender server's genuine key")
        {
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 40));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is accepted and stored")
            {
                INFO("reason: " << result.reason);
                REQUIRE(result.status == PduIngestionStatus::accepted);
                REQUIRE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker relays a message signed with a key that is not the sender server's")
        {
            auto const env = parse_envelope(make_remote_message_json(room.room_id, room.prev_event_ids(),
                                                                     room.auth_event_ids(), 4, 41, attacker_key_seed));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: not accepted and not stored")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker relays a message whose sender key main cannot resolve")
        {
            runtime.federation.remote_key_resolver =
                [](std::string_view, std::string_view) -> std::optional<federation::FederationRemoteRuntime> {
                return std::nullopt;
            };
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 42));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: not accepted and not stored")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        WHEN("the worker's frame names a different event ID from the one the signed event hashes to")
        {
            auto env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 43));
            auto const genuine_event_id = env.event_id;
            env.event_id = "$forged-event-id";
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("it is dropped: nothing is stored under either ID")
            {
                REQUIRE(result.status != PduIngestionStatus::accepted);
                REQUIRE_FALSE(event_stored(runtime, "$forged-event-id"));
                REQUIRE_FALSE(event_stored(runtime, genuine_event_id));
            }
        }

        WHEN("the key must be resolved while another thread needs the runtime lock")
        {
            auto resolver_called = false;
            auto lock_was_free = false;
            runtime.federation.remote_key_resolver =
                [&](std::string_view server_name,
                    std::string_view key_id) -> std::optional<federation::FederationRemoteRuntime> {
                resolver_called = true;
                // A real resolver may block on the network here. Another
                // thread must be able to take the runtime lock meanwhile.
                auto probe = std::thread{[&]() {
                    lock_was_free = runtime.mutex.try_lock();
                    if (lock_was_free)
                    {
                        runtime.mutex.unlock();
                    }
                }};
                probe.join();
                return genuine_key_resolver()(server_name, key_id);
            };
            auto const env = parse_envelope(
                make_remote_message_json(room.room_id, room.prev_event_ids(), room.auth_event_ids(), 4, 44));
            auto const result = homeserver::handle_pdu_ingest_request(runtime, envelope_frame("pdu_ingest", env));

            THEN("main resolved the key itself, without holding the runtime lock, and accepted the PDU")
            {
                REQUIRE(resolver_called);
                REQUIRE(lock_was_free);
                REQUIRE(result.status == PduIngestionStatus::accepted);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("main re-verifies the signature of a send_leave relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a room in which the remote member has joined, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = seed_remote_room(runtime, "!relay-sig-leave:local.example.org");

        WHEN("the worker relays the member's leave signed with the sender server's genuine key")
        {
            auto const env = parse_envelope(leave_json(room, remote_key_seed));
            auto const response = homeserver::handle_membership_ingest_request(
                runtime, envelope_frame("membership_ingest", env, std::string{"send_leave"}));

            THEN("the leave is accepted and the member has left")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(membership_of(runtime, room.room_id, remote_member) == "leave");
            }
        }

        WHEN("the worker relays a leave for the member signed with a key that is not the sender server's")
        {
            auto const env = parse_envelope(leave_json(room, attacker_key_seed));
            auto const response = homeserver::handle_membership_ingest_request(
                runtime, envelope_frame("membership_ingest", env, std::string{"send_leave"}));

            THEN("it is refused and the member is still joined")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(membership_of(runtime, room.room_id, remote_member) == "join");
                REQUIRE_FALSE(event_stored(runtime, env.event_id));
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("main re-verifies the signature of an invite relayed by a federation worker",
         "[integration][federation-worker][worker_relay_signature]")
{
    GIVEN("a local user, and main knowing the remote server's genuine key")
    {
        auto const path = unique_sqlite_path("merovingian-worker-relay-sig-");
        std::filesystem::remove(path);
        auto started = homeserver::start_runtime(config_with_sqlite(path));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        std::ignore = seed_remote_room(runtime, "!relay-sig-invite-host:local.example.org");
        auto const invitee = std::string{"@alice:"} + local_server;
        runtime.database.users.push_back({invitee, "", false, false, false});
        auto const remote_room_id = std::string{"!remote-room:remote.example.org"};

        auto const invite_frame = [&](std::string_view key_seed) {
            auto content = canonicaljson::Object{};
            content.push_back(canonicaljson::make_member("membership", canonicaljson::Value{std::string{"invite"}}));
            auto const event_json =
                make_remote_event_json(remote_room_id, "m.room.member", invitee, remote_member, std::move(content),
                                       {"$remote-prev"}, {"$remote-create"}, 5, 60, key_seed);
            auto obj = canonicaljson::Object{};
            obj.push_back(canonicaljson::make_member("type", canonicaljson::Value{std::string{"invite_ingest"}}));
            obj.push_back(canonicaljson::make_member("room_id", canonicaljson::Value{remote_room_id}));
            obj.push_back(
                canonicaljson::make_member("event_id", canonicaljson::Value{parse_envelope(event_json).event_id}));
            obj.push_back(canonicaljson::make_member("room_version", canonicaljson::Value{std::string{room_version}}));
            obj.push_back(canonicaljson::make_member("invite_event_json", canonicaljson::Value{event_json}));
            obj.push_back(canonicaljson::make_member("origin", canonicaljson::Value{std::string{remote_server}}));
            obj.push_back(
                canonicaljson::make_member("invite_room_state_json", canonicaljson::Value{canonicaljson::Array{}}));
            auto const serialized = canonicaljson::serialize_canonical(canonicaljson::Value{std::move(obj)});
            REQUIRE(serialized.error == canonicaljson::CanonicalJsonError::none);
            return serialized.output;
        };

        WHEN("the worker relays an invite signed with the sender server's genuine key")
        {
            auto const response = homeserver::handle_invite_ingest_request(runtime, invite_frame(remote_key_seed));

            THEN("the invite is accepted and recorded")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":true)") != std::string::npos);
                REQUIRE(membership_of(runtime, remote_room_id, invitee) == "invite");
            }
        }

        WHEN("the worker relays an invite signed with a key that is not the sender server's")
        {
            auto const response = homeserver::handle_invite_ingest_request(runtime, invite_frame(attacker_key_seed));

            THEN("it is refused and no invite is recorded")
            {
                INFO("response: " << response);
                REQUIRE(response.find(R"("accepted":false)") != std::string::npos);
                REQUIRE(membership_of(runtime, remote_room_id, invitee).empty());
            }
        }

        std::filesystem::remove(path);
    }
}
