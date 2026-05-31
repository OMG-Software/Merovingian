// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |        FEDERATED INVITE-THEN-JOIN CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18                                   |
// |  URL:  https://spec.matrix.org/v1.18/server-server-api/#joining-rooms   |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix spec or a   |
// |  hard correctness invariant. If a test fails:                            |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |       spec itself has changed and citing the updated section.            |
// |                                                                         |
// |  These tests guard three bugs that caused Synapse to reject joins with  |
// |  "403: You are not invited to this room":                                |
// |                                                                         |
// |  1. membership_template_provider did not populate auth_events on the    |
// |     make_join template, so the joining server signed a PDU with empty   |
// |     auth_events that could not be validated.                             |
// |  2. membership_acceptor did not copy auth_event_ids from the envelope   |
// |     to the persisted event, breaking the BFS auth-chain walk.           |
// |  3. invite_handler did not store the invite in store.events/state, so   |
// |     for inbound-invite cases the event was unreachable during BFS.      |
// +-------------------------------------------------------------------------+

#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

// Default server name from config::ServerConfig{} is "example.org"
auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "invite-join-test-seed";

[[nodiscard]] auto remote_for_test() -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = remote_origin;
    remote.signing_key = {remote_origin, remote_key_id, 2000U,
                          merovingian::federation::test::keypair_from_seed(remote_key_seed).public_key};
    remote.discovery.server_name = remote_origin;
    remote.discovery.well_known_host = remote_origin;
    remote.discovery.resolved_host = remote_origin;
    remote.discovery.resolved_addresses = {"203.0.113.10"};
    remote.discovery.tls_required = true;
    remote.trust.reputation_score = 100U;
    return remote;
}

[[nodiscard]] auto signed_get(std::string const& target) -> merovingian::federation::SignedFederationRequest
{
    auto req = merovingian::federation::SignedFederationRequest{};
    req.method = "GET";
    req.target = target;
    req.origin = remote_origin;
    req.destination = local_server;
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = "";
    req.signature = merovingian::federation::make_federation_signature(
        remote_origin, req.destination, req.method, target, req.body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

[[nodiscard]] auto signed_put(std::string const& target, std::string const& body)
    -> merovingian::federation::SignedFederationRequest
{
    auto req = merovingian::federation::SignedFederationRequest{};
    req.method = "PUT";
    req.target = target;
    req.origin = remote_origin;
    req.destination = local_server;
    req.key_id = remote_key_id;
    req.now_ts = 1000U;
    req.canonical_json_verified = true;
    req.body = body;
    req.signature = merovingian::federation::make_federation_signature(
        remote_origin, req.destination, req.method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

// Plant an invite event directly into the store (simulates a local user
// inviting a remote user, which goes through room_service and stores the
// event normally).
auto plant_invite_event(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                        std::string const& sender_user_id, std::string const& invited_user_id,
                        std::string const& invite_event_id) -> void
{
    auto pdu = merovingian::database::PersistentEvent{};
    pdu.event_id = invite_event_id;
    pdu.room_id = room_id;
    pdu.sender_user_id = sender_user_id;
    pdu.json =
        std::string{R"({"type":"m.room.member","state_key":")"} + invited_user_id +
        R"(","content":{"membership":"invite"},"room_id":")" + room_id + R"(","sender":")" + sender_user_id +
        R"(","event_id":")" + invite_event_id +
        R"(","depth":5,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},"origin_server_ts":1000})";
    pdu.depth = 5U;
    pdu.stream_ordering = runtime.database.next_stream_ordering++;
    auto state = std::optional<merovingian::database::PersistentStateEvent>{
        merovingian::database::PersistentStateEvent{room_id, "m.room.member", invited_user_id, invite_event_id}};
    REQUIRE(merovingian::database::store_event_with_state(runtime.database.persistent_store, std::move(pdu),
                                                          std::move(state)));
}

} // namespace

// --- make_join auth_events ---------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_joinroomiduserid
//
// The resident server MUST include in the template's auth_events:
//   - m.room.create
//   - m.room.join_rules
//   - m.room.power_levels (if present)
//   - m.room.member for the joining user (their current invite state)
//
// Omitting the invite event from auth_events causes the remote server to
// sign a join PDU with empty auth_events which then fails the receiving
// homeserver's authorization check with "403: You are not invited to this room".
SCENARIO("make_join template includes the invite event in auth_events for an invited user",
         "[homeserver][federation][invite-join][make_join][spec]")
{
    GIVEN("a room with a pending invite for a remote user stored in the event graph")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@bob:"} + remote_origin;
        auto const invite_event_id = std::string{"$test_invite_event:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join for the invited user")
        {
            auto const target =
                "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the response is 200 and the template body contains the invite event ID in auth_events")
            {
                // Spec MUST: auth_events in the join template must reference the
                // m.room.member invite event for the joining user. Without this
                // the joining server produces a PDU with empty auth_events that
                // remote homeservers (e.g. Synapse) will reject as unauthorized.
                // Do NOT remove — removing this test hides the root cause of
                // "403: You are not invited to this room" on federated joins.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(invite_event_id) != std::string::npos);
                REQUIRE(response.body.find(R"("auth_events")") != std::string::npos);
            }
        }
    }
}

// --- send_join auth_chain ----------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventid
//
// The resident server MUST return an auth_chain that includes ALL events
// referenced in the join PDU's auth_events. When the joining user was
// invited, the invite event MUST appear in the auth_chain.
//
// If auth_event_ids from the inbound PDU envelope are not copied to the
// persisted PersistentEvent, the BFS walk cannot follow auth links and
// the invite event is excluded from the auth_chain.
SCENARIO("send_join auth_chain includes the invite event when the join PDU references it",
         "[homeserver][federation][invite-join][send_join][spec]")
{
    GIVEN("a room where a remote user has a pending invite and calls send_join with it in auth_events")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host2", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@carol:"} + remote_origin;
        auto const invite_event_id = std::string{"$test_invite_carol:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const join_event_id = std::string{"$test_join_carol:remote.example.org"};

        // Join PDU with auth_events referencing the invite event.
        // This simulates what a conformant remote server (e.g. Synapse) sends
        // after receiving a make_join template with the correct auth_events.
        auto const join_body =
            std::string{R"({"type":"m.room.member","room_id":")"} + room_id +
            R"(","sender":")" + remote_user + R"(","state_key":")" + remote_user +
            R"(","content":{"membership":"join"},"depth":6,)" +
            R"("hashes":{"sha256":"x"},"origin_server_ts":2000,)" +
            R"("prev_events":[],"auth_events":[")" + invite_event_id +
            R"("],"signatures":{"remote.example.org":{"ed25519:auto":"aaaa"}}})";

        WHEN("the remote server calls send_join with the join PDU")
        {
            auto const target =
                "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation,
                                                                           signed_put(target, join_body));

            THEN("the response is 200 and auth_chain includes the invite event JSON")
            {
                // Spec MUST: the auth_chain must include every event reachable
                // via auth_events links from the current room state. The invite
                // event is reachable from the join event's auth_events and must
                // appear so Synapse can validate the join authorization.
                // Do NOT remove — this test guards the auth_event_ids copy fix.
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find(invite_event_id) != std::string::npos);
                REQUIRE(response.body.find(R"("auth_chain")") != std::string::npos);
            }
        }
    }
}

// --- invite_handler event persistence ----------------------------------------
// Spec: Matrix Server-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2inviteroomideventid
//
// The resident server MUST store accepted invite events in its persistent
// event graph so that:
//   (a) make_join can include it in auth_events, and
//   (b) the auth-chain BFS can find and return it in send_join responses.
//
// Storing only in store.invites (for sync) but not store.events means
// the event is invisible to the auth-chain walk.
SCENARIO("invite_handler stores the signed invite event in the persistent event graph",
         "[homeserver][federation][invite-join][invite][spec]")
{
    GIVEN("a started runtime with a local user and a remote server sends an invite")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        // Register the local user who will be invited
        auto const local_user = merovingian::homeserver::register_local_user(runtime, "invited_user",
                                                                             "CorrectHorse7!",
                                                                             merovingian::tests::registration_token);
        REQUIRE(local_user.ok);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const room_id = std::string{"!invite_test_room:remote.example.org"};
        auto const invite_event_id = std::string{"$invite_for_local:remote.example.org"};
        auto const target_user = local_user.value; // @invited_user:example.org

        // v2 invite body: {room_version, event, invite_room_state}
        auto const invite_body =
            std::string{R"({"room_version":"12","event":{"type":"m.room.member","state_key":")"} +
            target_user +
            R"(","content":{"membership":"invite"},"room_id":")" + room_id +
            R"(","sender":"@remote_host:remote.example.org","event_id":")" + invite_event_id +
            R"(","depth":1,"prev_events":[],"auth_events":[],"hashes":{"sha256":"x"},)" +
            R"("origin_server_ts":1000,"signatures":{"remote.example.org":{"ed25519:auto":"aaaa"}}},)" +
            R"("invite_room_state":[]})";

        WHEN("the remote server sends the invite via PUT /_matrix/federation/v2/invite/...")
        {
            auto const path = "/_matrix/federation/v2/invite/" + room_id + "/" + invite_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(path, invite_body));

            THEN("the invite is accepted and the event is stored in the persistent event graph")
            {
                // Spec MUST: after accepting an invite, the resident server must
                // have the invite event available for auth-chain construction.
                // If it is only stored in store.invites, subsequent send_join
                // calls cannot find it during BFS and return an incomplete auth_chain.
                // Do NOT remove — this test guards the invite_handler storage fix.
                REQUIRE(response.status == 200U);
                auto const& events = runtime.database.persistent_store.events;
                auto const found = std::any_of(events.begin(), events.end(), [&](auto const& e) {
                    return e.event_id == invite_event_id;
                });
                REQUIRE(found);

                // Also verify the invite appears in store.state for the user,
                // so make_join can include it in auth_events lookups.
                auto const& state = runtime.database.persistent_store.state;
                auto const in_state = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" &&
                           s.state_key == target_user && s.event_id == invite_event_id;
                });
                REQUIRE(in_state);
            }
        }
    }
}

// --- make_join depth > 0 -----------------------------------------------------
// Spec: Matrix Server-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_joinroomiduserid
//
// The make_join template MUST include depth = max(forward-extremity depths) + 1.
// Leaving it at 0 causes the joining server to produce a join event at depth=0
// which Synapse rejects internally and returns 500 to its joining client,
// causing an infinite make_join/send_join retry loop.
SCENARIO("make_join template has depth greater than zero when the room already has events",
         "[homeserver][federation][invite-join][make_join][spec]")
{
    GIVEN("a room with events already stored at depth > 0")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host3", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const& store = runtime.database.persistent_store;
        auto const max_stored = std::max_element(store.events.begin(), store.events.end(),
                                                 [](auto const& a, auto const& b) { return a.depth < b.depth; });
        REQUIRE(max_stored != store.events.end());
        REQUIRE(max_stored->depth > 0U);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join")
        {
            auto const remote_user = std::string{"@alice:"} + remote_origin;
            auto const target =
                "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the template event has depth > 0")
            {
                // Spec MUST: depth must reflect the room's forward extremity depth.
                // depth=0 makes Synapse produce a join event at depth=0 which is
                // rejected during state resolution → 500 on the client join call.
                // Do NOT remove — guards the bug where tmpl.depth was never set.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const ev_it =
                    std::ranges::find_if(*root, [](auto const& m) { return m.key == "event"; });
                REQUIRE(ev_it != root->end());
                auto const* ev_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&ev_it->value->storage());
                REQUIRE(ev_obj != nullptr);
                auto const depth_it =
                    std::ranges::find_if(*ev_obj, [](auto const& m) { return m.key == "depth"; });
                REQUIRE(depth_it != ev_obj->end());
                auto const* depth_val =
                    std::get_if<std::int64_t>(&depth_it->value->storage());
                REQUIRE(depth_val != nullptr);
                REQUIRE(*depth_val > 0);
            }
        }
    }
}

// --- make_join prev_events = forward extremities only ------------------------
// Spec: Matrix Server-Server API v1.18
//
// The make_join template prev_events MUST contain only the room's current
// forward extremities (events not yet referenced as another event's prev_events).
// Including all room events inflates the state snapshot on every retry and
// breaks state resolution for the joining server.
SCENARIO("make_join template prev_events contains only forward extremities, not all room events",
         "[homeserver][federation][invite-join][make_join][spec]")
{
    GIVEN("a room with a linear event chain producing exactly one forward extremity")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host4", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const& store = runtime.database.persistent_store;
        auto const room_event_count = static_cast<std::size_t>(std::count_if(
            store.events.begin(), store.events.end(),
            [&](auto const& e) { return e.room_id == room_id; }));
        REQUIRE(room_event_count > 1U);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join")
        {
            auto const remote_user = std::string{"@dave:"} + remote_origin;
            auto const target =
                "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("prev_events is exactly one entry — the forward extremity — not all events")
            {
                // Spec MUST: prev_events must be the current forward extremities.
                // The bug caused every stored event to be pushed into prev_events,
                // inflating the state snapshot sent to the joining server on each
                // retry and making state resolution produce incorrect results.
                // Do NOT remove — guards the bug where all store.events were used.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const ev_it =
                    std::ranges::find_if(*root, [](auto const& m) { return m.key == "event"; });
                REQUIRE(ev_it != root->end());
                auto const* ev_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&ev_it->value->storage());
                REQUIRE(ev_obj != nullptr);
                auto const prev_it =
                    std::ranges::find_if(*ev_obj, [](auto const& m) { return m.key == "prev_events"; });
                REQUIRE(prev_it != ev_obj->end());
                auto const* prev_arr =
                    std::get_if<merovingian::canonicaljson::Array>(&prev_it->value->storage());
                REQUIRE(prev_arr != nullptr);
                REQUIRE(prev_arr->size() == 1U);
                REQUIRE(prev_arr->size() < room_event_count);
            }
        }
    }
}

// --- send_join response requires members_omitted -----------------------------
// Spec: Matrix Server-Server API v1.18
// URL:  https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventid
//
// The send_join v2 response MUST include the `members_omitted` boolean field.
// Synapse parses this as a required field in SendJoinResponse; a missing field
// raises a KeyError and Synapse returns 500 to the joining client, which retries
// indefinitely via make_join / send_join.
SCENARIO("send_join response body includes the required members_omitted field",
         "[homeserver][federation][invite-join][send_join][spec]")
{
    GIVEN("a room with a pending invite for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host5", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@eve:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_eve:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const join_event_id = std::string{"$join_eve:remote.example.org"};
        auto const join_body =
            std::string{R"({"type":"m.room.member","room_id":")"} + room_id +
            R"(","sender":")" + remote_user + R"(","state_key":")" + remote_user +
            R"(","content":{"membership":"join"},"depth":6,)" +
            R"("hashes":{"sha256":"x"},"origin_server_ts":2000,)" +
            R"("prev_events":[],"auth_events":[")" + invite_event_id +
            R"("],"signatures":{"remote.example.org":{"ed25519:auto":"aaaa"}}})";

        WHEN("the remote server calls send_join with omit_members=true")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" +
                                join_event_id + "?omit_members=true";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join_body));

            THEN("the response body contains members_omitted set to false")
            {
                // Spec MUST: send_join v2 response must include members_omitted.
                // Synapse raises KeyError on a missing field and returns 500 to
                // the joining client, which then retries indefinitely.
                // Do NOT remove — guards the missing members_omitted wire format bug.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const mo_it = std::ranges::find_if(
                    *root, [](auto const& m) { return m.key == "members_omitted"; });
                REQUIRE(mo_it != root->end());
                auto const* mo_val = std::get_if<bool>(&mo_it->value->storage());
                REQUIRE(mo_val != nullptr);
                REQUIRE(*mo_val == false);
            }
        }
    }
}

// --- make_join auth_events must not contain create event for room v12 --------
// Spec: Matrix Server-Server API v1.18 / MSC4291 (room version 12)
// URL:  https://spec.matrix.org/v1.18/server-server-api/#get_matrixfederationv1make_joinroomiduserid
//
// In room version 12, the room ID is the reference hash of the m.room.create
// event, so the create event is NEVER listed in any event's auth_events.
// Synapse enforces this with an AssertionError in auth_event_ids():
//   assert create_event_id not in self._dict["auth_events"]
//
// If our make_join template includes the create event in auth_events, Synapse
// copies it into the join PDU it sends via send_join. We echo the join event
// back in the send_join response, and Synapse crashes with 500 processing it.
SCENARIO("make_join template auth_events does not include m.room.create for room v12",
         "[homeserver][federation][invite-join][make_join][spec]")
{
    GIVEN("a v12 room with a pending invite for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host6", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login =
            merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        // The default CreateRoomOptions uses room_version "12", so this room is v12.
        // Find the create event ID so we can assert it is absent from auth_events.
        auto const& store = runtime.database.persistent_store;
        auto create_event_id = std::string{};
        for (auto const& s : store.state)
        {
            if (s.room_id == room_id && s.event_type == "m.room.create")
            {
                create_event_id = s.event_id;
                break;
            }
        }
        REQUIRE(!create_event_id.empty());

        auto const remote_user = std::string{"@frank:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_frank:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join")
        {
            auto const target =
                "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the template auth_events does not contain the create event ID")
            {
                // Spec MUST (MSC4291 / room v12): the create event must never
                // appear in any event's auth_events. Synapse asserts this and
                // crashes with 500 if the create event is listed. The room ID
                // is the reference hash of the create event, so its presence
                // in auth_events is redundant and forbidden.
                // Do NOT remove — guards the v12 make_join create-event-in-auth
                // bug that caused Synapse AssertionError on every join attempt.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root =
                    std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const ev_it =
                    std::ranges::find_if(*root, [](auto const& m) { return m.key == "event"; });
                REQUIRE(ev_it != root->end());
                auto const* ev_obj =
                    std::get_if<merovingian::canonicaljson::Object>(&ev_it->value->storage());
                REQUIRE(ev_obj != nullptr);
                auto const auth_it =
                    std::ranges::find_if(*ev_obj, [](auto const& m) { return m.key == "auth_events"; });
                REQUIRE(auth_it != ev_obj->end());
                auto const* auth_arr =
                    std::get_if<merovingian::canonicaljson::Array>(&auth_it->value->storage());
                REQUIRE(auth_arr != nullptr);
                // The create event must not appear anywhere in auth_events
                auto const has_create = std::any_of(auth_arr->begin(), auth_arr->end(),
                    [&](auto const& v) {
                        auto const* s = std::get_if<std::string>(&v.storage());
                        return s != nullptr && *s == create_event_id;
                    });
                REQUIRE_FALSE(has_create);
                // The invite event must still be present
                auto const has_invite = std::any_of(auth_arr->begin(), auth_arr->end(),
                    [&](auto const& v) {
                        auto const* s = std::get_if<std::string>(&v.storage());
                        return s != nullptr && *s == invite_event_id;
                    });
                REQUIRE(has_invite);
            }
        }
    }
}
