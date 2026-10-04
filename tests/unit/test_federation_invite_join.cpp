// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |        FEDERATED INVITE-THEN-JOIN CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#joining-rooms   |
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

#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <sodium.h>

#if defined(__NetBSD__)
[[maybe_unused]] inline auto merovingian_netbsd_diag(std::string_view const msg) -> void
{
    std::cerr << "[netbsd-diag] " << msg << '\n' << std::flush;
}
#else
[[maybe_unused]] inline auto merovingian_netbsd_diag(std::string_view const /*msg*/) -> void
{
}
#endif

#define MEROVINGIAN_NETBSD_DIAG(msg) merovingian_netbsd_diag(msg)

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
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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
    remote.signing_key = {remote_origin, remote_key_id, 4'102'444'800'000U,
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

// Build a properly signed m.room.member join PDU from the remote server.
// The event is signed with the same key_seed used by remote_for_test(), so
// authorize_federation_pdu can verify the Ed25519 signature against the
// remote's signing_key. The content hash is computed and attached by
// sign_event_for_server, so verify_pdu_content_hash also passes.
[[nodiscard]] auto json_id_array(std::vector<std::string> const& ids) -> std::string
{
    auto out = std::string{"["};
    for (std::size_t i = 0U; i < ids.size(); ++i)
    {
        if (i != 0U)
        {
            out += ',';
        }
        out += "\"" + ids[i] + "\"";
    }
    out += "]";
    return out;
}

// prev_events and auth_events default to empty only for the few scenarios
// that deliberately send a malformed event; every realistic join passes the
// room's forward extremities and the selected auth events (ADR-0064 phase
// B2 authorises an inbound membership against both).
struct SignedJoinBody final
{
    std::string body{};
    std::string event_id{};
};

[[nodiscard]] auto make_signed_join_body(std::string const& room_id, std::string const& sender,
                                         std::vector<std::string> const& auth_events = {},
                                         std::vector<std::string> const& prev_events = {}) -> SignedJoinBody
{
    auto const auth_json = json_id_array(auth_events);
    auto const prev_json = json_id_array(prev_events);

    auto const unsigned_json =
        std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
        "\",\"state_key\":\"" + sender + "\",\"content\":{\"membership\":\"join\"},\"depth\":6," +
        "\"origin_server_ts\":2000,\"prev_events\":" + prev_json + ",\"auth_events\":" + auth_json + "}";

    auto const body = merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin, remote_key_id,
                                                                          remote_key_seed, "12");
    auto const parsed = merovingian::canonicaljson::parse_lossless(body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    auto const id = merovingian::events::make_reference_hash_event_id(parsed.value, *policy);
    return {body, id.event_id};
}

struct SignedInvite final
{
    std::string body{};
    std::string event_id{};
};

[[nodiscard]] auto make_signed_invite(std::string const& room_id, std::string const& sender,
                                      std::string const& state_key, std::string const& room_version = "12")
    -> SignedInvite
{
    auto const unsigned_json = std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id +
                               "\",\"sender\":\"" + sender + "\",\"state_key\":\"" + state_key +
                               "\",\"content\":{\"membership\":\"invite\"},\"depth\":1," +
                               "\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[]}";
    auto const signed_event = merovingian::federation::test::make_signed_event_json(
        unsigned_json, remote_origin, remote_key_id, remote_key_seed, room_version);
    auto const parsed = merovingian::canonicaljson::parse_lossless(signed_event);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* policy = merovingian::rooms::find_room_version_policy(room_version);
    REQUIRE(policy != nullptr);
    auto const id = merovingian::events::make_reference_hash_event_id(parsed.value, *policy);
    return {"{\"room_version\":\"" + room_version + "\",\"event\":" + signed_event + ",\"invite_room_state\":[]}",
            id.event_id};
}

// Plant an invite event directly into the store (simulates a local user
// inviting a remote user, which goes through room_service and stores the
// event normally).
auto plant_invite_event(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                        std::string const& sender_user_id, std::string const& invited_user_id,
                        std::string const& invite_event_id) -> void
{
    using namespace merovingian;

    auto& store = runtime.database.persistent_store;
    auto const* policy = rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);

    auto const prev_events = tests::fixture_prev_event_ids(store, room_id);
    auto const auth_events = tests::fixture_auth_event_ids(store, room_id, sender_user_id, true);

    auto pdu = database::PersistentEvent{};
    pdu.event_id = invite_event_id;
    pdu.room_id = room_id;
    pdu.sender_user_id = sender_user_id;
    pdu.prev_event_ids = prev_events;
    pdu.auth_event_ids = auth_events;
    pdu.json =
        std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + invited_user_id +
        "\",\"content\":{\"membership\":\"invite\"},\"room_id\":\"" + room_id + "\",\"sender\":\"" + sender_user_id +
        "\",\"event_id\":\"" + invite_event_id + "\",\"depth\":5,\"prev_events\":" + json_id_array(prev_events) +
        ",\"auth_events\":" + json_id_array(auth_events) + ",\"hashes\":{\"sha256\":\"x\"},\"origin_server_ts\":1000}";
    pdu.depth = 5U;
    pdu.stream_ordering = runtime.database.next_stream_ordering++;
    auto state = std::optional<database::PersistentStateEvent>{
        database::PersistentStateEvent{room_id, "m.room.member", invited_user_id, invite_event_id}
    };
    REQUIRE(database::store_event_with_state(store, std::move(pdu), std::move(state)));

    auto const state_before = homeserver::compute_state_before(store, room_id, *policy, prev_events);
    REQUIRE(state_before.ok);
    auto const state_after =
        homeserver::compute_state_after(state_before.state, invite_event_id, "m.room.member", invited_user_id);
    auto const group = homeserver::record_event_state(store, room_id, invite_event_id, prev_events, state_after, true);
    REQUIRE(group.has_value());
    REQUIRE(homeserver::recompute_current_state(store, room_id, *policy));

    store.memberships.push_back({room_id, invited_user_id, "invite", 0U});
}

} // namespace

namespace
{

// Navigate a JSON object and return a raw pointer to the Value for `key`.
// Returns nullptr if the key is absent.
[[nodiscard]] auto json_get(merovingian::canonicaljson::Object const& obj, std::string const& key)
    -> merovingian::canonicaljson::Value const*
{
    for (auto const& m : obj)
        if (m.key == key)
            return &(*m.value);
    return nullptr;
}

// Extract the auth_events Array from a make_join response root object.
// Returns nullptr on any navigation failure.
[[nodiscard]] auto extract_auth_events(merovingian::canonicaljson::Object const& root)
    -> merovingian::canonicaljson::Array const*
{
    auto const* ev_val = json_get(root, "event");
    if (ev_val == nullptr)
        return nullptr;
    auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev_val->storage());
    if (ev_obj == nullptr)
        return nullptr;
    auto const* auth_val = json_get(*ev_obj, "auth_events");
    if (auth_val == nullptr)
        return nullptr;
    return std::get_if<merovingian::canonicaljson::Array>(&auth_val->storage());
}

// Return true if `arr` (an array of JSON strings) contains `target`.
[[nodiscard]] auto array_contains_string(merovingian::canonicaljson::Array const& arr, std::string const& target)
    -> bool
{
    return std::any_of(arr.begin(), arr.end(), [&](auto const& v) {
        auto const* s = std::get_if<std::string>(&v.storage());
        return s != nullptr && *s == target;
    });
}

} // namespace

// --- NetBSD SIGABRT diagnostic -----------------------------------------------
// The NetBSD CI job aborts during the first federation invite-join scenario.
// Catch2 attributes fatal signals to the last active assertion, which is the
// sodium_init() check, so the real crash site is somewhere between that check
// and the next assertion. This minimal scenario isolates start_runtime() so we
// can tell whether the abort is inside start_runtime() or in the scenario body.
// TODO: remove once the NetBSD abort is diagnosed and fixed.
SCENARIO("diagnostic: start_runtime does not abort on NetBSD", "[netbsd][diagnostic][start_runtime][temporary]")
{
    GIVEN("a registration-enabled config")
    {
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
    }
}

// --- make_join auth_events ---------------------------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
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
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
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
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* auth_arr = extract_auth_events(*root);
                REQUIRE(auth_arr != nullptr);
                REQUIRE(array_contains_string(*auth_arr, invite_event_id));
            }
        }
    }
}

// --- send_join auth_chain ----------------------------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@carol:"} + remote_origin;
        auto const invite_event_id = std::string{"$test_invite_carol:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        // Join PDU with auth_events referencing the invite event.
        // This simulates what a conformant remote server (e.g. Synapse) sends
        // after receiving a make_join template with the correct auth_events.
        auto const& fixture_store = runtime.database.persistent_store;
        auto const join_auth_ids =
            merovingian::tests::fixture_auth_event_ids(fixture_store, room_id, remote_user, true);
        auto const join = make_signed_join_body(
            room_id, remote_user, join_auth_ids, merovingian::tests::fixture_prev_event_ids(fixture_store, room_id));

        WHEN("the remote server calls send_join with the join PDU")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join.body));

            THEN("the response is 200 and auth_chain includes the invite event JSON")
            {
                // Spec MUST: the auth_chain must include every event reachable
                // via auth_events links from the current room state. The invite
                // event is reachable from the join event's auth_events and must
                // appear so Synapse can validate the join authorization.
                // Do NOT remove — this test guards the auth_event_ids copy fix.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* chain_val = json_get(*root, std::string{"auth_chain"});
                REQUIRE(chain_val != nullptr);
                auto const* chain_arr = std::get_if<merovingian::canonicaljson::Array>(&chain_val->storage());
                REQUIRE(chain_arr != nullptr);
                // Find invite event in auth_chain by looking at each PDU's event_id field
                auto const has_invite = std::any_of(chain_arr->begin(), chain_arr->end(), [&](auto const& v) {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                    if (obj == nullptr)
                        return false;
                    auto const* eid_val = json_get(*obj, std::string{"event_id"});
                    if (eid_val == nullptr)
                        return false;
                    auto const* eid = std::get_if<std::string>(&eid_val->storage());
                    return eid != nullptr && *eid == invite_event_id;
                });
                REQUIRE(has_invite);
            }
        }
    }
}

// --- invite_handler event persistence ----------------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid
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
        auto const local_user = merovingian::homeserver::register_local_user(runtime, "invited_user", "CorrectHorse7!",
                                                                             merovingian::tests::registration_token);
        REQUIRE(local_user.ok);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const room_id = std::string{"!invite_test_room:remote.example.org"};
        auto const target_user = local_user.value; // @invited_user:example.org

        // v2 invite body: {room_version, event, invite_room_state}
        // The event is properly signed by the remote server so it passes
        // the PDU verification pipeline (signature + content hash + origin check).
        // The URL event ID must be the event's own reference-hash ID (audit FED-5).
        auto const signed_invite = make_signed_invite(room_id, "@remote_host:remote.example.org", target_user);
        auto const invite_body = signed_invite.body;
        auto const invite_event_id = signed_invite.event_id;

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
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == target_user &&
                           s.event_id == invite_event_id;
                });
                REQUIRE(in_state);
            }
        }
    }
}

// --- make_join depth > 0 -----------------------------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const& store = runtime.database.persistent_store;
        auto const max_stored =
            std::max_element(store.events.begin(), store.events.end(), [](auto const& a, auto const& b) {
                return a.depth < b.depth;
            });
        REQUIRE(max_stored != store.events.end());
        REQUIRE(max_stored->depth > 0U);
        // Capture before make_join so we have the expected template depth.
        auto const max_depth_before = max_stored->depth;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join")
        {
            auto const remote_user = std::string{"@alice:"} + remote_origin;
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the template event has depth > 0")
            {
                // Spec MUST: depth must be exactly max(forward-extremity depths) + 1.
                // depth=0 makes Synapse produce a join event at depth=0 which is
                // rejected during state resolution → 500 on the client join call.
                // Do NOT remove — guards the bug where tmpl.depth was never set.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* ev_val = json_get(*root, std::string{"event"});
                REQUIRE(ev_val != nullptr);
                auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev_val->storage());
                REQUIRE(ev_obj != nullptr);
                auto const* depth_val = json_get(*ev_obj, std::string{"depth"});
                REQUIRE(depth_val != nullptr);
                auto const* depth_int = std::get_if<std::int64_t>(&depth_val->storage());
                REQUIRE(depth_int != nullptr);
                // Spec MUST: depth = max(forward-extremity depths) + 1.
                // After a linear create_room chain, the single extremity is at max_depth_before.
                REQUIRE(*depth_int == static_cast<std::int64_t>(max_depth_before) + 1);
            }
        }
    }
}

// --- make_join prev_events = forward extremities only ------------------------
// Spec: Matrix Server-Server API v1.19
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const& store = runtime.database.persistent_store;
        auto const room_event_count =
            static_cast<std::size_t>(std::count_if(store.events.begin(), store.events.end(), [&](auto const& e) {
                return e.room_id == room_id;
            }));
        REQUIRE(room_event_count > 1U);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join")
        {
            auto const remote_user = std::string{"@dave:"} + remote_origin;
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
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
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const ev_it = std::ranges::find_if(*root, [](auto const& m) {
                    return m.key == "event";
                });
                REQUIRE(ev_it != root->end());
                auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev_it->value->storage());
                REQUIRE(ev_obj != nullptr);
                auto const prev_it = std::ranges::find_if(*ev_obj, [](auto const& m) {
                    return m.key == "prev_events";
                });
                REQUIRE(prev_it != ev_obj->end());
                auto const* prev_arr = std::get_if<merovingian::canonicaljson::Array>(&prev_it->value->storage());
                REQUIRE(prev_arr != nullptr);
                REQUIRE(prev_arr->size() == 1U);
                REQUIRE(prev_arr->size() < room_event_count);
            }
        }
    }
}

// --- send_join response requires members_omitted -----------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@eve:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_eve:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const& fixture_store = runtime.database.persistent_store;
        auto const join_auth_ids =
            merovingian::tests::fixture_auth_event_ids(fixture_store, room_id, remote_user, true);
        auto const join = make_signed_join_body(
            room_id, remote_user, join_auth_ids, merovingian::tests::fixture_prev_event_ids(fixture_store, room_id));

        WHEN("the remote server calls send_join with omit_members=true")
        {
            auto const target =
                "/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id + "?omit_members=true";
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join.body));

            THEN("the response body contains members_omitted set to false")
            {
                // Spec MUST: send_join v2 response must include members_omitted.
                // Synapse raises KeyError on a missing field and returns 500 to
                // the joining client, which then retries indefinitely.
                // Do NOT remove — guards the missing members_omitted wire format bug.
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const mo_it = std::ranges::find_if(*root, [](auto const& m) {
                    return m.key == "members_omitted";
                });
                REQUIRE(mo_it != root->end());
                auto const* mo_val = std::get_if<bool>(&mo_it->value->storage());
                REQUIRE(mo_val != nullptr);
                REQUIRE(*mo_val == false);
            }
        }
    }
}

// --- make_join auth_events must not contain create event for room v12 --------
// Spec: Matrix Server-Server API v1.19 / MSC4291 (room version 12)
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
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
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
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
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
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
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* auth_arr = extract_auth_events(*root);
                REQUIRE(auth_arr != nullptr);
                REQUIRE_FALSE(array_contains_string(*auth_arr, create_event_id));
                REQUIRE(array_contains_string(*auth_arr, invite_event_id));
            }
        }
    }
}

// --- make_join response required top-level and event template fields ---------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
//
// A 200 response MUST contain:
//   room_version  — the room version string matching the room
//   event         — object with:
//     type                 == "m.room.member"
//     state_key            == the joining user ID
//     sender               == the joining user ID
//     room_id              == the target room ID
//     origin_server_ts     — integer timestamp
//     content.membership   == "join"
SCENARIO("make_join response contains all required top-level and event template fields",
         "[homeserver][federation][make_join][spec]")
{
    GIVEN("a v12 room and a remote server requesting a join template")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host7", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());
        auto const remote_user = std::string{"@grace:"} + remote_origin;

        WHEN("the remote server calls make_join")
        {
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the response body has room_version and a well-formed event template")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: room_version present and matches the room
                auto const* rv_val = json_get(*root, std::string{"room_version"});
                REQUIRE(rv_val != nullptr);
                auto const* rv_str = std::get_if<std::string>(&rv_val->storage());
                REQUIRE(rv_str != nullptr);
                REQUIRE(*rv_str == std::string{"12"});

                auto const* ev_val = json_get(*root, std::string{"event"});
                REQUIRE(ev_val != nullptr);
                auto const* ev_obj = std::get_if<merovingian::canonicaljson::Object>(&ev_val->storage());
                REQUIRE(ev_obj != nullptr);

                // Spec MUST: event.type == "m.room.member"
                auto const* type_val = json_get(*ev_obj, std::string{"type"});
                REQUIRE(type_val != nullptr);
                REQUIRE(*std::get_if<std::string>(&type_val->storage()) == std::string{"m.room.member"});

                // Spec MUST: event.state_key == joining user
                auto const* sk_val = json_get(*ev_obj, std::string{"state_key"});
                REQUIRE(sk_val != nullptr);
                REQUIRE(*std::get_if<std::string>(&sk_val->storage()) == remote_user);

                // Spec MUST: event.sender == joining user
                auto const* sender_val = json_get(*ev_obj, std::string{"sender"});
                REQUIRE(sender_val != nullptr);
                REQUIRE(*std::get_if<std::string>(&sender_val->storage()) == remote_user);

                // Spec MUST: event.room_id == target room
                auto const* rid_val = json_get(*ev_obj, std::string{"room_id"});
                REQUIRE(rid_val != nullptr);
                REQUIRE(*std::get_if<std::string>(&rid_val->storage()) == room_id);

                // Spec MUST: event.origin_server_ts present and numeric
                auto const* ts_val = json_get(*ev_obj, std::string{"origin_server_ts"});
                REQUIRE(ts_val != nullptr);
                REQUIRE(std::get_if<std::int64_t>(&ts_val->storage()) != nullptr);

                // Spec MUST: event.content.membership == "join"
                auto const* content_val = json_get(*ev_obj, std::string{"content"});
                REQUIRE(content_val != nullptr);
                auto const* content_obj = std::get_if<merovingian::canonicaljson::Object>(&content_val->storage());
                REQUIRE(content_obj != nullptr);
                auto const* mem_val = json_get(*content_obj, std::string{"membership"});
                REQUIRE(mem_val != nullptr);
                REQUIRE(*std::get_if<std::string>(&mem_val->storage()) == std::string{"join"});
            }
        }
    }
}

// --- make_join auth_events completeness for v12 --------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
//
// For a v12 room where the joining user has a pending invite, auth_events MUST:
//   - include the m.room.power_levels event ID
//   - include the m.room.join_rules event ID
//   - include the m.room.member (invite) event ID for the joining user
//   - NOT include the m.room.create event ID (forbidden in v12 / MSC4291)
SCENARIO("make_join auth_events includes power_levels and join_rules alongside the invite for v12",
         "[homeserver][federation][make_join][spec]")
{
    GIVEN("a v12 room with power_levels, join_rules, and a pending invite in state")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host8", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const& store = runtime.database.persistent_store;
        auto pl_event_id = std::string{};
        auto jr_event_id = std::string{};
        auto create_event_id = std::string{};
        for (auto const& s : store.state)
        {
            if (s.room_id != room_id)
                continue;
            if (s.event_type == std::string{"m.room.power_levels"})
                pl_event_id = s.event_id;
            else if (s.event_type == std::string{"m.room.join_rules"})
                jr_event_id = s.event_id;
            else if (s.event_type == std::string{"m.room.create"})
                create_event_id = s.event_id;
        }
        REQUIRE(!pl_event_id.empty());
        REQUIRE(!jr_event_id.empty());
        REQUIRE(!create_event_id.empty());

        auto const remote_user = std::string{"@henry:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_henry:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join for the invited user")
        {
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("auth_events contains power_levels and join_rules but not create")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* auth_arr = extract_auth_events(*root);
                REQUIRE(auth_arr != nullptr);

                // Spec MUST: power_levels in auth_events
                REQUIRE(array_contains_string(*auth_arr, pl_event_id));
                // Spec MUST: join_rules in auth_events
                REQUIRE(array_contains_string(*auth_arr, jr_event_id));
                // Spec MUST: invite in auth_events
                REQUIRE(array_contains_string(*auth_arr, invite_event_id));
                // Spec MUST NOT (v12/MSC4291): create not in auth_events
                REQUIRE_FALSE(array_contains_string(*auth_arr, create_event_id));
            }
        }
    }
}

// --- make_join returns 404 for unknown room -----------------------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
//
// If the room is not known to the resident server it MUST return 404.
SCENARIO("make_join returns 404 when the room does not exist on this server",
         "[homeserver][federation][make_join][spec]")
{
    GIVEN("a started runtime with no rooms created")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join for a non-existent room")
        {
            auto const remote_user = std::string{"@ivan:"} + remote_origin;
            auto const target =
                std::string{"/_matrix/federation/v1/make_join/!nonexistent:example.org/"} + remote_user + "?ver=12";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the response status is 404")
            {
                // Spec MUST: return 404 when the room is not known.
                REQUIRE(response.status == 404U);
            }
        }
    }
}

// --- make_join returns 400 M_INCOMPATIBLE_ROOM_VERSION -----------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1make_joinroomiduserid
//
// If the room version is not listed in the `ver` query parameters, the server
// MUST return 400 with errcode M_INCOMPATIBLE_ROOM_VERSION and a room_version
// field set to the actual room version.
SCENARIO("make_join returns 400 M_INCOMPATIBLE_ROOM_VERSION when the room version is not supported",
         "[homeserver][federation][make_join][spec]")
{
    GIVEN("a v12 room and a remote server that only supports room version 1")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host9", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the remote server calls make_join advertising only ver=1")
        {
            auto const remote_user = std::string{"@julia:"} + remote_origin;
            auto const target = "/_matrix/federation/v1/make_join/" + room_id + "/" + remote_user + "?ver=1";
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime.federation, signed_get(target));

            THEN("the response is 400 with M_INCOMPATIBLE_ROOM_VERSION and room_version field")
            {
                // Spec MUST: 400 M_INCOMPATIBLE_ROOM_VERSION when room version not
                // listed in ver parameters.  room_version field MUST be present.
                REQUIRE(response.status == 400U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* errcode_val = json_get(*root, std::string{"errcode"});
                REQUIRE(errcode_val != nullptr);
                auto const* errcode = std::get_if<std::string>(&errcode_val->storage());
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == std::string{"M_INCOMPATIBLE_ROOM_VERSION"});
                auto const* rv_val = json_get(*root, std::string{"room_version"});
                REQUIRE(rv_val != nullptr);
                auto const* rv = std::get_if<std::string>(&rv_val->storage());
                REQUIRE(rv != nullptr);
                REQUIRE(*rv == std::string{"12"});
            }
        }
    }
}

// --- send_join response required fields: origin, state, auth_chain -----------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// The send_join v2 response MUST include:
//   origin        — the resident server name
//   state         — non-empty array of current room state PDUs
//   auth_chain    — non-empty array of auth events
//   members_omitted — boolean (already guarded by earlier scenario)
SCENARIO("send_join response includes origin, non-empty state, and non-empty auth_chain",
         "[homeserver][federation][send_join][spec]")
{
    GIVEN("a room with a pending invite for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host10", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@kate:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_kate:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const& fixture_store = runtime.database.persistent_store;
        auto const join_auth_ids =
            merovingian::tests::fixture_auth_event_ids(fixture_store, room_id, remote_user, true);
        auto const join = make_signed_join_body(
            room_id, remote_user, join_auth_ids, merovingian::tests::fixture_prev_event_ids(fixture_store, room_id));

        WHEN("the remote server calls send_join")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join.body));

            THEN("the response contains origin, non-empty state, and non-empty auth_chain")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);

                // Spec MUST: origin == resident server name
                auto const* origin_val = json_get(*root, std::string{"origin"});
                REQUIRE(origin_val != nullptr);
                auto const* origin_str = std::get_if<std::string>(&origin_val->storage());
                REQUIRE(origin_str != nullptr);
                REQUIRE(*origin_str == std::string{local_server});

                // Spec MUST: state array, non-empty
                auto const* state_val = json_get(*root, std::string{"state"});
                REQUIRE(state_val != nullptr);
                auto const* state_arr = std::get_if<merovingian::canonicaljson::Array>(&state_val->storage());
                REQUIRE(state_arr != nullptr);
                REQUIRE(!state_arr->empty());

                // Spec MUST: auth_chain array, non-empty for a non-trivial room
                auto const* chain_val = json_get(*root, std::string{"auth_chain"});
                REQUIRE(chain_val != nullptr);
                auto const* chain_arr = std::get_if<merovingian::canonicaljson::Array>(&chain_val->storage());
                REQUIRE(chain_arr != nullptr);
                REQUIRE(!chain_arr->empty());
            }
        }
    }
}

// --- send_join state is PRE-JOIN (invite visible, join event absent) ---------
// Spec: Matrix Server-Server API v1.19 §11.5.1
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// The `state` field MUST represent the room state PRIOR TO the new join event.
// The joining user's m.room.member event in state must therefore show
// membership="invite" (not "join"), and the join event itself must NOT appear
// anywhere in the state array.
//
// If state contains the post-join snapshot, Synapse uses it to recalculate
// expected auth_events for the join, finds the join event as the current member
// state, and calculates that the join should reference itself — a circular
// dependency that triggers a Synapse WARNING and breaks auth chain validation.
SCENARIO("send_join state array reflects pre-join room state with membership invite for joining user",
         "[homeserver][federation][send_join][spec]")
{
    GIVEN("a room with a pending invite for a remote user")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "host11", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const remote_user = std::string{"@liam:"} + remote_origin;
        auto const invite_event_id = std::string{"$invite_liam:example.org"};
        plant_invite_event(runtime, room_id, user.value, remote_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const& fixture_store = runtime.database.persistent_store;
        auto const join_auth_ids =
            merovingian::tests::fixture_auth_event_ids(fixture_store, room_id, remote_user, true);
        auto const join = make_signed_join_body(
            room_id, remote_user, join_auth_ids, merovingian::tests::fixture_prev_event_ids(fixture_store, room_id));

        WHEN("the remote server calls send_join")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join.body));

            THEN("state shows the remote user as invited (pre-join) and the join event is absent from state")
            {
                REQUIRE(response.status == 200U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* state_val = json_get(*root, std::string{"state"});
                REQUIRE(state_val != nullptr);
                auto const* state_arr = std::get_if<merovingian::canonicaljson::Array>(&state_val->storage());
                REQUIRE(state_arr != nullptr);

                // Spec MUST: state is the room state PRIOR TO the join. The joining
                // user's m.room.member event must show membership="invite", not "join".
                // This prevents Synapse from recalculating the join event's auth_events
                // as referencing itself (a circular dependency it logs as a WARNING).
                auto const has_invite_member = std::any_of(state_arr->begin(), state_arr->end(), [&](auto const& v) {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                    if (obj == nullptr)
                        return false;
                    auto const* type_val = json_get(*obj, std::string{"type"});
                    if (type_val == nullptr)
                        return false;
                    auto const* type_str = std::get_if<std::string>(&type_val->storage());
                    if (type_str == nullptr || *type_str != std::string{"m.room.member"})
                        return false;
                    auto const* sk_val = json_get(*obj, std::string{"state_key"});
                    if (sk_val == nullptr)
                        return false;
                    auto const* sk_str = std::get_if<std::string>(&sk_val->storage());
                    if (sk_str == nullptr || *sk_str != remote_user)
                        return false;
                    auto const* content_val = json_get(*obj, std::string{"content"});
                    if (content_val == nullptr)
                        return false;
                    auto const* content_obj = std::get_if<merovingian::canonicaljson::Object>(&content_val->storage());
                    if (content_obj == nullptr)
                        return false;
                    auto const* mem_val = json_get(*content_obj, std::string{"membership"});
                    if (mem_val == nullptr)
                        return false;
                    auto const* mem_str = std::get_if<std::string>(&mem_val->storage());
                    return mem_str != nullptr && *mem_str == std::string{"invite"};
                });
                REQUIRE(has_invite_member);

                // The join event itself must NOT be in the state array.
                // If it were, Synapse calculates auth_events[m.room.member] = join event
                // then expects the join to reference itself — the circular bug.
                auto const join_in_state = std::any_of(state_arr->begin(), state_arr->end(), [&](auto const& v) {
                    auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                    if (obj == nullptr)
                        return false;
                    auto const* eid_val = json_get(*obj, std::string{"event_id"});
                    if (eid_val == nullptr)
                        return false;
                    auto const* eid_str = std::get_if<std::string>(&eid_val->storage());
                    return eid_str != nullptr && *eid_str == join.event_id;
                });
                REQUIRE_FALSE(join_in_state);
            }
        }
    }
}

// --- Invite must not downgrade existing "join" membership -------------------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2inviteroomideventid
//
// If a local user is already persistently "join" in a remote room (they joined
// via federation previously), and the remote server re-sends an invite (e.g.
// because their own state diverged), our server MUST NOT downgrade the
// membership from "join" to "invite". Doing so corrupts sync: the room
// disappears from rooms.join and reappears as an empty invite the user cannot
// dismiss, creating an infinite join-loop.
//
// Regression test for: federated invite handler calling upsert_membership
// unconditionally, overwriting "join" with "invite".
SCENARIO("federated invite does not downgrade an existing join membership to invite",
         "[homeserver][federation][invite-join][invite][regression]")
{
    GIVEN("a local user who is already persistently joined to a remote room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "already_joined", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const room_id = std::string{"!already_joined_room:remote.example.org"};
        auto const join_event_id = std::string{"$join_event_for_alice:remote.example.org"};

        // Inject the room into the persistent store and in-memory rooms, simulating
        // a successfully completed federation join that happened earlier.
        REQUIRE(merovingian::database::store_room(runtime.database.persistent_store, {room_id, user.value}));
        auto const join_stream = runtime.database.next_stream_ordering++;
        REQUIRE(merovingian::database::store_membership(runtime.database.persistent_store,
                                                        {room_id, user.value, "join", join_stream}) ==
                merovingian::database::MembershipStoreResult::stored);
        // Plant a join member-state event in store.state so joined_membership_changed_since
        // can find it (mirrors what the federation join path stores).
        {
            auto pdu = merovingian::database::PersistentEvent{};
            pdu.event_id = join_event_id;
            pdu.room_id = room_id;
            pdu.sender_user_id = user.value;
            pdu.json = "{\"type\":\"m.room.member\",\"state_key\":\"" + user.value +
                       "\",\"content\":{\"membership\":\"join\"},\"room_id\":\"" + room_id + "\",\"sender\":\"" +
                       user.value + "\",\"event_id\":\"" + join_event_id +
                       "\",\"depth\":10,\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"x\"},\"origin_"
                       "server_ts\":2000}";
            pdu.stream_ordering = join_stream;
            auto state = std::optional<merovingian::database::PersistentStateEvent>{
                merovingian::database::PersistentStateEvent{room_id, "m.room.member", user.value, join_event_id}
            };
            REQUIRE(merovingian::database::store_event_with_state(runtime.database.persistent_store, std::move(pdu),
                                                                  std::move(state)));
        }
        // Also add to in-memory rooms so find_room succeeds.
        runtime.database.rooms.push_back({room_id, user.value, {user.value}, {}});

        // Verify pre-condition: membership is "join".
        auto const& mems_before = runtime.database.persistent_store.memberships;
        auto const before_it = std::ranges::find_if(mems_before, [&](auto const& m) {
            return m.room_id == room_id && m.user_id == user.value;
        });
        REQUIRE(before_it != mems_before.end());
        REQUIRE(before_it->membership == "join");

        WHEN("the remote server re-sends a federated invite for the same user to the same room")
        {
            // Build a properly signed v2 invite body so the PDU verification
            // pipeline (signature + content hash) accepts it.
            auto const unsigned_invite_json = std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id +
                                              "\",\"sender\":\"@remote_host:remote.example.org\","
                                              "\"state_key\":\"" +
                                              user.value +
                                              "\",\"content\":{\"membership\":\"invite\"},\"depth\":5,"
                                              "\"origin_server_ts\":3000,\"prev_events\":[],\"auth_events\":[]}";
            auto const signed_invite_event = merovingian::federation::test::make_signed_event_json(
                unsigned_invite_json, remote_origin, remote_key_id, remote_key_seed, "10");
            auto const invite_body =
                std::string{"{\"room_version\":\"10\",\"event\":"} + signed_invite_event + ",\"invite_room_state\":[]}";

            // The URL event ID must be the event's own reference-hash ID (audit FED-5).
            auto const new_invite_event_id =
                merovingian::federation::test::reference_hash_event_id(signed_invite_event, "10");
            auto const path = "/_matrix/federation/v2/invite/" + room_id + "/" + new_invite_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(path, invite_body));

            THEN("the invite is accepted (signed and returned to the remote)")
            {
                // Spec MUST: the server MUST sign and return the invite event.
                REQUIRE(response.status == 200U);
            }

            THEN("the persistent membership is NOT downgraded from join to invite")
            {
                // The user is already a member. Overwriting "join" with "invite"
                // would corrupt sync: the room vanishes from rooms.join and the
                // user enters an infinite invite loop they cannot escape.
                auto const& mems_after = runtime.database.persistent_store.memberships;
                auto const after_it = std::ranges::find_if(mems_after, [&](auto const& m) {
                    return m.room_id == room_id && m.user_id == user.value;
                });
                REQUIRE(after_it != mems_after.end());
                // Spec MUST: membership MUST remain "join"; a stale invite from
                // the remote server MUST NOT overwrite a valid local join state.
                REQUIRE(after_it->membership == "join");
            }

            THEN("the m.room.member state entry still points to the join event, not the invite")
            {
                // If store.state is updated to point at the invite event,
                // joined_membership_changed_since returns false for the next sync
                // and the room is suppressed from rooms.join — it appears empty.
                auto const& state = runtime.database.persistent_store.state;
                auto const state_it = std::ranges::find_if(state, [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == user.value;
                });
                REQUIRE(state_it != state.end());
                // Spec MUST: the current join state must be preserved; the invite
                // event MUST NOT replace it in the state snapshot.
                REQUIRE(state_it->event_id == join_event_id);
            }
        }
    }
}

// --- Stale in-memory membership triggers federation retry -------------------
// Spec: Matrix Client-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#joining-rooms
//
// If a local user's in-memory LocalRoom.members still lists them as joined
// but the persistent membership record is "invite" (not "join"), the in-memory
// state is stale. The join endpoint MUST NOT return 200 OK via the already_member
// shortcut; it MUST attempt a fresh federation join so the remote server learns
// about the user's membership.
//
// Scenario: Bug 1 downgraded the persistent membership to "invite" while the
// in-memory room still had the user in members. Without this fix, a subsequent
// POST /join returns 200 and silently calls delete_invite, leaving persistent
// membership == "invite" with no invite metadata — an empty-invite-state loop.
SCENARIO("join_room retries federation for a remote room when persistent membership is stale",
         "[homeserver][federation][invite-join][join][regression]")
{
    GIVEN("a local user in-memory joined to a remote room but persistently in invite state")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "stale_user", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        // Room on a remote server: the room ID domain gives us a candidate server.
        auto const room_id = std::string{"!stale_room:remote.example.org"};

        // Inject the room into the persistent store (it was joined before).
        REQUIRE(merovingian::database::store_room(runtime.database.persistent_store, {room_id, user.value}));
        // Persistent membership is "invite" — simulates Bug 1 downgrade.
        auto const stale_stream = runtime.database.next_stream_ordering++;
        REQUIRE(merovingian::database::store_membership(runtime.database.persistent_store,
                                                        {room_id, user.value, "invite", stale_stream}) ==
                merovingian::database::MembershipStoreResult::stored);
        // In-memory room still lists the user as a member (the stale state).
        runtime.database.rooms.push_back({room_id, user.value, {user.value}, {}});

        WHEN("the user calls join_room for the remote room")
        {
            auto const result = merovingian::homeserver::join_room(runtime, login.value, room_id, {});

            THEN("the already_member shortcut is NOT taken")
            {
                // Before the fix, already_member fired (in-memory member list matched)
                // and returned 200 OK, leaving the user stuck with invite membership
                // and an empty invite_state in sync. After the fix, the server detects
                // the stale persistent state and attempts federation instead.
                //
                // In this test environment there is no actual remote server, so the
                // federation attempt fails with a non-200 status — which is CORRECT
                // behaviour: the user is informed the join did not succeed rather than
                // silently receiving a 200 that masks the broken state.
                REQUIRE_FALSE(result.ok);
                // Spec MUST: the server MUST NOT pretend success when the membership
                // state is inconsistent. 200 OK from already_member is incorrect here.
                REQUIRE(result.status != 200U);
            }

            THEN("the stale in-memory room record is cleared so a real join can be retried")
            {
                // After the fix the stale LocalRoom entry is erased before the
                // federation attempt. If the federation join were to succeed later
                // (with a real remote), push_back would create a clean record.
                // Verify the stale entry is gone from the in-memory list.
                auto const& rooms = runtime.database.rooms;
                auto const still_there = std::ranges::any_of(rooms, [&](auto const& r) {
                    return r.room_id == room_id;
                });
                // The stale room is removed so it does not block a future join attempt.
                REQUIRE_FALSE(still_there);
            }
        }
    }
}

// --- send_join state ingestion: empty state_key events reach store.state -------
// Spec: Matrix Server-Server API v1.19
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// The Matrix spec defines a state event as any event whose JSON carries a
// "state_key" field. The value of that field may be empty (""). Events such as
// m.room.create, m.room.power_levels, m.room.encryption, m.room.history_visibility,
// and m.room.join_rules all use state_key="". They MUST be written to the state
// table when processing the state[] array from a send_join response.
//
// The bug: the original code checked `!parsed.event.state_key.empty()` to decide
// whether to create a state row. EventEnvelope::state_key defaults to "" both for
// (a) state events with state_key="" and (b) non-state events (no "state_key"
// field at all). The .empty() check is therefore indistinguishable — it incorrectly
// excluded every empty-state-key event from the state table.
//
// The consequence: after a federated join, store.state contained only membership
// rows. The post-join sync omitted m.room.encryption, m.room.create, etc. from the
// room state section. The joining client could not set up E2E encryption, leaving
// the user unable to decrypt messages or send new ones to the room.
//
// The fix: check whether the raw JSON Object carries a "state_key" field at all,
// regardless of its value.
SCENARIO("ingest_send_join_state writes empty-state-key events to store.state",
         "[homeserver][federation][send_join][e2ee][spec]")
{
    GIVEN("a send_join response state array with m.room.encryption and m.room.create (state_key=\"\")")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const room_id = std::string{"!enc_room:matrix.example.org"};
        auto const creator = std::string{"@creator:matrix.example.org"};

        // A minimal state array as a remote Synapse returns in send_join.
        // Three event types cover both code paths:
        //   m.room.create     — state_key=""  (was silently dropped by the bug)
        //   m.room.encryption — state_key=""  (the critical E2E event, also dropped)
        //   m.room.member     — state_key=user_id  (non-empty, always worked)
        auto const state_json = std::string{"["
                                            "{\"type\":\"m.room.create\",\"state_key\":\"\",\"room_id\":\"" +
                                            room_id +
                                            "\","
                                            "\"sender\":\"" +
                                            creator +
                                            "\",\"depth\":1,\"origin_server_ts\":1000,"
                                            "\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"aGFzaA\"},"
                                            "\"content\":{\"room_version\":\"10\"},"
                                            "\"signatures\":{\"matrix.example.org\":{\"ed25519:auto\":\"aaaa\"}}},"
                                            "{\"type\":\"m.room.encryption\",\"state_key\":\"\",\"room_id\":\"" +
                                            room_id +
                                            "\","
                                            "\"sender\":\"" +
                                            creator +
                                            "\",\"depth\":2,\"origin_server_ts\":1000,"
                                            "\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"aGFzaA\"},"
                                            "\"content\":{\"algorithm\":\"m.megolm.v1.aes-sha2\"},"
                                            "\"signatures\":{\"matrix.example.org\":{\"ed25519:auto\":\"aaaa\"}}},"
                                            "{\"type\":\"m.room.member\",\"state_key\":\"" +
                                            creator + "\",\"room_id\":\"" + room_id +
                                            "\","
                                            "\"sender\":\"" +
                                            creator +
                                            "\",\"depth\":3,\"origin_server_ts\":1000,"
                                            "\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"aGFzaA\"},"
                                            "\"content\":{\"membership\":\"join\"},"
                                            "\"signatures\":{\"matrix.example.org\":{\"ed25519:auto\":\"aaaa\"}}}"
                                            "]"};

        auto const parsed_arr = merovingian::canonicaljson::parse_lossless(state_json);
        REQUIRE(parsed_arr.error == merovingian::canonicaljson::ParseError::none);
        auto const* arr = std::get_if<merovingian::canonicaljson::Array>(&parsed_arr.value.storage());
        REQUIRE(arr != nullptr);
        REQUIRE(arr->size() == 3U);

        // Room version 10 policy: reference-hash event IDs, standard v6+ auth rules.
        auto const policy = merovingian::rooms::RoomVersionPolicy{
            .id = "10",
            .event_id_format = merovingian::rooms::EventIdFormat::reference_hash,
        };

        WHEN("the state array is ingested via ingest_send_join_state")
        {
            auto const ingested = merovingian::homeserver::ingest_send_join_state(runtime, room_id, *arr, policy);
            auto const& members = ingested.joined_members;

            THEN("m.room.encryption is present in store.state with state_key=\"\"")
            {
                // Spec MUST: the "state_key" field is present (value "") → this IS a
                // state event and MUST appear in the state table after ingestion.
                // If it is absent, the post-join sync omits it from the room state and
                // the joining client cannot set up E2E encryption.
                // Do NOT remove — this is the primary regression guard for the
                // !state_key.empty() bug that caused E2E failures on federated joins.
                auto const& state = runtime.database.persistent_store.state;
                auto const has_encryption = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.encryption" && s.state_key.empty();
                });
                REQUIRE(has_encryption);
            }

            THEN("m.room.create is present in store.state with state_key=\"\"")
            {
                // m.room.create also uses state_key="". Without it in state, clients
                // cannot determine the room version and auth-rule lookups fail.
                auto const& state = runtime.database.persistent_store.state;
                auto const has_create = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.create" && s.state_key.empty();
                });
                REQUIRE(has_create);
            }

            THEN("m.room.member with non-empty state_key is also in store.state")
            {
                // Non-empty state_key membership events must continue to be stored.
                // This guards the non-regression of the path that previously worked.
                auto const& state = runtime.database.persistent_store.state;
                auto const has_member = std::any_of(state.begin(), state.end(), [&](auto const& s) {
                    return s.room_id == room_id && s.event_type == "m.room.member" && s.state_key == creator;
                });
                REQUIRE(has_member);
            }

            THEN("the join-membership user IDs from the state array are returned")
            {
                // ingest_send_join_state must return the user IDs with membership="join"
                // so join_room can populate the in-memory LocalRoom.members list.
                REQUIRE(std::find(members.begin(), members.end(), creator) != members.end());
            }
        }
    }
}

// --- v12 send_join: m.room.create room_id derivation -----------------------
// Spec: Matrix Server-Server API v1.19 / Room Version 12 (MSC4291)
// URL:  ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// In room version 12 the m.room.create event carries no "room_id" field.
// The room ID equals the create event's reference hash with the sigil swapped:
//   room_id = "!" + event_id.substr(1)
//
// Bug: ingest_send_join_state used parsed.event.room_id (empty for v12 create
// events) when building PersistentStateEvent. The state row was stored with
// room_id="" instead of the derived room ID. build_pdu_auth_event_map filters
// by room_id == envelope.room_id and therefore missed the entry, leaving
// auth_events.create empty. Every subsequent inbound PDU failed event-auth at
// step 2: "room has no create event".
//
// Fix: when parsed.event.room_id is empty and the policy's
// create_event_is_room_id flag is set, derive room_id = "!" + event_id.substr(1).
SCENARIO("ingest_send_join_state stores v12 m.room.create with room_id derived from event_id",
         "[homeserver][federation][send_join][v12][spec][regression]")
{
    GIVEN("a send_join state array for a v12 room whose create event has no room_id field")
    {
        REQUIRE(sodium_init() >= 0);
        MEROVINGIAN_NETBSD_DIAG("sodium_init passed");
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        MEROVINGIAN_NETBSD_DIAG("start_runtime passed");
        auto& runtime = started.runtime;

        auto const creator = std::string{"@creator:remote.example.org"};

        // v12 m.room.create: no room_id field, state_key is present but empty.
        auto const create_json = std::string{"{\"type\":\"m.room.create\",\"state_key\":\"\","
                                             "\"sender\":\"" +
                                             creator +
                                             "\",\"depth\":1,\"origin_server_ts\":1000,"
                                             "\"prev_events\":[],\"auth_events\":[],"
                                             "\"hashes\":{\"sha256\":\"aGFzaA\"},"
                                             "\"content\":{\"room_version\":\"12\"},"
                                             "\"signatures\":{\"remote.example.org\":{\"ed25519:auto\":\"aaaa\"}}}"};

        auto const state_json = std::string{"["} + create_json + std::string{"]"};
        auto const parsed_arr = merovingian::canonicaljson::parse_lossless(state_json);
        REQUIRE(parsed_arr.error == merovingian::canonicaljson::ParseError::none);
        auto const* arr = std::get_if<merovingian::canonicaljson::Array>(&parsed_arr.value.storage());
        REQUIRE(arr != nullptr);

        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        REQUIRE(policy->create_event_is_room_id);

        // Compute the expected room_id from the reference hash so the assertion
        // is exact rather than just checking for non-emptiness.
        auto const parsed_create = merovingian::canonicaljson::parse_lossless(create_json);
        REQUIRE(parsed_create.error == merovingian::canonicaljson::ParseError::none);
        auto const eid = merovingian::events::make_reference_hash_event_id(parsed_create.value, *policy);
        REQUIRE_FALSE(eid.event_id.empty());
        MEROVINGIAN_NETBSD_DIAG("reference hash passed");
        auto const expected_room_id = "!" + eid.event_id.substr(1);

        WHEN("the state array is ingested via ingest_send_join_state")
        {
            std::ignore = merovingian::homeserver::ingest_send_join_state(runtime, expected_room_id, *arr, *policy);
            MEROVINGIAN_NETBSD_DIAG("ingest passed");

            THEN("m.room.create appears in store.state with the derived room_id, not \"\"")
            {
                // Spec MUST (MSC4291): the state row MUST use the room_id derived
                // from the create event's reference hash. Storing "" breaks
                // build_pdu_auth_event_map which filters by room_id, causing every
                // inbound PDU to fail event-auth at step 2 ("room has no create event").
                auto const& state = runtime.database.persistent_store.state;
                auto const it = std::ranges::find_if(state, [](auto const& s) {
                    return s.event_type == "m.room.create" && s.state_key.empty();
                });
                // The create state row must exist at all.
                REQUIRE(it != state.end());
                // It must carry the correct derived room_id, not "".
                REQUIRE(it->room_id == expected_room_id);
            }

            THEN("no m.room.create state entry is stored with an empty room_id")
            {
                // Regression guard: the bug produced room_id="" for every v12 create
                // event. Verify that entry is gone so a future refactor cannot
                // silently reintroduce the bad row.
                auto const& state = runtime.database.persistent_store.state;
                auto const has_empty = std::ranges::any_of(state, [](auto const& s) {
                    return s.event_type == "m.room.create" && s.room_id.empty();
                });
                REQUIRE_FALSE(has_empty);
            }
            MEROVINGIAN_NETBSD_DIAG("scenario end");
        }
    }
}

// --- filter_verified_send_join_events ---------------------------------------
// Spec: Server-Server API v1.19 — a joining server MUST verify the signature
// of every event before admitting it to the event graph
// (src/federation/AGENTS.md rule 2). A send_join response's `state` array
// carries one m.room.member per room member — thousands for a large room —
// so these scenarios also prove the resolver fan-out is bounded, not
// unbounded, per the configured `join_state_key_parallelism`.
namespace
{

[[nodiscard]] auto remote_for(std::string const& server_name, std::string const& key_id, std::string const& seed)
    -> merovingian::federation::FederationRemoteRuntime
{
    auto remote = merovingian::federation::FederationRemoteRuntime{};
    remote.server_name = server_name;
    remote.signing_key = {server_name, key_id, 4'102'444'800'000U,
                          merovingian::federation::test::keypair_from_seed(seed).public_key};
    remote.discovery.server_name = server_name;
    remote.trust.reputation_score = 100U;
    return remote;
}

// Builds a signed m.room.member event: content is signed with the keypair
// derived from `sign_seed`, and the signature is attached under
// `{claimed_server, claimed_key_id}` — normally the same as the signing
// keypair's own server/key, but scenarios that need a signature/key mismatch
// pass a different `sign_seed` than the resolver's registered key.
[[nodiscard]] auto signed_member_event(std::string const& room_id, std::string const& user_id,
                                       std::string const& claimed_server, std::string const& claimed_key_id,
                                       std::string const& sign_seed,
                                       merovingian::rooms::RoomVersionPolicy const& policy)
    -> merovingian::canonicaljson::Value
{
    auto raw = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""};
    raw += user_id;
    raw += "\",\"room_id\":\"";
    raw += room_id;
    raw += "\",\"sender\":\"";
    raw += user_id;
    raw += "\",\"depth\":5,\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[],";
    raw += "\"hashes\":{\"sha256\":\"aGFzaA\"},\"content\":{\"membership\":\"join\"}}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const payload = merovingian::events::make_event_signing_payload(parsed.value, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const kp = merovingian::federation::test::keypair_from_seed(sign_seed);
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), reinterpret_cast<unsigned char const*>(kp.secret_key.data()));
    auto const sig_b64 =
        merovingian::events::matrix_base64_from_bytes({reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
    auto const attached =
        merovingian::events::attach_event_signature(parsed.value, {claimed_server, claimed_key_id}, sig_b64);
    REQUIRE(attached.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const reparsed = merovingian::canonicaljson::parse_lossless(attached.output);
    REQUIRE(reparsed.error == merovingian::canonicaljson::ParseError::none);
    return reparsed.value;
}

} // namespace

SCENARIO("filter_verified_send_join_events keeps an event with a valid signature",
         "[homeserver][federation][send_join][security]")
{
    GIVEN("a state array with one event validly signed by its sender's home server, and a matching resolver")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.federation.remote_key_resolver =
            [](std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != remote_origin || key_id != remote_key_id)
            {
                return std::nullopt;
            }
            return remote_for_test();
        };

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(signed_member_event(room_id, bob, remote_origin, remote_key_id, remote_key_seed, policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the validly signed event survives")
            {
                REQUIRE(filtered.size() == 1U);
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events drops an event with an invalid signature",
         "[homeserver][federation][send_join][security]")
{
    GIVEN("a state array with one event whose bytes were NOT signed by the key the resolver returns")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.federation.remote_key_resolver =
            [](std::string_view server_name,
               std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            if (server_name != remote_origin || key_id != remote_key_id)
            {
                return std::nullopt;
            }
            // Returns the REAL remote_key_seed public key; the event below is
            // signed with a different key entirely, so verification must fail.
            return remote_for_test();
        };

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        // Claims to be signed by remote_origin/remote_key_id, but the bytes were
        // actually produced with an unrelated keypair — signature verification
        // against the resolver's real public key must fail.
        array.push_back(
            signed_member_event(room_id, bob, remote_origin, remote_key_id, "an-entirely-different-seed", policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the event is silently dropped, not persisted")
            {
                REQUIRE(filtered.empty());
            }
        }
    }
}

// Spec: rooms/v5.md "Signing key validity period" (unchanged through v12):
// "When validating event signatures, servers MUST enforce the valid_until_ts
// property from a key request is at least as large as the origin_server_ts for
// the event being validated." A send_join response is validated the same way
// as any other received event (ADR-0075).
SCENARIO("filter_verified_send_join_events drops an event signed by a key that expired before it was sent",
         "[homeserver][federation][send_join][security][key_validity]")
{
    GIVEN("a room v10 state array with one event sent at origin_server_ts 1000")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(signed_member_event(room_id, bob, remote_origin, remote_key_id, remote_key_seed, policy));

        for (auto const valid_until : {std::uint64_t{999U}, std::uint64_t{1000U}})
        {
            WHEN("the sender's genuine key is valid until " + std::to_string(valid_until))
            {
                runtime.federation.remote_key_resolver =
                    [valid_until](
                        std::string_view server_name,
                        std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
                    if (server_name != remote_origin || key_id != remote_key_id)
                    {
                        return std::nullopt;
                    }
                    auto remote = remote_for(remote_origin, remote_key_id, remote_key_seed);
                    remote.signing_key.valid_until_ts = valid_until;
                    return remote;
                };
                auto const filtered =
                    merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

                THEN("the event is kept only if the key was valid when it was sent")
                {
                    // Spec MUST: valid_until_ts at least as large as origin_server_ts.
                    REQUIRE(filtered.size() == (valid_until >= 1000U ? 1U : 0U));
                }
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events drops an event whose sender-domain key cannot be resolved",
         "[homeserver][federation][send_join][security]")
{
    GIVEN("a state array with a foreign-domain event and no wired remote_key_resolver")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // remote_key_resolver is left default-constructed (empty) — fail-closed.

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(signed_member_event(room_id, bob, remote_origin, remote_key_id, remote_key_seed, policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the event is dropped rather than trusted without verification")
            {
                REQUIRE(filtered.empty());
            }
        }
    }
}

// --- FED-1: own-domain events in a send_join response ------------------------
// Spec: Server-Server API v1.19, "Checks performed on receipt of a PDU": "2.
// Passes signature checks, otherwise it is dropped." There is no exception for
// events that name a sender on the receiving server. A resident server has no
// reason to send us events we authored that we do not already hold, so an
// event claiming our domain is verified against this server's OWN signing keys
// (current and retired — never fetched over the network), and dropped when the
// key is not one we hold or the signature does not verify.
namespace
{

[[nodiscard]] auto sign_with_secret(merovingian::canonicaljson::Value const& event,
                                    merovingian::rooms::RoomVersionPolicy const& policy,
                                    std::string const& claimed_server, std::string const& claimed_key_id,
                                    std::span<std::uint8_t const> secret_key) -> merovingian::canonicaljson::Value
{
    REQUIRE(secret_key.size() == crypto_sign_SECRETKEYBYTES);
    auto const payload = merovingian::events::make_event_signing_payload(event, policy);
    REQUIRE(payload.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto sig = std::array<unsigned char, crypto_sign_BYTES>{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<unsigned char const*>(payload.output.data()),
                         payload.output.size(), secret_key.data());
    auto const sig_b64 =
        merovingian::events::matrix_base64_from_bytes({reinterpret_cast<char const*>(sig.data()), crypto_sign_BYTES});
    auto const attached = merovingian::events::attach_event_signature(event, {claimed_server, claimed_key_id}, sig_b64);
    REQUIRE(attached.error == merovingian::canonicaljson::CanonicalJsonError::none);
    auto const reparsed = merovingian::canonicaljson::parse_lossless(attached.output);
    REQUIRE(reparsed.error == merovingian::canonicaljson::ParseError::none);
    return reparsed.value;
}

[[nodiscard]] auto unsigned_member_event(std::string const& room_id, std::string const& user_id)
    -> merovingian::canonicaljson::Value
{
    auto raw = std::string{"{\"type\":\"m.room.member\",\"state_key\":\""};
    raw += user_id;
    raw += "\",\"room_id\":\"";
    raw += room_id;
    raw += "\",\"sender\":\"";
    raw += user_id;
    raw += "\",\"depth\":5,\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[],";
    raw += "\"hashes\":{\"sha256\":\"aGFzaA\"},\"content\":{\"membership\":\"join\"}}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

// A member event for `user_id` signed with this runtime's own current signing
// key, under the key ID the server publishes for it.
[[nodiscard]] auto own_signed_member_event(merovingian::homeserver::HomeserverRuntime& runtime,
                                           std::string const& room_id, std::string const& user_id,
                                           merovingian::rooms::RoomVersionPolicy const& policy)
    -> merovingian::canonicaljson::Value
{
    auto const own_key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);
    REQUIRE(own_key.has_value());
    return sign_with_secret(unsigned_member_event(room_id, user_id), policy, local_server, own_key->key_id,
                            runtime.database.signing_secret_key.bytes());
}

[[nodiscard]] auto counting_resolver(
    std::shared_ptr<std::atomic<bool>> const& called // SHARED_PTR: reviewed — test callback shares bool flag
    ) -> merovingian::federation::RemoteKeyResolver
{
    return [called](std::string_view,
                    std::string_view) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
        *called = true;
        return std::nullopt;
    };
}

} // namespace

SCENARIO("filter_verified_send_join_events drops an own-domain event not signed by a key this server holds",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("a state array event whose sender is on our own server, signed under a key ID we never issued")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto resolver_called = std::make_shared<std::atomic<bool>>(false);
        runtime.federation.remote_key_resolver = counting_resolver(resolver_called);

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const alice = std::string{"@alice:"} + local_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(signed_member_event(room_id, alice, local_server, "ed25519:whatever", remote_key_seed, policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the event is dropped, and our own keys are never fetched over the network")
            {
                REQUIRE(filtered.empty());
                REQUIRE_FALSE(resolver_called->load());
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events drops an unsigned own-domain event",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("a state array event whose sender is on our own server and which carries no signatures at all")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const alice = std::string{"@alice:"} + local_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(unsigned_member_event(room_id, alice));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the event is dropped")
            {
                REQUIRE(filtered.empty());
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events drops an own-domain event forged under our real key ID",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("an own-domain event that names this server's current key ID but was signed by some other key")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const own_key = merovingian::homeserver::ensure_runtime_server_signing_key(runtime);
        REQUIRE(own_key.has_value());

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const alice = std::string{"@alice:"} + local_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(signed_member_event(room_id, alice, local_server, own_key->key_id, remote_key_seed, policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the signature does not verify against our key and the event is dropped")
            {
                REQUIRE(filtered.empty());
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events keeps an own-domain event signed with this server's own key",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("an own-domain event genuinely signed with this server's current key, and a resolver that must not be "
          "invoked")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto resolver_called = std::make_shared<std::atomic<bool>>(false);
        runtime.federation.remote_key_resolver = counting_resolver(resolver_called);

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const alice = std::string{"@alice:"} + local_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(own_signed_member_event(runtime, room_id, alice, policy));

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the event verifies against our own key and is kept, with no network key lookup")
            {
                REQUIRE(filtered.size() == 1U);
                REQUIRE_FALSE(resolver_called->load());
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events keeps an own-domain event signed with a key this server has since retired",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("an own-domain event signed with our key at origin_server_ts 1000, after which the key was rotated out")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const alice = std::string{"@alice:"} + local_server;
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(own_signed_member_event(runtime, room_id, alice, policy));
        auto const rotated = merovingian::homeserver::rotate_server_signing_key(runtime);
        REQUIRE(rotated.ok);

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("the retired key still verifies the event, which was sent while the key was valid")
            {
                REQUIRE(filtered.size() == 1U);
            }
        }
    }
}

// --- FED-1: send_join response events are bound to the room being joined ----
// Spec: Server-Server API v1.19, "Joining Rooms": the send_join response's
// `state` is the room state before the join event and `auth_chain` is the
// auth chain for that state — both describe the room being joined and
// nothing else. rooms/v12.md: the m.room.create event has no room_id; "The
// room ID is the event ID of the event with sigil ! instead of $", and a
// create event that has a room_id is rejected (auth rule 1.2).
namespace
{

[[nodiscard]] auto parse_test_event(std::string const& raw) -> merovingian::canonicaljson::Value
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

[[nodiscard]] auto v12_create_event(std::string const& creator, std::string const& nonce)
    -> merovingian::canonicaljson::Value
{
    return parse_test_event(R"({"type":"m.room.create","state_key":"","sender":")" + creator +
                            R"(","depth":1,"origin_server_ts":1000,"prev_events":[],"auth_events":[],)"
                            R"("hashes":{"sha256":"aGFzaA"},"content":{"room_version":"12","nonce":")" +
                            nonce + R"("}})");
}

[[nodiscard]] auto derived_v12_room_id(merovingian::canonicaljson::Value const& create,
                                       merovingian::rooms::RoomVersionPolicy const& policy) -> std::string
{
    auto const eid = merovingian::events::make_reference_hash_event_id(create, policy);
    REQUIRE(eid.error.empty());
    REQUIRE_FALSE(eid.event_id.empty());
    return "!" + eid.event_id.substr(1);
}

} // namespace

SCENARIO("filter_send_join_events_for_room keeps only events for the room being joined",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("a v10 send_join array mixing events for the joined room, another room, and no room at all")
    {
        auto const joined = std::string{"!joined:remote.example.org"};
        auto const other = std::string{"!local:example.org"};
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(unsigned_member_event(joined, "@bob:remote.example.org"));
        array.push_back(unsigned_member_event(other, "@alice:example.org"));
        array.push_back(parse_test_event(
            R"({"type":"m.room.power_levels","state_key":"","sender":"@evil:remote.example.org","depth":2,)"
            R"("origin_server_ts":1000,"prev_events":[],"auth_events":[],"content":{}})"));

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, policy);

            THEN("only the joined room's event survives")
            {
                REQUIRE(kept.size() == 1U);
                auto const envelope = merovingian::events::parse_event_envelope(kept.front());
                REQUIRE(envelope.error.empty());
                REQUIRE(envelope.event.room_id == joined);
            }
        }
    }
}

SCENARIO("filter_send_join_events_for_room binds a v12 m.room.create event by its derived room ID",
         "[homeserver][federation][send_join][security][v12][fed1]")
{
    GIVEN("the v12 create event of the joined room and the create event of a different v12 room")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        REQUIRE(policy->create_event_is_room_id);
        auto const joined_create = v12_create_event("@creator:remote.example.org", "joined");
        auto const other_create = v12_create_event("@creator:remote.example.org", "other");
        auto const joined = derived_v12_room_id(joined_create, *policy);
        REQUIRE(derived_v12_room_id(other_create, *policy) != joined);

        auto array = merovingian::canonicaljson::Array{};
        array.push_back(other_create);
        array.push_back(joined_create);

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, *policy);

            THEN("only the create event whose reference hash is the joined room ID survives")
            {
                REQUIRE(kept.size() == 1U);
                REQUIRE(derived_v12_room_id(kept.front(), *policy) == joined);
            }
        }
    }

    GIVEN("a v12 create event that carries a room_id field naming the joined room")
    {
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        auto const joined = derived_v12_room_id(v12_create_event("@creator:remote.example.org", "joined"), *policy);
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(parse_test_event(
            R"({"type":"m.room.create","state_key":"","room_id":")" + joined +
            R"(","sender":"@creator:remote.example.org","depth":1,"origin_server_ts":1000,"prev_events":[],)"
            R"("auth_events":[],"hashes":{"sha256":"aGFzaA"},"content":{"room_version":"12","nonce":"joined"}})"));

        WHEN("the array is filtered for the joined room")
        {
            auto const kept = merovingian::homeserver::filter_send_join_events_for_room(array, joined, *policy);

            THEN("the create event is dropped, as v12 auth rule 1.2 rejects it")
            {
                REQUIRE(kept.empty());
            }
        }
    }
}

SCENARIO("ingest_send_join_state never writes state for a room other than the one being joined",
         "[homeserver][federation][send_join][security][fed1]")
{
    GIVEN("a local room with a current m.room.power_levels, and a state array naming that room")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const local_room = std::string{"!local:example.org"};
        auto const joined = std::string{"!joined:remote.example.org"};
        auto const original_pl = std::string{"$original_pl"};
        runtime.database.persistent_store.state.push_back({local_room, "m.room.power_levels", "", original_pl});
        auto const policy = *merovingian::rooms::find_room_version_policy("10");

        auto array = merovingian::canonicaljson::Array{};
        array.push_back(parse_test_event(
            R"({"type":"m.room.power_levels","state_key":"","room_id":")" + local_room +
            R"(","sender":"@evil:remote.example.org","depth":2,"origin_server_ts":1000,"prev_events":[],)"
            R"("auth_events":[],"hashes":{"sha256":"aGFzaA"},"content":{"users":{"@evil:remote.example.org":100}}})"));
        array.push_back(unsigned_member_event(local_room, "@victim:example.org"));
        auto const events_before = runtime.database.persistent_store.events.size();

        WHEN("the array is ingested for the joined room")
        {
            auto const ingested = merovingian::homeserver::ingest_send_join_state(runtime, joined, array, policy);

            THEN("the local room's current state is untouched and nothing is stored")
            {
                auto const& state = runtime.database.persistent_store.state;
                auto const pl = std::ranges::find_if(state, [&](auto const& s) {
                    return s.room_id == local_room && s.event_type == "m.room.power_levels";
                });
                REQUIRE(pl != state.end());
                REQUIRE(pl->event_id == original_pl);
                REQUIRE_FALSE(std::ranges::any_of(state, [&](auto const& s) {
                    return s.room_id == local_room && s.event_type == "m.room.member";
                }));
                REQUIRE(runtime.database.persistent_store.events.size() == events_before);
                REQUIRE(ingested.joined_members.empty());
                REQUIRE(ingested.state_entries.empty());
            }
        }
    }
}

SCENARIO("filter_verified_send_join_events bounds concurrent key resolutions to join_state_key_parallelism",
         "[homeserver][federation][send_join][security][concurrency]")
{
    GIVEN("a state array with six distinct sender domains and join_state_key_parallelism=2")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.federation.config.join_state_key_parallelism = 2U;

        static constexpr auto k_domain_count = std::size_t{6U};
        auto calls = std::make_shared<std::atomic<std::size_t>>(0U);
        auto in_flight = std::make_shared<std::atomic<std::size_t>>(0U);
        auto peak = std::make_shared<std::atomic<std::size_t>>(0U);
        auto keys = std::make_shared<
            std::map<std::pair<std::string, std::string>, merovingian::federation::FederationRemoteRuntime>>();

        auto const room_id = std::string{"!room:matrix.example.org"};
        auto const policy = *merovingian::rooms::find_room_version_policy("10");
        auto array = merovingian::canonicaljson::Array{};
        for (auto i = std::size_t{0U}; i < k_domain_count; ++i)
        {
            auto const domain = "sender" + std::to_string(i) + ".example.org";
            auto const key_id = std::string{"ed25519:auto"};
            auto const seed = "bounded-parallelism-seed-" + std::to_string(i);
            (*keys)[{domain, key_id}] = remote_for(domain, key_id, seed);
            auto const user_id = "@user" + std::to_string(i) + ":" + domain;
            array.push_back(signed_member_event(room_id, user_id, domain, key_id, seed, policy));
        }

        runtime.federation.remote_key_resolver =
            [calls, in_flight, peak,
             keys](std::string_view server_name,
                   std::string_view key_id) -> std::optional<merovingian::federation::FederationRemoteRuntime> {
            calls->fetch_add(1U);
            auto const current = in_flight->fetch_add(1U) + 1U;
            auto prev_peak = peak->load();
            while (current > prev_peak && !peak->compare_exchange_weak(prev_peak, current))
            {
            }
            std::this_thread::sleep_for(std::chrono::milliseconds{30});
            in_flight->fetch_sub(1U);
            auto const it =
                keys->find(std::pair<std::string, std::string>{std::string{server_name}, std::string{key_id}});
            return it != keys->end() ? std::optional{it->second} : std::nullopt;
        };

        WHEN("filter_verified_send_join_events is called")
        {
            auto const filtered =
                merovingian::homeserver::filter_verified_send_join_events(runtime, array, policy, local_server);

            THEN("every event verifies, each distinct domain is resolved exactly once, and concurrency never exceeds 2")
            {
                REQUIRE(filtered.size() == k_domain_count);
                REQUIRE(calls->load() == k_domain_count);
                REQUIRE(peak->load() <= 2U);
            }
        }
    }
}

// --- split_send_join_state_events (fast join) --------------------------------
// Fast join: a send_join `state` array is split into "critical" state (verified
// and persisted synchronously, before the join response returns) and
// "background" state (every OTHER member's m.room.member, verified and
// persisted after the response returns — see room.join.background_state_complete).
// These scenarios are pure JSON classification with no crypto involved, so
// events below are unsigned; signature verification is filter_verified_send_join_events's
// job, tested separately above.
namespace
{

[[nodiscard]] auto bare_event(std::string const& type, std::string const& state_key, std::string const& sender)
    -> merovingian::canonicaljson::Value
{
    auto const raw = std::string{"{\"type\":\""} + type + "\",\"state_key\":\"" + state_key + "\",\"sender\":\"" +
                     sender +
                     "\",\"room_id\":\"!room:matrix.example.org\",\"depth\":1,"
                     "\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[],"
                     "\"content\":{}}";
    auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return parsed.value;
}

} // namespace

SCENARIO("split_send_join_state_events keeps non-membership state events critical",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("a state array of room-level state events with empty state_key")
    {
        auto const alice = std::string{"@alice:"} + local_server;
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(bare_event("m.room.create", "", alice));
        array.push_back(bare_event("m.room.power_levels", "", alice));
        array.push_back(bare_event("m.room.join_rules", "", alice));
        array.push_back(bare_event("m.room.history_visibility", "", alice));
        array.push_back(bare_event("m.room.encryption", "", alice));

        WHEN("the state array is split")
        {
            auto const split = merovingian::homeserver::split_send_join_state_events(array, alice);

            THEN("every event is critical and none are deferred")
            {
                REQUIRE(split.critical.size() == 5U);
                REQUIRE(split.background.empty());
            }
        }
    }
}

SCENARIO("split_send_join_state_events keeps the joining user's own membership critical",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("a state array with only the joining user's own m.room.member event")
    {
        auto const alice = std::string{"@alice:"} + local_server;
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(bare_event("m.room.member", alice, alice));

        WHEN("the state array is split")
        {
            auto const split = merovingian::homeserver::split_send_join_state_events(array, alice);

            THEN("the event is critical, not deferred")
            {
                REQUIRE(split.critical.size() == 1U);
                REQUIRE(split.background.empty());
            }
        }
    }
}

SCENARIO("split_send_join_state_events defers other members' membership events",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("a state array with three OTHER users' m.room.member events")
    {
        auto const alice = std::string{"@alice:"} + local_server;
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const carol = std::string{"@carol:"} + remote_origin;
        auto const dave = std::string{"@dave:"} + remote_origin;
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(bare_event("m.room.member", bob, bob));
        array.push_back(bare_event("m.room.member", carol, carol));
        array.push_back(bare_event("m.room.member", dave, dave));

        WHEN("the state array is split for the joining user alice")
        {
            auto const split = merovingian::homeserver::split_send_join_state_events(array, alice);

            THEN("all three are deferred to background, none are critical")
            {
                REQUIRE(split.critical.empty());
                REQUIRE(split.background.size() == 3U);
            }
        }
    }
}

SCENARIO("split_send_join_state_events splits a realistic mixed state array correctly",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("create, power_levels, the joining user's membership, and two other members")
    {
        auto const alice = std::string{"@alice:"} + local_server;
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const carol = std::string{"@carol:"} + remote_origin;
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(bare_event("m.room.create", "", bob));
        array.push_back(bare_event("m.room.power_levels", "", bob));
        array.push_back(bare_event("m.room.member", alice, alice));
        array.push_back(bare_event("m.room.member", bob, bob));
        array.push_back(bare_event("m.room.member", carol, carol));

        WHEN("the state array is split for the joining user alice")
        {
            auto const split = merovingian::homeserver::split_send_join_state_events(array, alice);

            THEN("create, power_levels, and alice's own membership are critical; bob and carol are deferred")
            {
                REQUIRE(split.critical.size() == 3U);
                REQUIRE(split.background.size() == 2U);
            }
        }
    }
}

SCENARIO("split_send_join_state_events treats malformed entries as critical, not silently dropped",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("a state array entry with no state_key field at all")
    {
        auto const alice = std::string{"@alice:"} + local_server;
        auto const bob = std::string{"@bob:"} + remote_origin;
        auto const raw = std::string{"{\"type\":\"m.room.member\",\"sender\":\""} + bob +
                         "\",\"room_id\":\"!room:matrix.example.org\",\"depth\":1,"
                         "\"origin_server_ts\":1000,\"prev_events\":[],\"auth_events\":[],\"content\":{}}";
        auto const parsed = merovingian::canonicaljson::parse_lossless(raw);
        REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
        auto array = merovingian::canonicaljson::Array{};
        array.push_back(parsed.value);

        WHEN("the state array is split")
        {
            auto const split = merovingian::homeserver::split_send_join_state_events(array, alice);

            THEN("the unclassifiable entry defaults to the synchronous critical path, not lost")
            {
                REQUIRE(split.critical.size() == 1U);
                REQUIRE(split.background.empty());
            }
        }
    }
}

SCENARIO("split_send_join_state_events returns an empty split for an empty state array",
         "[homeserver][federation][send_join][fast-join]")
{
    GIVEN("an empty state array")
    {
        auto const alice = std::string{"@alice:"} + local_server;

        WHEN("the state array is split")
        {
            auto const split =
                merovingian::homeserver::split_send_join_state_events(merovingian::canonicaljson::Array{}, alice);

            THEN("both halves are empty")
            {
                REQUIRE(split.critical.empty());
                REQUIRE(split.background.empty());
            }
        }
    }
}

// --- inbound /invite for a room hosted here (audit FED-5) --------------------
// Spec: Matrix Server-Server API v1.19, "Inviting to a room"
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#inviting-to-a-room
//
// "if the remote homeserver is already in the room, it will receive the
// invite event twice; once through this endpoint, and again through a
// federation transaction". The transaction path does the full PDU checks and
// state handling, so the endpoint MUST NOT write the event into room state for
// a room this server holds. The event is still subject to the room's
// authorisation rules ("If the target user is banned, reject").
namespace
{

// A local room where remote @carol has joined and may invite (invite level 0),
// plus a second local user who can be the invite's target.
struct HostedRoomFixture final
{
    HostedRoomFixture()
        : started{merovingian::homeserver::start_runtime(registration_enabled_config())}
    {
        REQUIRE(sodium_init() >= 0);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const host = merovingian::homeserver::register_local_user(runtime, "fed5host", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(host.ok);
        host_id = host.value;
        auto const victim = merovingian::homeserver::register_local_user(runtime, "fed5victim", "CorrectHorse7!",
                                                                         merovingian::tests::registration_token);
        REQUIRE(victim.ok);
        victim_id = victim.value;
        auto const login = merovingian::homeserver::login_local_user(runtime, host_id, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        host_token = login.value;

        auto options = merovingian::homeserver::CreateRoomOptions{};
        options.power_level_content_override.push_back(
            merovingian::canonicaljson::make_member("invite", merovingian::canonicaljson::Value{std::int64_t{0}}));
        auto const room = merovingian::homeserver::create_room(runtime, host_token, options);
        REQUIRE(room.ok);
        room_id = room.value;

        // Carol is invited by the host, then joins over federation.
        carol_id = std::string{"@carol:"} + remote_origin;
        plant_invite_event(runtime, room_id, host_id, carol_id, "$fed5_invite_carol:example.org");
        auto const& store = runtime.database.persistent_store;
        auto const join = make_signed_join_body(
            room_id, carol_id, merovingian::tests::fixture_auth_event_ids(store, room_id, carol_id, true),
            merovingian::tests::fixture_prev_event_ids(store, room_id));
        auto const join_response = merovingian::federation::handle_inbound_federation_request(
            runtime.federation,
            signed_put("/_matrix/federation/v2/send_join/" + room_id + "/" + join.event_id,
                       join.body));
        REQUIRE(join_response.status == 200U);
    }

    [[nodiscard]] auto invite_victim() -> merovingian::federation::FederationResponse
    {
        auto const invite = make_signed_invite(room_id, carol_id, victim_id);
        return merovingian::federation::handle_inbound_federation_request(
            started.runtime.federation,
            signed_put("/_matrix/federation/v2/invite/" + room_id + "/" + invite.event_id, invite.body));
    }

    // (event_type, state_key, event_id) of every current-state row of the room.
    [[nodiscard]] auto state_snapshot() const -> std::vector<std::array<std::string, 3U>>
    {
        auto rows = std::vector<std::array<std::string, 3U>>{};
        for (auto const& row : started.runtime.database.persistent_store.state)
        {
            if (row.room_id == room_id)
            {
                rows.push_back({row.event_type, row.state_key, row.event_id});
            }
        }
        std::ranges::sort(rows);
        return rows;
    }

    [[nodiscard]] auto victim_membership() const -> std::string
    {
        for (auto const& row : started.runtime.database.persistent_store.memberships)
        {
            if (row.room_id == room_id && row.user_id == victim_id)
            {
                return row.membership;
            }
        }
        return {};
    }

    merovingian::homeserver::RuntimeStartResult started;
    std::string host_id{};
    std::string victim_id{};
    std::string host_token{};
    std::string room_id{};
    std::string carol_id{};
};

} // namespace

SCENARIO("A remote invite cannot undo a ban for a local user in a room hosted here",
         "[homeserver][federation][invite-join][invite][security][fed5]")
{
    GIVEN("local user U banned in local room L, and a remote member who is allowed to invite")
    {
        auto fixture = HostedRoomFixture{};
        REQUIRE(merovingian::homeserver::ban_user(fixture.started.runtime, fixture.host_token, fixture.room_id,
                                                  fixture.victim_id)
                    .ok);
        REQUIRE(fixture.victim_membership() == "ban");
        auto const state_before = fixture.state_snapshot();

        WHEN("the remote server sends a validly signed invite for U into L")
        {
            auto const response = fixture.invite_victim();

            THEN("the answer is 403 M_FORBIDDEN, U stays banned and L's state is unchanged")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(response.body.find("M_FORBIDDEN") != std::string::npos);
                REQUIRE(fixture.victim_membership() == "ban");
                REQUIRE(fixture.state_snapshot() == state_before);
            }
        }
    }
}

SCENARIO("A remote invite for a room hosted here is authorised against the room's current state",
         "[homeserver][federation][invite-join][invite][security][fed5]")
{
    GIVEN("a local room and a remote sender who is not a member of it")
    {
        auto fixture = HostedRoomFixture{};
        auto const state_before = fixture.state_snapshot();
        auto const stranger = std::string{"@stranger:"} + remote_origin;
        auto const invite = make_signed_invite(fixture.room_id, stranger, fixture.victim_id);

        WHEN("the remote server sends an invite signed by that non-member")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                fixture.started.runtime.federation,
                signed_put("/_matrix/federation/v2/invite/" + fixture.room_id + "/" + invite.event_id, invite.body));

            THEN("the answer is 403 and neither membership nor state change")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(fixture.victim_membership().empty());
                REQUIRE(fixture.state_snapshot() == state_before);
            }
        }
    }
}

SCENARIO("A valid remote invite into a room hosted here does not write current state",
         "[homeserver][federation][invite-join][invite][spec][fed5]")
{
    GIVEN("a local room, a joined remote member with invite power, and a local target")
    {
        auto fixture = HostedRoomFixture{};
        auto const state_before = fixture.state_snapshot();

        WHEN("the remote member's server sends a validly signed invite for the local target")
        {
            auto const response = fixture.invite_victim();

            THEN("the invite is accepted and signed, and the target sees an invite")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(fixture.victim_membership() == "invite");
            }

            AND_THEN("the room's current state is untouched (the transaction path updates it)")
            {
                REQUIRE(fixture.state_snapshot() == state_before);
            }
        }
    }
}

SCENARIO("An inbound invite whose URL event ID is not the event's own ID is refused",
         "[homeserver][federation][invite-join][invite][security][fed5]")
{
    GIVEN("a local user and a remote server that sends a signed invite under a different event ID in the URL")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());
        auto const local_user = merovingian::homeserver::register_local_user(runtime, "fed5idbind", "CorrectHorse7!",
                                                                             merovingian::tests::registration_token);
        REQUIRE(local_user.ok);
        auto const room_id = std::string{"!bind_test_room:remote.example.org"};
        auto const invite = make_signed_invite(room_id, "@remote_host:remote.example.org", local_user.value);

        WHEN("the URL carries an event ID that does not match the signed event")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation,
                signed_put("/_matrix/federation/v2/invite/" + room_id + "/$not_the_real_event_id", invite.body));

            THEN("the answer is 400 M_INVALID_PARAM and nothing is stored")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("M_INVALID_PARAM") != std::string::npos);
                REQUIRE(std::ranges::none_of(runtime.database.persistent_store.memberships, [&](auto const& row) {
                    return row.room_id == room_id;
                }));
            }
        }
    }
}
