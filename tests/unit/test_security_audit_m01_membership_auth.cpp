// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |  SECURITY AUDIT M-01 — FEDERATION MEMBERSHIP AUTHORIZATION BYPASS        |
// |                                                                         |
// |  runtime.federation.membership_acceptor (wired in                       |
// |  wire_federation_callbacks_impl, src/homeserver/local_http_router.cpp)  |
// |  handles inbound send_join / send_leave / send_knock. It checks only    |
// |  that the target room exists, then persists the event and membership   |
// |  unconditionally. It never runs Matrix event authorization rules, so a  |
// |  remote server holding nothing more than a valid signing key can join a |
// |  user into an invite-only room without ever having been invited, or    |
// |  "leave" a room on behalf of a user who was never a member of it.       |
// |                                                                         |
// |  Compare with ingest_pdu_event() in the same file (used for ordinary    |
// |  /send transactions), which builds an auth-event map via the file-local |
// |  build_pdu_auth_event_map() helper and rejects through                  |
// |  events::authorize_event_against_auth_events() before persisting        |
// |  anything. membership_acceptor has no equivalent check.                 |
// |                                                                         |
// |  These scenarios assert on STORED STATE (persistent_store.memberships   |
// |  and persistent_store.events), not just the HTTP response, because the  |
// |  finding is about data reaching the store despite a failed              |
// |  authorization decision.                                                |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19 §authorization-rules              |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#authorization-rules |
// +-------------------------------------------------------------------------+

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
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
auto constexpr remote_key_seed = "m01-audit-remote-seed";

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
        req.origin, req.destination, req.method, target, body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

// Build a properly signed m.room.member PDU (join, leave, or knock) from the
// remote server. Mirrors make_signed_join_body() in
// tests/unit/test_federation_invite_join.cpp, generalised over `membership`.
[[nodiscard]] auto make_signed_membership_body(std::string const& room_id, std::string const& sender,
                                               std::string const& state_key, std::string const& membership,
                                               std::vector<std::string> const& auth_events = {}) -> std::string
{
    auto auth_json = std::string{"["};
    for (std::size_t i = 0U; i < auth_events.size(); ++i)
    {
        if (i != 0U)
        {
            auth_json += ',';
        }
        auth_json += "\"" + auth_events[i] + "\"";
    }
    auth_json += "]";

    auto const unsigned_json =
        std::string{"{\"type\":\"m.room.member\",\"room_id\":\""} + room_id + "\",\"sender\":\"" + sender +
        "\",\"state_key\":\"" + state_key + "\",\"content\":{\"membership\":\"" + membership +
        "\"},\"depth\":6,\"origin_server_ts\":2000,\"prev_events\":[],\"auth_events\":" + auth_json + "}";

    return merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin, remote_key_id,
                                                                 remote_key_seed, "12");
}

// Plant an invite event directly into the store (simulates a local user
// inviting a remote user, which normally goes through room_service and
// stores the event through the ordinary path). Copied from
// tests/unit/test_federation_invite_join.cpp's plant_invite_event().
auto plant_invite_event(merovingian::homeserver::HomeserverRuntime& runtime, std::string const& room_id,
                        std::string const& sender_user_id, std::string const& invited_user_id,
                        std::string const& invite_event_id) -> void
{
    auto pdu = merovingian::database::PersistentEvent{};
    pdu.event_id = invite_event_id;
    pdu.room_id = room_id;
    pdu.sender_user_id = sender_user_id;
    pdu.json =
        std::string{"{\"type\":\"m.room.member\",\"state_key\":\""} + invited_user_id +
        "\",\"content\":{\"membership\":\"invite\"},\"room_id\":\"" + room_id + "\",\"sender\":\"" + sender_user_id +
        "\",\"event_id\":\"" + invite_event_id +
        "\",\"depth\":5,\"prev_events\":[],\"auth_events\":[],\"hashes\":{\"sha256\":\"x\"},\"origin_server_ts\":1000}";
    pdu.depth = 5U;
    pdu.stream_ordering = runtime.database.next_stream_ordering++;
    auto state = std::optional<merovingian::database::PersistentStateEvent>{
        merovingian::database::PersistentStateEvent{room_id, "m.room.member", invited_user_id, invite_event_id}
    };
    REQUIRE(merovingian::database::store_event_with_state(runtime.database.persistent_store, std::move(pdu),
                                                          std::move(state)));
}

// True if `store` has a membership row for (room_id, user_id) with the given
// membership value.
[[nodiscard]] auto has_membership(merovingian::database::PersistentStore const& store, std::string const& room_id,
                                  std::string const& user_id, std::string const& membership) -> bool
{
    return std::ranges::any_of(store.memberships, [&](merovingian::database::PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id && m.membership == membership;
    });
}

// True if `store` has any membership row at all for (room_id, user_id),
// regardless of value.
[[nodiscard]] auto has_any_membership(merovingian::database::PersistentStore const& store, std::string const& room_id,
                                      std::string const& user_id) -> bool
{
    return std::ranges::any_of(store.memberships, [&](merovingian::database::PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id;
    });
}

} // namespace

// --- send_join must not bypass authorization for invite-only rooms -----------
// Spec: Matrix Server-Server API v1.19 §authorization-rules, rule 4 (membership
// events) — a join into an invite-only room is only authorized when the target
// user's current membership is already "invite" (or "join").
//
// M-01: membership_acceptor persists the join unconditionally once the room is
// found to exist. It never runs authorize_event_against_auth_events, so this
// scenario currently succeeds when it MUST be rejected. Do NOT weaken this
// test to make it pass — fix membership_acceptor so it runs the same
// authorization check ingest_pdu_event runs for ordinary PDUs.
SCENARIO("send_join is rejected for an uninvited remote user in an invite-only room, and nothing is persisted",
         "[security][federation][m01]")
{
    GIVEN("an invite-only room and a remote user who has never been invited")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "m01user1", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        // Default CreateRoomOptions preset is "private_chat" -> m.room.join_rules
        // content.join_rule == "invite" (src/homeserver/room_service.cpp).
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const uninvited_user = std::string{"@mallory:"} + remote_origin;
        auto const join_event_id = std::string{"$m01_join_mallory:remote.example.org"};
        auto const join_body = make_signed_membership_body(room_id, uninvited_user, uninvited_user, "join");

        auto const& store = runtime.database.persistent_store;
        auto const events_before = store.events.size();

        WHEN("the remote server delivers send_join for the uninvited user")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join_body));

            THEN("the join is refused with 403")
            {
                REQUIRE(response.status == 403U);
            }

            THEN("no membership row for the uninvited user exists in the persistent store")
            {
                REQUIRE_FALSE(has_any_membership(store, room_id, uninvited_user));
            }

            // ADR-0064 phase B2 / spec "Rejection": a rejected event IS
            // stored — "Subsequent events from other servers that reference
            // rejected events should be allowed if they still pass the auth
            // rules" — it simply never updates state, never becomes a forward
            // extremity, and is never shown to clients. The security property
            // this scenario guards is the membership NOT being applied
            // (asserted above), not the row being absent.
            THEN("the rejected join is stored as rejected, but never applied to state")
            {
                REQUIRE(store.events.size() == events_before + 1U);
                auto const stored = std::ranges::find_if(store.events,
                                                         [](merovingian::database::PersistentEvent const& e) {
                                                             return e.sender_user_id.starts_with("@uninvited");
                                                         });
                REQUIRE(stored != store.events.end());
                REQUIRE(stored->status == "rejected");
            }
        }
    }
}

// --- send_join still works for a user who genuinely holds an invite ----------
// This is the control case: fixing M-01 must not break a legitimate federated
// join. The target user has a pending invite planted in the store exactly as
// a real invite (via the invite_handler) would leave it.
SCENARIO("send_join is accepted for a remote user who holds a pending invite", "[security][federation][m01]")
{
    GIVEN("an invite-only room and a remote user with a pending invite")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "m01user2", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        auto const invited_user = std::string{"@carol:"} + remote_origin;
        auto const invite_event_id = std::string{"$m01_invite_carol:example.org"};
        plant_invite_event(runtime, room_id, user.value, invited_user, invite_event_id);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const join_event_id = std::string{"$m01_join_carol:remote.example.org"};
        auto const join_body =
            make_signed_membership_body(room_id, invited_user, invited_user, "join", {invite_event_id});

        WHEN("the remote server delivers send_join for the invited user")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join_body));

            THEN("the join is accepted")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("the membership row for the invited user becomes join")
            {
                REQUIRE(has_membership(runtime.database.persistent_store, room_id, invited_user, "join"));
            }
        }
    }
}

// --- send_join still works for a public room ----------------------------------
// Second control case: a public room's join_rules legitimately permit anyone
// to join without an invite, so this must keep succeeding after M-01 is fixed.
SCENARIO("send_join is accepted for an uninvited remote user in a public room", "[security][federation][m01]")
{
    GIVEN("a public room and a remote user who has never been invited")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "m01user3", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        // preset "public_chat" -> m.room.join_rules content.join_rule == "public"
        // (src/homeserver/room_service.cpp).
        auto options = merovingian::homeserver::CreateRoomOptions{};
        options.preset = "public_chat";
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value, options);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const uninvited_user = std::string{"@dave:"} + remote_origin;
        auto const join_event_id = std::string{"$m01_join_dave:remote.example.org"};
        auto const join_body = make_signed_membership_body(room_id, uninvited_user, uninvited_user, "join");

        WHEN("the remote server delivers send_join for the uninvited user")
        {
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + join_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, join_body));

            THEN("the join is accepted because the room is public")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("the membership row for the joining user becomes join")
            {
                REQUIRE(has_membership(runtime.database.persistent_store, room_id, uninvited_user, "join"));
            }
        }
    }
}

// --- send_leave must not accept a leave from a non-member ---------------------
// Spec: Matrix Server-Server API v1.19 §authorization-rules, rule 4.2 —
// a self-leave is only authorized when the target user's current membership
// is invite, join, or knock. A user who was never a member of the room has no
// membership event to leave from.
//
// M-01: membership_acceptor persists the leave unconditionally (creating a
// brand-new "leave" membership row for a user who was never seen in the room)
// because it never runs authorization before calling upsert_membership.
SCENARIO("send_leave is rejected for a remote user who was never a member, and no membership row is written",
         "[security][federation][m01]")
{
    GIVEN("a room and a remote user who has never joined, been invited, or knocked")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "m01user4", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const non_member = std::string{"@eve:"} + remote_origin;
        auto const leave_event_id = std::string{"$m01_leave_eve:remote.example.org"};
        auto const leave_body = make_signed_membership_body(room_id, non_member, non_member, "leave");

        REQUIRE_FALSE(has_any_membership(runtime.database.persistent_store, room_id, non_member));

        WHEN("the remote server delivers send_leave for the non-member")
        {
            auto const target = "/_matrix/federation/v2/send_leave/" + room_id + "/" + leave_event_id;
            auto const response = merovingian::federation::handle_inbound_federation_request(
                runtime.federation, signed_put(target, leave_body));

            THEN("the leave is refused with 403")
            {
                REQUIRE(response.status == 403U);
            }

            THEN("no membership row was created for the non-member")
            {
                REQUIRE_FALSE(has_any_membership(runtime.database.persistent_store, room_id, non_member));
            }
        }
    }
}
