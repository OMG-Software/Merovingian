// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |  SECURITY AUDIT FED-6, FED-8, FED-11                                    |
// |  Medium-severity federation findings from 2026-09-29 audit.           |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/membership_fixture_support.hpp"
#include "../support/registration_token.hpp"
#include "federation_signing_test_support.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/event.hpp"
#include "merovingian/events/event_id.hpp"
#include "merovingian/events/event_signer.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/server_acl.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/state_bookkeeping.hpp"
#include "merovingian/homeserver/worker_pool.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <algorithm>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <sodium.h>

namespace
{

[[nodiscard]] auto registration_enabled_config(std::string server_name = "example.org") -> merovingian::config::Config
{
    auto server = merovingian::config::ServerConfig{};
    server.server_name = std::move(server_name);
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

auto constexpr local_server = "example.org";
auto constexpr remote_origin = "remote.example.org";
auto constexpr remote_key_id = "ed25519:auto";
auto constexpr remote_key_seed = "fed-6-8-11-audit-remote-seed";

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
        req.origin, req.destination, req.method, target, req.body,
        merovingian::federation::test::keypair_from_seed(remote_key_seed).secret_key);
    return req;
}

[[nodiscard]] auto federation_runtime_config() -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.enabled = true;
    config.default_policy = "allow";
    config.require_valid_tls = true;
    config.verify_json_signatures = true;
    config.max_transaction_bytes = 16384U;
    config.remote_timeout_seconds = 30U;
    config.server_name = local_server;
    return config;
}

struct SignedMembershipPdu final
{
    std::string json;
    std::string event_id;
};

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

[[nodiscard]] auto string_array(std::vector<std::string> const& values) -> merovingian::canonicaljson::Value
{
    auto array = merovingian::canonicaljson::Array{};
    array.reserve(values.size());
    for (auto const& value : values)
    {
        array.push_back(merovingian::canonicaljson::Value{value});
    }
    return merovingian::canonicaljson::Value{std::move(array)};
}

[[nodiscard]] auto make_signed_membership_body(std::string const& room_id, std::string const& sender,
                                               std::string const& state_key, std::string const& membership,
                                               std::vector<std::string> const& auth_events = {},
                                               std::vector<std::string> const& prev_events = {},
                                               std::string_view event_type = "m.room.member") -> SignedMembershipPdu
{
    auto const auth_json = json_id_array(auth_events);
    auto const prev_json = json_id_array(prev_events);

    auto const unsigned_json = std::string{"{\"type\":\""} + std::string{event_type} + "\",\"room_id\":\"" + room_id +
                               "\",\"sender\":\"" + sender + "\",\"state_key\":\"" + state_key +
                               "\",\"content\":{\"membership\":\"" + membership +
                               "\"},\"depth\":6,\"origin_server_ts\":2000,\"prev_events\":" + prev_json +
                               ",\"auth_events\":" + auth_json + "}";

    auto const signed_json = merovingian::federation::test::make_signed_event_json(
        unsigned_json, remote_origin, remote_key_id, remote_key_seed, "12");

    auto const parsed = merovingian::canonicaljson::parse_lossless(signed_json);
    auto const* policy = merovingian::rooms::find_room_version_policy("12");
    REQUIRE(policy != nullptr);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const event_id = merovingian::events::make_reference_hash_event_id(parsed.value, *policy);
    REQUIRE(!event_id.event_id.empty());
    return {signed_json, event_id.event_id};
}

[[nodiscard]] auto has_any_membership(merovingian::database::PersistentStore const& store, std::string const& room_id,
                                      std::string const& user_id) -> bool
{
    return std::ranges::any_of(store.memberships, [&](merovingian::database::PersistentMembership const& m) {
        return m.room_id == room_id && m.user_id == user_id;
    });
}

[[nodiscard]] auto has_receipt_for(merovingian::homeserver::HomeserverRuntime const& runtime,
                                   std::string const& room_id, std::string const& user_id) -> bool
{
    return std::ranges::any_of(runtime.receipts, [&](auto const& r) {
        return r.room_id == room_id && r.user_id == user_id;
    });
}

} // namespace

// --- FED-6: send_join/send_leave/send_knock endpoint/content agreement -------
// Spec (SS API v1.19, send_join/send_leave/send_knock): the receiving server
// MUST validate that the event type is m.room.member, the content membership
// matches the endpoint, the sender is a user on the origin server, and the
// state_key equals the sender. The membership stored must be derived from the
// event content, not from the endpoint path.
SCENARIO("send_join rejects a knock membership event with M_INVALID_PARAM", "[security][federation][fed-6]")
{
    GIVEN("a knock room and a remote user with a signed knock event")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "fed6host", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);

        auto options = merovingian::homeserver::CreateRoomOptions{};
        options.preset = "public_chat";
        auto join_rules_content = merovingian::canonicaljson::Object{};
        join_rules_content.push_back(merovingian::canonicaljson::make_member(
            "join_rule", merovingian::canonicaljson::Value{std::string{"knock"}}));
        auto join_rules_event = merovingian::canonicaljson::Object{};
        join_rules_event.push_back(merovingian::canonicaljson::make_member(
            "type", merovingian::canonicaljson::Value{std::string{"m.room.join_rules"}}));
        join_rules_event.push_back(merovingian::canonicaljson::make_member(
            "content", merovingian::canonicaljson::Value{std::move(join_rules_content)}));
        options.initial_state.push_back(merovingian::canonicaljson::Value{std::move(join_rules_event)});
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value, options);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const remote_user = std::string{"@knocker:"} + remote_origin;
        auto const& store = runtime.database.persistent_store;
        auto const knock_auth = merovingian::tests::fixture_auth_event_ids(store, room_id, remote_user, true);
        auto const knock_prev = merovingian::tests::fixture_prev_event_ids(store, room_id);
        auto const knock_pdu =
            make_signed_membership_body(room_id, remote_user, remote_user, "knock", knock_auth, knock_prev);

        WHEN("the knock event is PUT to send_join instead of send_knock")
        {
            auto const direct_acceptor = GENERATE(false, true);
            auto const target = "/_matrix/federation/v2/send_join/" + room_id + "/" + knock_pdu.event_id;
            auto const response = [&]() -> merovingian::federation::FederationResponse {
                if (direct_acceptor)
                {
                    auto envelope = merovingian::federation::parse_inbound_pdu_envelope(knock_pdu.json, "12");
                    REQUIRE(envelope.has_value());
                    envelope->origin = remote_origin;
                    auto const result = runtime.federation.membership_acceptor(
                        merovingian::federation::FederationEndpoint::send_join, room_id, {}, *envelope);
                    return {result.status, result.reason};
                }
                return merovingian::federation::handle_inbound_federation_request(runtime.federation,
                                                                                  signed_put(target, knock_pdu.json));
            }();

            THEN("the response is 400 M_INVALID_PARAM")
            {
                REQUIRE(response.status == 400U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* errcode = merovingian::tests::string_member(*root, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == std::string{"M_INVALID_PARAM"});
            }

            THEN("no membership row is written for the remote user")
            {
                REQUIRE_FALSE(has_any_membership(runtime.database.persistent_store, room_id, remote_user));
            }

            THEN("the remote user is not added to the room member list")
            {
                auto const room_it = std::ranges::find_if(runtime.database.rooms, [&](auto const& r) {
                    return r.room_id == room_id;
                });
                REQUIRE(room_it != runtime.database.rooms.end());
                REQUIRE_FALSE(std::ranges::any_of(room_it->members, [&](auto const& m) {
                    return m == remote_user;
                }));
            }
        }
    }
}

SCENARIO("membership endpoint validation precedes the acceptor", "[security][federation][fed-6]")
{
    GIVEN("an authenticated origin and a membership acceptor that records calls")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& federation = started.runtime.federation;
        merovingian::federation::upsert_remote(federation, remote_for_test());
        federation.room_version_resolver = [](std::string_view) {
            return std::string{"12"};
        };
        auto calls = 0U;
        federation.membership_acceptor = [&](auto, auto, auto, auto const&) {
            ++calls;
            auto result = merovingian::federation::MembershipAcceptResult{};
            result.accepted = true;
            result.status = 200U;
            result.room_version = "12";
            return result;
        };
        auto const endpoint = std::string{GENERATE("send_join", "send_leave", "send_knock")};
        auto const expected_membership = endpoint == "send_join"    ? std::string{"join"}
                                         : endpoint == "send_leave" ? std::string{"leave"}
                                                                    : std::string{"knock"};
        auto const room_id = std::string{"!"} + std::string(43U, 'A');
        auto const remote_user = std::string{"@member:"} + remote_origin;
        auto const invalid_field = std::string{
            GENERATE("membership", "empty_membership", "type", "sender", "state_key", "room_id", "event_id", "none")};
        auto const sender = invalid_field == "sender" ? std::string{"@forged:other.example.org"} : remote_user;
        auto const state_key = invalid_field == "state_key" ? std::string{"@other:"} + remote_origin : sender;
        auto const membership = invalid_field == "empty_membership" ? std::string{}
                                : invalid_field == "membership"
                                    ? (expected_membership == "knock" ? std::string{"join"} : std::string{"knock"})
                                    : expected_membership;
        auto const pdu = make_signed_membership_body(room_id, sender, state_key, membership, {}, {},
                                                     invalid_field == "type" ? "m.room.message" : "m.room.member");
        auto const target_room = invalid_field == "room_id" ? std::string{"!"} + std::string(43U, 'B') : room_id;
        auto const target_event = invalid_field == "event_id" ? std::string{"$wrong"} : pdu.event_id;
        auto const version = endpoint == "send_knock" ? std::string{"v1"} : std::string{"v2"};
        auto const target = "/_matrix/federation/" + version + "/" + endpoint + "/" + target_room + "/" + target_event;

        WHEN(endpoint + " receives an event with " + invalid_field + " mismatched")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(federation, signed_put(target, pdu.json));
            THEN("only an endpoint-consistent event can reach the acceptor")
            {
                REQUIRE(calls == (invalid_field == "none" ? 1U : 0U));
                REQUIRE(response.status == (invalid_field == "none" ? 200U : 400U));
                if (invalid_field != "none")
                {
                    auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                    auto const& root = std::get<merovingian::canonicaljson::Object>(parsed.value.storage());
                    REQUIRE(merovingian::tests::string_member(root, "errcode") != nullptr);
                    REQUIRE(*merovingian::tests::string_member(root, "errcode") == "M_INVALID_PARAM");
                }
            }
        }
    }
}

// Spec (SS API v1.19): GET /make_join/{roomId}/{userId},
// GET /make_knock/{roomId}/{userId}, GET /make_leave/{roomId}/{userId} all
// require {userId} to be a user on the origin server. The template provider
// must not be invoked when this precondition fails.
SCENARIO("make_membership rejects a userId that is not on the origin server", "[security][federation][fed-6]")
{
    GIVEN("a runtime with a wired make_membership template provider")
    {
        REQUIRE(sodium_init() >= 0);
        auto runtime = merovingian::federation::make_federation_runtime_state(federation_runtime_config());
        merovingian::federation::upsert_remote(runtime, remote_for_test());

        auto provider_calls = 0U;
        runtime.membership_template_provider = [&](merovingian::federation::FederationEndpoint, std::string_view,
                                                   std::string_view, std::vector<std::string> const&) {
            ++provider_calls;
            auto tmpl = merovingian::federation::MembershipEventTemplate{};
            tmpl.room_id = "!room:example.org";
            tmpl.user_id = "@member:remote.example.org";
            tmpl.membership = "join";
            tmpl.room_version = "12";
            tmpl.depth = 5;
            tmpl.prev_events = {"$prev:example.org"};
            tmpl.auth_events = {"$auth:example.org"};
            tmpl.content_json = R"({"membership":"join"})";
            return std::optional<merovingian::federation::MembershipEventTemplate>{std::move(tmpl)};
        };

        auto const endpoint = std::string{GENERATE("make_join", "make_leave", "make_knock")};
        auto const room_id = std::string{"!room:example.org"};
        auto const foreign_user = std::string{"@alice:example.org"};
        auto const target = "/_matrix/federation/v1/" + endpoint + "/" + room_id + "/" + foreign_user + "?ver=12";

        WHEN(endpoint + " receives a userId outside the authenticated origin")
        {
            auto const response =
                merovingian::federation::handle_inbound_federation_request(runtime, signed_get(target));

            THEN("the response is 400 M_INVALID_PARAM")
            {
                REQUIRE(response.status == 400U);
                auto const parsed = merovingian::canonicaljson::parse_lossless(response.body);
                REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
                auto const* root = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
                REQUIRE(root != nullptr);
                auto const* errcode = merovingian::tests::string_member(*root, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == std::string{"M_INVALID_PARAM"});
            }

            THEN("the template provider is never invoked")
            {
                REQUIRE(provider_calls == 0U);
            }
        }
    }
}

// --- FED-8: receipt EDUs must pass the server ACL ----------------------------
// Spec (SS API v1.19 §server-access-control-lists): for m.receipt, all
// receipts for a particular room ID MUST be ignored if the sending server is
// denied access to the room identified by that ID.
SCENARIO("receipt EDU from a server denied by room ACL is not stored", "[security][federation][fed-8]")
{
    GIVEN("a room whose ACL denies evil.example and a local membership row")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "fed8host", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        // Plant an m.room.server_acl state event that denies the remote origin.
        auto const acl_event_id = std::string{"$acl-fed8:example.org"};
        auto acl_content = merovingian::canonicaljson::Object{};
        acl_content.push_back(merovingian::canonicaljson::make_member("allow", string_array({"*"})));
        acl_content.push_back(merovingian::canonicaljson::make_member("deny", string_array({remote_origin})));
        auto acl_event = merovingian::database::PersistentEvent{};
        acl_event.event_id = acl_event_id;
        acl_event.room_id = room_id;
        acl_event.sender_user_id = user.value;
        acl_event.json = std::string{"{\"type\":\"m.room.server_acl\",\"state_key\":\"\",\"room_id\":\""} + room_id +
                         "\",\"sender\":\"" + user.value + "\",\"event_id\":\"" + acl_event_id +
                         "\",\"content\":{\"allow\":[\"*\"],\"deny\":[\"" + remote_origin +
                         "\"]},\"depth\":7,\"prev_events\":[],\"auth_events\":[],"
                         "\"origin_server_ts\":3000,\"hashes\":{\"sha256\":\"x\"}}";
        acl_event.depth = 7U;
        acl_event.stream_ordering = runtime.database.next_stream_ordering++;
        auto acl_state = std::optional<merovingian::database::PersistentStateEvent>{
            merovingian::database::PersistentStateEvent{room_id, "m.room.server_acl", "", acl_event_id}
        };
        REQUIRE(merovingian::database::store_event_with_state(runtime.database.persistent_store, std::move(acl_event),
                                                              std::move(acl_state)));

        // Recompute state so the ACL is visible to room_server_acl_provider.
        auto const* policy = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(policy != nullptr);
        REQUIRE(merovingian::homeserver::recompute_current_state(runtime.database.persistent_store, room_id, *policy));

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        WHEN("the denied remote origin sends a receipt for that room")
        {
            auto const receipt_user = std::string{"@reader:"} + remote_origin;
            auto const content = std::string{"{\""} + room_id + "\":{\"m.read\":{\"" + receipt_user +
                                 "\":{\"event_ids\":[\"$read:example.org\"],\"data\":{\"ts\":1234}}}}}";
            auto const target = std::string{"/_matrix/federation/v1/send/txn-fed8"};
            auto const body =
                std::string{"{\"origin\":\""} + remote_origin +
                "\",\"origin_server_ts\":1000,\"pdus\":[],\"edus\":[{\"edu_type\":\"m.receipt\",\"content\":" +
                content + "}]}";
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime.federation,
                                                                                             signed_put(target, body));

            THEN("the transaction itself succeeds")
            {
                REQUIRE(response.status == 200U);
            }

            THEN("no receipt is stored for the denied room")
            {
                REQUIRE_FALSE(has_receipt_for(runtime, room_id, receipt_user));
            }
        }

        WHEN("a receipt EDU contains both an ACL-denied room and an allowed room")
        {
            auto const direct_sink = GENERATE(false, true);
            auto const allowed = merovingian::homeserver::create_room(runtime, login.value);
            REQUIRE(allowed.ok);
            auto const receipt_user = std::string{"@reader:"} + remote_origin;
            // Both users are joined, so only the denied room's ACL can reject it.
            for (auto const& id : {room_id, allowed.value})
            {
                REQUIRE(merovingian::database::store_membership(runtime.database.persistent_store,
                                                                {id, receipt_user, "join", 1U}) ==
                        merovingian::database::MembershipStoreResult::stored);
            }
            runtime.receipts.push_back({room_id, "m.read", receipt_user, "$original", 1U, 2U});
            auto const content = std::string{"{\""} + room_id + "\":{\"m.read\":{\"" + receipt_user +
                                 "\":{\"event_ids\":[\"$denied-new\"],\"data\":{\"ts\":1234}}}},\"" + allowed.value +
                                 "\":{\"m.read\":{\"" + receipt_user +
                                 "\":{\"event_ids\":[\"$allowed-new\"],\"data\":{\"ts\":1234}}}}}";
            if (direct_sink)
            {
                auto const edu =
                    merovingian::federation::parse_inbound_edu_envelope("m.receipt", remote_origin, content);
                REQUIRE(edu.has_value());
                REQUIRE(runtime.federation.edu_sink(*edu).status ==
                        merovingian::federation::EduDispositionStatus::accepted);
            }
            else
            {
                auto const body =
                    std::string{"{\"origin\":\""} + remote_origin +
                    "\",\"origin_server_ts\":1000,\"pdus\":[],\"edus\":[{\"edu_type\":\"m.receipt\",\"content\":" +
                    content + "}]}";
                REQUIRE(merovingian::federation::handle_inbound_federation_request(
                            runtime.federation, signed_put("/_matrix/federation/v1/send/txn-fed8-mixed", body))
                            .status == 200U);
            }

            THEN("the denied receipt is unchanged and the allowed receipt is stored")
            {
                REQUIRE(runtime.receipts.size() == 2U);
                auto const denied_receipt = std::ranges::find_if(runtime.receipts, [&](auto const& receipt) {
                    return receipt.room_id == room_id;
                });
                REQUIRE(denied_receipt != runtime.receipts.end());
                REQUIRE(denied_receipt->event_id == "$original");
                REQUIRE(denied_receipt->ts == 1U);
                REQUIRE(denied_receipt->stream_id == 2U);
                auto const allowed_receipt = std::ranges::find_if(runtime.receipts, [&](auto const& receipt) {
                    return receipt.room_id == allowed.value;
                });
                REQUIRE(allowed_receipt != runtime.receipts.end());
                REQUIRE(allowed_receipt->event_id == "$allowed-new");
                REQUIRE(allowed_receipt->ts == 1234U);
            }
        }
    }
}

SCENARIO("receipt EDU subject must be a joined member of the room", "[security][federation][fed-8]")
{
    GIVEN("a room with local membership and a remote user who is not joined")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);

        auto const user = merovingian::homeserver::register_local_user(runtime, "fed8member", "CorrectHorse7!",
                                                                       merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user(runtime, user.value, "CorrectHorse7!", "DEVICE1");
        REQUIRE(login.ok);
        auto const room_result = merovingian::homeserver::create_room(runtime, login.value);
        REQUIRE(room_result.ok);
        auto const room_id = room_result.value;

        // Local server is in the room via the creator, but the remote receipt
        // subject is only invited (not joined).
        auto const receipt_user = std::string{"@reader:"} + remote_origin;
        REQUIRE(merovingian::database::store_membership(runtime.database.persistent_store,
                                                        {room_id, receipt_user, "invite", 1U}) ==
                merovingian::database::MembershipStoreResult::stored);

        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const content = std::string{"{\""} + room_id + "\":{\"m.read\":{\"" + receipt_user +
                             "\":{\"event_ids\":[\"$read:example.org\"],\"data\":{\"ts\":1234}}}}}";
        auto const target = std::string{"/_matrix/federation/v1/send/txn-fed8-not-joined"};
        auto const body =
            std::string{"{\"origin\":\""} + remote_origin +
            "\",\"origin_server_ts\":1000,\"pdus\":[],\"edus\":[{\"edu_type\":\"m.receipt\",\"content\":" + content +
            "}]}";

        WHEN("the remote origin sends a receipt for a non-joined user")
        {
            auto const response = merovingian::federation::handle_inbound_federation_request(runtime.federation,
                                                                                             signed_put(target, body));

            THEN("the transaction succeeds but no receipt is stored")
            {
                REQUIRE(response.status == 200U);
                REQUIRE_FALSE(has_receipt_for(runtime, room_id, receipt_user));
            }
        }
    }
}

SCENARIO("PDU admission requires current local room interest", "[security][federation][fed-11]")
{
    GIVEN("a signed PDU and a current membership row")
    {
        REQUIRE(sodium_init() >= 0);
        auto const server_name = std::string{GENERATE("example.org", "example.org:8448")};
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config(server_name));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        auto const membership = std::string{GENERATE("join", "invite", "knock", "leave", "ban")};
        auto const account = std::string{GENERATE("local", "remote", "malformed")};
        auto const local_user = merovingian::homeserver::register_local_user(
            runtime, "fed11interested", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(local_user.ok);
        auto const room_id = std::string{"!interest:remote.example.org"};
        auto const user_id = account == "local"    ? local_user.value
                             : account == "remote" ? std::string{"@remote:remote.example.org"}
                                                   : "not-a-user:" + server_name;
        REQUIRE(merovingian::database::store_membership(runtime.database.persistent_store,
                                                        {room_id, user_id, membership, 1U}) ==
                merovingian::database::MembershipStoreResult::stored);
        auto const unsigned_json =
            std::string{R"({"type":"m.room.message","room_id":")"} + room_id +
            R"(","sender":"@sender:remote.example.org","content":{"body":"admission","msgtype":"m.text"},"depth":1,"origin_server_ts":1000,"prev_events":[],"auth_events":[]})";
        auto const json = merovingian::federation::test::make_signed_event_json(unsigned_json, remote_origin,
                                                                                remote_key_id, remote_key_seed, "10");
        auto envelope = merovingian::federation::parse_inbound_pdu_envelope(json, "10");
        REQUIRE(envelope.has_value());
        envelope->origin = remote_origin;
        auto const before = runtime.database.persistent_store.events.size();
        auto const ordering = runtime.database.next_stream_ordering;
        auto const sync = runtime.database.persistent_store.next_sync_stream_id;
        WHEN("the envelope reaches the common PDU sink")
        {
            auto const result = runtime.federation.pdu_sink(*envelope);
            THEN("only joined, invited or knocking local users allow receipt processing")
            {
                auto const interested =
                    account == "local" && (membership == "join" || membership == "invite" || membership == "knock");
                CHECK(runtime.database.persistent_store.events.size() == before + (interested ? 1U : 0U));
                CHECK(runtime.database.next_stream_ordering == ordering + (interested ? 1U : 0U));
                CHECK(runtime.database.persistent_store.next_sync_stream_id == sync + (interested ? 1U : 0U));
                // Admission is distinct from auth: this PDU intentionally has no auth chain.
                CHECK(result.status == (interested ? merovingian::federation::PduIngestionStatus::rejected_auth
                                                   : merovingian::federation::PduIngestionStatus::rejected_invalid));
            }
        }
    }
}

// --- FED-11: PDUs for rooms with no local membership are dropped -------------
// Security audit FED-11: a remote server can spam PDUs for rooms this server is
// not in. Without a gate those events are stored as rejected and never pruned.
// This admission policy must distinguish unsolicited transactions from an
// active outbound join and must run before stream allocation or backfill.
// A room-version resolver is not such a signal (unknown rooms resolve to v10).
SCENARIO("PDUs for rooms with no local membership are not stored", "[security][federation][fed-11]")
{
    GIVEN("a runtime with no membership in evil.example rooms and a trusted remote")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        merovingian::homeserver::wire_federation_callbacks(runtime);
        merovingian::federation::upsert_remote(runtime.federation, remote_for_test());

        auto const worker_relay = GENERATE(false, true);
        runtime.federation.remote_key_resolver = [](auto, auto) {
            return std::optional{remote_for_test()};
        };
        auto const evil_room = std::string{"!unsolicited:remote.example.org"};
        auto const origin = std::string{remote_origin};
        // Unknown rooms currently resolve to legacy v10. Sign for that actual
        // policy, with a valid domain-bearing room ID, so admission is the only
        // reason this transaction could be discarded.
        auto const room_version = runtime.federation.room_version_resolver(evil_room);
        REQUIRE(room_version == "10");
        auto const event_ids_before = runtime.database.persistent_store.events.size();
        auto const sync_stream_before = runtime.database.persistent_store.next_sync_stream_id;
        auto const ordering_before = runtime.database.next_stream_ordering;
        auto seen_event_ids = std::set<std::string>{};

        WHEN("50 distinct signed PDUs for the unknown room arrive in federation transactions")
        {
            for (auto i = 0U; i < 50U; ++i)
            {
                auto const unsigned_pdu =
                    std::string{"{\"type\":\"m.room.message\",\"room_id\":\""} + evil_room +
                    "\",\"sender\":\"@spammer:" + origin + "\",\"content\":{\"body\":\"spam " + std::to_string(i) +
                    "\",\"msgtype\":\"m.text\"},\"depth\":1,\"origin_server_ts\":" + std::to_string(1000U + i) +
                    ",\"prev_events\":[],\"auth_events\":[]}";
                auto const signed_pdu = merovingian::federation::test::make_signed_event_json(
                    unsigned_pdu, origin, remote_key_id, remote_key_seed, room_version);
                auto const pdu =
                    merovingian::federation::parse_federation_pdu(signed_pdu, runtime.federation.room_version_resolver);
                REQUIRE(pdu.room_id == evil_room);
                REQUIRE(merovingian::federation::authorize_federation_pdu(pdu, origin, remote_for_test().signing_key)
                            .accepted);
                auto const parsed = merovingian::canonicaljson::parse_lossless(signed_pdu);
                REQUIRE(merovingian::events::verify_pdu_content_hash(parsed.value));
                REQUIRE(seen_event_ids.insert(pdu.event_id).second);
                auto const body = std::string{"{\"origin\":\""} + origin + "\",\"origin_server_ts\":1000,\"pdus\":[" +
                                  signed_pdu + "],\"edus\":[]}";
                auto const target = std::string{"/_matrix/federation/v1/send/txn-fed11-"} + std::to_string(i);
                if (worker_relay)
                {
                    auto frame = merovingian::canonicaljson::Object{};
                    for (auto const& [key, value] : std::vector<std::pair<std::string, std::string>>{
                             {"event_id",     pdu.event_id},
                             {"room_id",      evil_room   },
                             {"room_version", room_version},
                             {"origin",       origin      },
                             {"json",         signed_pdu  }
                    })
                    {
                        frame.push_back(
                            merovingian::canonicaljson::make_member(key, merovingian::canonicaljson::Value{value}));
                    }
                    auto const json = merovingian::canonicaljson::serialize_canonical(
                        merovingian::canonicaljson::Value{std::move(frame)});
                    REQUIRE(json.error == merovingian::canonicaljson::CanonicalJsonError::none);
                    auto const result = merovingian::homeserver::handle_pdu_ingest_request(runtime, json.output);
                    REQUIRE(result.status == merovingian::federation::PduIngestionStatus::rejected_invalid);
                    REQUIRE(result.reason == "unsolicited PDU for an uninterested room");
                }
                else
                {
                    auto const response = merovingian::federation::handle_inbound_federation_request(
                        runtime.federation, signed_put(target, body));
                    REQUIRE(response.status == 200U);
                }
            }

            THEN("no events for the unknown room are stored")
            {
                REQUIRE(seen_event_ids.size() == 50U);
                auto const events_after = runtime.database.persistent_store.events.size();
                CHECK(events_after == event_ids_before);
                CHECK(runtime.database.persistent_store.next_sync_stream_id == sync_stream_before);
                CHECK(runtime.database.next_stream_ordering == ordering_before);
                auto const any_evils = std::ranges::any_of(runtime.database.persistent_store.events,
                                                           [&](merovingian::database::PersistentEvent const& e) {
                                                               return e.room_id == evil_room;
                                                           });
                REQUIRE_FALSE(any_evils);
            }
        }
    }
}
