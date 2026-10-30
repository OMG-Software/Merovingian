// SPDX-License-Identifier: GPL-3.0-or-later
#include "../federation_signing_test_support.hpp"
#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_outbound_proxy.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

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

[[nodiscard]] auto response_string_field(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    REQUIRE(value != nullptr);
    REQUIRE(!value->empty());
    return *value;
}

struct SessionCredentials final
{
    std::string access_token{};
    std::string device_id{};
    std::string user_id{};
};

[[nodiscard]] auto register_session(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& localpart,
                                    std::string const& password) -> SessionCredentials
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(registration.response.status == 200U);
    return {
        response_string_field(registration.response.body, "access_token"),
        response_string_field(registration.response.body, "device_id"),
        std::string{"@"} + localpart + ":example.org",
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart, std::string const& password,
                                      std::string const& device_id) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(registration.response.status == 200U);

    auto const login_body =
        std::string{"{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"@"} + localpart +
        ":example.org\"},\"password\":\"" + password + "\",\"device_id\":\"" + device_id + "\"}";
    auto const login = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);
    return response_string_field(login.response.body, "access_token");
}

auto upload_device_keys(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                        std::string_view user_id, std::string_view device_id, std::string_view curve_key,
                        std::string_view ed_key) -> void
{
    auto const body = std::string{R"({"device_keys":{"user_id":")"} + std::string{user_id} + R"(","device_id":")" +
                      std::string{device_id} +
                      R"(","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:)" +
                      std::string{device_id} + R"(":")" + std::string{curve_key} + R"(","ed25519:)" +
                      std::string{device_id} + R"(":")" + std::string{ed_key} + R"("}}})";
    auto const upload = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body});
    REQUIRE(upload.response.status == 200U);
}

// device_secret_key MUST match the public key registered by upload_device_keys for
// this device. OTK signatures are now cryptographically verified server-side.
auto upload_one_time_key(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                         std::string_view user_id, std::string_view device_id, std::string_view key_id,
                         std::string_view key_value, std::string const& device_secret_key) -> void
{
    auto const otk_json =
        merovingian::federation::test::make_signed_otk_json(user_id, device_id, key_value, device_secret_key);
    auto const body =
        std::string{R"({"one_time_keys":{"signed_curve25519:)"} + std::string{key_id} + "\":" + otk_json + "}}";
    auto const upload = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body});
    REQUIRE(upload.response.status == 200U);
}

[[nodiscard]] auto sync_next_batch(std::string const& body) -> std::string
{
    return response_string_field(body, "next_batch");
}

[[nodiscard]] auto typing_user_ids_from_sync(std::string const& body, std::string const& room_id)
    -> std::vector<std::string>
{
    auto const root = parse_object(body);
    auto const* rooms = object_member_as_object(root, "rooms");
    if (rooms == nullptr)
    {
        return {};
    }
    auto const* joins = object_member_as_object(*rooms, "join");
    if (joins == nullptr)
    {
        return {};
    }
    auto const* room = object_member_as_object(*joins, room_id);
    if (room == nullptr)
    {
        return {};
    }
    auto const* ephemeral = object_member_as_object(*room, "ephemeral");
    if (ephemeral == nullptr)
    {
        return {};
    }
    auto const* events = object_member_as_array(*ephemeral, "events");
    if (events == nullptr)
    {
        return {};
    }
    for (auto const& ev : *events)
    {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&ev.storage());
        if (obj == nullptr)
        {
            continue;
        }
        auto const* type = string_member(*obj, "type");
        if (type == nullptr || *type != "m.typing")
        {
            continue;
        }
        auto const* content = object_member_as_object(*obj, "content");
        if (content == nullptr)
        {
            continue;
        }
        auto const* user_ids = object_member_as_array(*content, "user_ids");
        if (user_ids == nullptr)
        {
            return {};
        }
        auto out = std::vector<std::string>{};
        for (auto const& id : *user_ids)
        {
            if (auto const* s = std::get_if<std::string>(&id.storage()))
            {
                out.push_back(*s);
            }
        }
        return out;
    }
    return {};
}

} // namespace

SCENARIO("Integrated client-server flow covers auth devices rooms state joined rooms sync and logout",
         "[homeserver][client-server][integration]")
{
    GIVEN("registration-enabled client-server config")
    {
        auto const config = registration_enabled_config();

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("the flow completes and sync returns full event content")
            {
                REQUIRE(result.ok);
                REQUIRE(result.value.find("next_batch") != std::string::npos);
                REQUIRE(result.value.find("event_count") != std::string::npos);
                // Matrix E2EE: m.room.encrypted events are relayed opaquely
                // through /sync — clients decrypt locally.
                REQUIRE(result.value.find("m.room.encrypted") != std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated client-server flow covers account 3PID request add list and delete",
         "[homeserver][client-server][integration][account][3pid]")
{
    GIVEN("a running client-server runtime and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice", "CorrectHorse7!", "ALICE_3PID");
        auto identity_server = merovingian::tests::tls_mock::MockIdentityServer{
            merovingian::tests::tls_mock::MockIdentityServer::cooperative_responses({{"email", "user@example.org"}}
            )
        };
        identity_server.install(runtime);

        WHEN("an email address is requested and then associated with the account")
        {
            auto const email_response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/account/3pid/email/requestToken",
                          {},
                          identity_server.with_identity_server(
                              R"({"client_secret":"secret123","email":"user@example.org","send_attempt":1})")});
            REQUIRE(email_response.response.status == 200U);
            auto const email_body = parse_object(email_response.response.body);
            auto const* email_sid = string_member(email_body, "sid");
            REQUIRE(email_sid != nullptr);

            auto const add_body = std::string{R"({"client_secret":"secret123","sid":")"} + *email_sid +
                                  R"(","auth":{"type":"m.login.password","password":"CorrectHorse7!"}})";
            auto const add = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/3pid/add", alice, add_body});
            auto const listed = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/3pid", alice, {}});
            auto const deleted = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/3pid/delete", alice,
                          R"({"address":"user@example.org","medium":"email"})"});
            auto const listed_after_delete = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/3pid", alice, {}});

            THEN("the contact identifier flows through the account lifecycle")
            {
                REQUIRE(add.response.status == 200U);
                REQUIRE(listed.response.status == 200U);
                REQUIRE(listed.response.body.find("user@example.org") != std::string::npos);
                REQUIRE(listed.response.body.find("\"medium\":\"email\"") != std::string::npos);
                REQUIRE(deleted.response.status == 200U);
                REQUIRE(deleted.response.body.find("\"id_server_unbind_result\"") != std::string::npos);
                REQUIRE(listed_after_delete.response.status == 200U);
                REQUIRE(listed_after_delete.response.body.find("user@example.org") == std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated client-server flow rejects invalid and duplicate account 3PID associations",
         "[homeserver][client-server][integration][account][3pid]")
{
    GIVEN("a running client-server runtime with two logged-in users")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice", "CorrectHorse7!", "ALICE_3PID_NEG");
        auto const bob = register_and_login(runtime, "bob", "CorrectHorse8!", "BOB_3PID_NEG");
        auto identity_server = merovingian::tests::tls_mock::MockIdentityServer{
            merovingian::tests::tls_mock::MockIdentityServer::cooperative_responses({{"email", "user@example.org"}}
            )
        };
        identity_server.install(runtime);

        auto const email_response = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/account/3pid/email/requestToken",
                      {},
                      identity_server.with_identity_server(
                          R"({"client_secret":"secret123","email":"user@example.org","send_attempt":1})")});
        REQUIRE(email_response.response.status == 200U);
        auto const email_body = parse_object(email_response.response.body);
        auto const* email_sid = string_member(email_body, "sid");
        REQUIRE(email_sid != nullptr);

        WHEN("alice and bob attempt invalid or duplicate account 3PID associations")
        {
            auto const missing_session = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/account/3pid/add", alice,
                 R"({"client_secret":"secret123","sid":"missing-session","auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});
            auto const add_body = std::string{R"({"client_secret":"secret123","sid":")"} + *email_sid +
                                  R"(","auth":{"type":"m.login.password","password":"CorrectHorse7!"}})";
            auto const alice_add = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/3pid/add", alice, add_body});
            auto const duplicate_request = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/account/3pid/email/requestToken",
                          {},
                          R"({"client_secret":"secret456","email":"USER@example.org","send_attempt":1})"});
            auto const bob_duplicate_add = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/3pid/add", bob, add_body});

            THEN("invalid sessions and duplicate identifiers are rejected across the flow")
            {
                REQUIRE(missing_session.response.status == 400U);
                REQUIRE(missing_session.response.body.find("M_SESSION_NOT_VALIDATED") != std::string::npos);
                REQUIRE(alice_add.response.status == 200U);
                REQUIRE(duplicate_request.response.status == 400U);
                REQUIRE(duplicate_request.response.body.find("M_THREEPID_IN_USE") != std::string::npos);
                REQUIRE(bob_duplicate_add.response.status != 200U);
            }
        }
    }
}

SCENARIO("Integrated Matrix v1.19 interop flow covers login join key exchange messaging receipts and leave",
         "[homeserver][client-server][integration][conformance][e2ee]")
{
    GIVEN("two users using a normal encrypted private-room flow")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = register_and_login(runtime, "alice", "CorrectHorse7!", "ALICE_DEV");
        auto const bob = register_and_login(runtime, "bob", "CorrectHorse8!", "BOB_DEV");

        upload_device_keys(runtime, alice, "@alice:example.org", "ALICE_DEV", "ALICE_CURVE", "ALICE_ED");
        // Bob needs a real Ed25519 keypair: OTK signatures are verified server-side.
        auto const bob_kp = merovingian::federation::test::keypair_from_seed("flow-test-bob-seed");
        upload_device_keys(runtime, bob, "@bob:example.org", "BOB_DEV", "BOB_CURVE",
                           merovingian::federation::test::pubkey_b64(bob_kp));
        upload_one_time_key(runtime, bob, "@bob:example.org", "BOB_DEV", "BOB_OTK_AAAA", "BOB_OTK_VALUE",
                            bob_kp.secret_key);

        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST", "/_matrix/client/v3/createRoom", alice,
             R"({"preset":"private_chat","invite":["@bob:example.org"],"initial_state":[{"type":"m.room.encryption","state_key":"","content":{"algorithm":"m.megolm.v1.aes-sha2"}}]})"});
        REQUIRE(create.response.status == 200U);
        auto const room_id = response_string_field(create.response.body, "room_id");

        auto const alice_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
        REQUIRE(alice_initial_sync.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_initial_sync.response.body);

        auto const bob_initial_sync =
            merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", bob, {}});
        REQUIRE(bob_initial_sync.response.status == 200U);
        auto const bob_initial_body = parse_object(bob_initial_sync.response.body);
        auto const* initial_rooms = object_member_as_object(bob_initial_body, "rooms");
        REQUIRE(initial_rooms != nullptr);
        auto const* initial_invites = object_member_as_object(*initial_rooms, "invite");
        REQUIRE(initial_invites != nullptr);
        REQUIRE(object_member_as_object(*initial_invites, room_id) != nullptr);
        auto const bob_from = sync_next_batch(bob_initial_sync.response.body);

        WHEN("bob joins, alice performs the full key bootstrap, bob reads the message, and then leaves")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob, "{}"});
            REQUIRE(join.response.status == 200U);

            auto const bob_join_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + bob_from, bob, {}});
            REQUIRE(bob_join_sync.response.status == 200U);
            auto const bob_join_sync_body = parse_object(bob_join_sync.response.body);
            auto const* bob_rooms = object_member_as_object(bob_join_sync_body, "rooms");
            REQUIRE(bob_rooms != nullptr);
            auto const* bob_joins = object_member_as_object(*bob_rooms, "join");
            REQUIRE(bob_joins != nullptr);
            auto const* bob_room_entry = object_member_as_object(*bob_joins, room_id);
            REQUIRE(bob_room_entry != nullptr);
            auto const* bob_state = object_member_as_object(*bob_room_entry, "state");
            REQUIRE(bob_state != nullptr);
            auto const* bob_state_events = object_member_as_array(*bob_state, "events");
            REQUIRE(bob_state_events != nullptr);
            REQUIRE(std::ranges::any_of(*bob_state_events, [](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return type != nullptr && *type == "m.room.encryption";
            }));

            auto const alice_join_to_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", alice, {}});
            REQUIRE(alice_join_to_sync.response.status == 200U);
            auto const alice_join_to = sync_next_batch(alice_join_to_sync.response.body);

            auto const changes = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/keys/changes?from=" + alice_from + "&to=" + alice_join_to, alice, {}});
            REQUIRE(changes.response.status == 200U);
            auto const changes_body = parse_object(changes.response.body);
            auto const* changed = object_member_as_array(changes_body, "changed");
            REQUIRE(changed != nullptr);
            REQUIRE(std::ranges::any_of(*changed, [](merovingian::canonicaljson::Value const& value) {
                auto const* user_id = std::get_if<std::string>(&value.storage());
                return user_id != nullptr && *user_id == "@bob:example.org";
            }));

            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", alice,
                          R"({"device_keys":{"@bob:example.org":["BOB_DEV"]}})"});
            REQUIRE(query.response.status == 200U);
            auto const query_body = parse_object(query.response.body);
            auto const* device_keys = object_member_as_object(query_body, "device_keys");
            REQUIRE(device_keys != nullptr);
            auto const* bob_devices = object_member_as_object(*device_keys, "@bob:example.org");
            REQUIRE(bob_devices != nullptr);
            auto const* bob_device = object_member_as_object(*bob_devices, "BOB_DEV");
            REQUIRE(bob_device != nullptr);
            REQUIRE(string_member(*bob_device, "device_id") != nullptr);
            REQUIRE(*string_member(*bob_device, "device_id") == "BOB_DEV");
            REQUIRE(string_member(*bob_device, "user_id") != nullptr);
            REQUIRE(*string_member(*bob_device, "user_id") == "@bob:example.org");

            auto const claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", alice,
                          R"({"one_time_keys":{"@bob:example.org":{"BOB_DEV":"signed_curve25519"}}})"});
            REQUIRE(claim.response.status == 200U);
            REQUIRE(claim.response.body.find("BOB_OTK_VALUE") != std::string::npos);

            auto const send_to_device_body =
                std::string{"{\"messages\":{\"@bob:example.org\":{\"BOB_DEV\":{\"algorithm\":\"m.megolm.v1.aes-sha2\","
                            "\"room_id\":\""} +
                room_id + "\",\"session_id\":\"sid-interop-1\",\"session_key\":\"skey-interop-1\"}}}}";
            auto const send_to_device = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn-interop-room-key", alice, send_to_device_body});
            REQUIRE(send_to_device.response.status == 200U);

            auto const bob_key_sync = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/sync?since=" + sync_next_batch(bob_join_sync.response.body), bob, {}});
            REQUIRE(bob_key_sync.response.status == 200U);
            auto const bob_key_sync_body = parse_object(bob_key_sync.response.body);
            auto const* to_device = object_member_as_object(bob_key_sync_body, "to_device");
            REQUIRE(to_device != nullptr);
            auto const* to_device_events = object_member_as_array(*to_device, "events");
            REQUIRE(to_device_events != nullptr);
            REQUIRE(std::ranges::any_of(*to_device_events, [](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return type != nullptr && *type == "m.room_key";
            }));

            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.encrypted/txn-interop-event", alice,
                 R"({"algorithm":"m.megolm.v1.aes-sha2","ciphertext":"opaque-ciphertext","device_id":"ALICE_DEV","sender_key":"ALICE_CURVE","session_id":"sid-interop-1"})"});
            REQUIRE(send.response.status == 200U);
            auto const event_id = response_string_field(send.response.body, "event_id");

            auto const bob_message_sync = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/sync?since=" + sync_next_batch(bob_key_sync.response.body), bob, {}});
            REQUIRE(bob_message_sync.response.status == 200U);
            auto const bob_message_sync_body = parse_object(bob_message_sync.response.body);
            auto const* bob_message_rooms = object_member_as_object(bob_message_sync_body, "rooms");
            REQUIRE(bob_message_rooms != nullptr);
            auto const* bob_message_joins = object_member_as_object(*bob_message_rooms, "join");
            REQUIRE(bob_message_joins != nullptr);
            auto const* bob_message_room = object_member_as_object(*bob_message_joins, room_id);
            REQUIRE(bob_message_room != nullptr);
            auto const* timeline = object_member_as_object(*bob_message_room, "timeline");
            REQUIRE(timeline != nullptr);
            auto const* events = object_member_as_array(*timeline, "events");
            REQUIRE(events != nullptr);
            REQUIRE(std::ranges::any_of(*events, [&event_id](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* current_event_id = event == nullptr ? nullptr : string_member(*event, "event_id");
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return current_event_id != nullptr && type != nullptr && *current_event_id == event_id &&
                       *type == "m.room.encrypted";
            }));

            auto const receipt = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, bob, "{}"});
            REQUIRE(receipt.response.status == 200U);

            auto const alice_receipt_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + alice_from, alice, {}});
            REQUIRE(alice_receipt_sync.response.status == 200U);
            auto const alice_receipt_sync_body = parse_object(alice_receipt_sync.response.body);
            auto const* alice_rooms = object_member_as_object(alice_receipt_sync_body, "rooms");
            REQUIRE(alice_rooms != nullptr);
            auto const* alice_joins = object_member_as_object(*alice_rooms, "join");
            REQUIRE(alice_joins != nullptr);
            auto const* alice_room = object_member_as_object(*alice_joins, room_id);
            REQUIRE(alice_room != nullptr);
            auto const* alice_ephemeral = object_member_as_object(*alice_room, "ephemeral");
            REQUIRE(alice_ephemeral != nullptr);
            auto const* alice_ephemeral_events = object_member_as_array(*alice_ephemeral, "events");
            REQUIRE(alice_ephemeral_events != nullptr);
            REQUIRE(std::ranges::any_of(*alice_ephemeral_events, [&event_id](
                                                                     merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                auto const* receipt_event = content == nullptr ? nullptr : object_member_as_object(*content, event_id);
                auto const* reads =
                    receipt_event == nullptr ? nullptr : object_member_as_object(*receipt_event, "m.read");
                return type != nullptr && *type == "m.receipt" && reads != nullptr &&
                       object_member_as_object(*reads, "@bob:example.org") != nullptr;
            }));

            auto const leave = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob, "{}"});
            REQUIRE(leave.response.status == 200U);

            THEN("the typical encrypted-room flow works end to end")
            {
                auto const bob_joined_rooms = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/joined_rooms", bob, {}});
                REQUIRE(bob_joined_rooms.response.status == 200U);
                REQUIRE(bob_joined_rooms.response.body.find(room_id) == std::string::npos);

                auto const bob_member_state = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET",
                              "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/%40bob%3Aexample.org",
                              alice,
                              {}});
                REQUIRE(bob_member_state.response.status == 200U);
                auto const bob_member_state_body = parse_object(bob_member_state.response.body);
                auto const* membership = string_member(bob_member_state_body, "membership");
                REQUIRE(membership != nullptr);
                REQUIRE(*membership == "leave");
            }
        }
    }
}

SCENARIO("Integrated Matrix v1.19 interop flow works with registration-issued sessions and joined-room bootstrap",
         "[homeserver][client-server][integration][conformance][e2ee][registration]")
{
    GIVEN("two users relying on the access tokens and device ids returned by registration")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = register_session(runtime, "alice_reg", "CorrectHorse7!");
        auto const bob = register_session(runtime, "bob_reg", "CorrectHorse8!");

        upload_device_keys(runtime, alice.access_token, alice.user_id, alice.device_id, "ALICE_REG_CURVE",
                           "ALICE_REG_ED");
        auto const bob_reg_kp = merovingian::federation::test::keypair_from_seed("flow-test-bob-reg-seed");
        upload_device_keys(runtime, bob.access_token, bob.user_id, bob.device_id, "BOB_REG_CURVE",
                           merovingian::federation::test::pubkey_b64(bob_reg_kp));
        upload_one_time_key(runtime, bob.access_token, bob.user_id, bob.device_id, "BOB_REG_OTK_AAAA",
                            "BOB_REG_OTK_VALUE", bob_reg_kp.secret_key);

        auto const create_body = std::string{"{\"preset\":\"private_chat\",\"invite\":[\""} + bob.user_id +
                                 "\"],\"initial_state\":[{\"type\":\"m.room.encryption\",\"state_key\":\"\","
                                 "\"content\":{\"algorithm\":\"m.megolm.v1.aes-sha2\"}}]}";
        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice.access_token, create_body});
        REQUIRE(create.response.status == 200U);
        auto const room_id = response_string_field(create.response.body, "room_id");

        auto const alice_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", alice.access_token, {}});
        REQUIRE(alice_initial_sync.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_initial_sync.response.body);

        auto const bob_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", bob.access_token, {}});
        REQUIRE(bob_initial_sync.response.status == 200U);
        auto const bob_initial_sync_body = parse_object(bob_initial_sync.response.body);
        auto const* bob_initial_rooms = object_member_as_object(bob_initial_sync_body, "rooms");
        REQUIRE(bob_initial_rooms != nullptr);
        auto const* bob_initial_invites = object_member_as_object(*bob_initial_rooms, "invite");
        REQUIRE(bob_initial_invites != nullptr);
        auto const* bob_invited_room = object_member_as_object(*bob_initial_invites, room_id);
        REQUIRE(bob_invited_room != nullptr);
        auto const* invite_state = object_member_as_object(*bob_invited_room, "invite_state");
        REQUIRE(invite_state != nullptr);
        auto const* invite_events = object_member_as_array(*invite_state, "events");
        REQUIRE(invite_events != nullptr);
        REQUIRE_FALSE(invite_events->empty());
        auto const bob_from = sync_next_batch(bob_initial_sync.response.body);

        WHEN("the invitee joins and the room bootstraps E2EE using only registration-issued sessions")
        {
            auto const join = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob.access_token, "{}"});
            REQUIRE(join.response.status == 200U);

            auto const members = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/rooms/" + room_id + "/members?not_membership=leave",
                          alice.access_token,
                          {}});
            REQUIRE(members.response.status == 200U);
            auto const members_body = parse_object(members.response.body);
            auto const* member_chunk = object_member_as_array(members_body, "chunk");
            REQUIRE(member_chunk != nullptr);
            REQUIRE(std::ranges::any_of(*member_chunk, [&alice](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
                auto const* event_id = event == nullptr ? nullptr : string_member(*event, "event_id");
                return state_key != nullptr && event_id != nullptr && *state_key == alice.user_id;
            }));
            REQUIRE(std::ranges::any_of(*member_chunk, [&bob](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
                auto const* event_id = event == nullptr ? nullptr : string_member(*event, "event_id");
                auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
                return state_key != nullptr && event_id != nullptr && membership != nullptr &&
                       *state_key == bob.user_id && *membership == "join";
            }));

            auto const bob_join_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + bob_from, bob.access_token, {}});
            REQUIRE(bob_join_sync.response.status == 200U);
            auto const bob_join_sync_body = parse_object(bob_join_sync.response.body);
            auto const* bob_rooms = object_member_as_object(bob_join_sync_body, "rooms");
            REQUIRE(bob_rooms != nullptr);
            auto const* bob_joins = object_member_as_object(*bob_rooms, "join");
            REQUIRE(bob_joins != nullptr);
            auto const* bob_room_entry = object_member_as_object(*bob_joins, room_id);
            REQUIRE(bob_room_entry != nullptr);
            auto const* bob_state = object_member_as_object(*bob_room_entry, "state");
            REQUIRE(bob_state != nullptr);
            auto const* bob_state_events = object_member_as_array(*bob_state, "events");
            REQUIRE(bob_state_events != nullptr);
            REQUIRE(std::ranges::any_of(*bob_state_events, [](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return type != nullptr && *type == "m.room.create";
            }));
            REQUIRE(std::ranges::any_of(*bob_state_events, [](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return type != nullptr && *type == "m.room.encryption";
            }));
            // Spec (GET /sync, JoinedRoom `state`, v1.19): state "up to the start of the
            // timeline". Bob's join is in this sync's timeline, so it is not repeated in `state`;
            // a client takes the room's state from `state` followed by the timeline.
            auto const* bob_timeline = object_member_as_object(*bob_room_entry, "timeline");
            REQUIRE(bob_timeline != nullptr);
            auto const* bob_timeline_events = object_member_as_array(*bob_timeline, "events");
            REQUIRE(bob_timeline_events != nullptr);
            auto const is_bob_join = [&bob](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                auto const* state_key = event == nullptr ? nullptr : string_member(*event, "state_key");
                auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                auto const* membership = content == nullptr ? nullptr : string_member(*content, "membership");
                return type != nullptr && state_key != nullptr && content != nullptr && membership != nullptr &&
                       *type == "m.room.member" && *state_key == bob.user_id && *membership == "join";
            };
            REQUIRE((std::ranges::any_of(*bob_state_events, is_bob_join) ||
                     std::ranges::any_of(*bob_timeline_events, is_bob_join)));

            auto const alice_join_to_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync", alice.access_token, {}});
            REQUIRE(alice_join_to_sync.response.status == 200U);
            auto const alice_join_to = sync_next_batch(alice_join_to_sync.response.body);

            auto const changes = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/keys/changes?from=" + alice_from + "&to=" + alice_join_to,
                          alice.access_token,
                          {}});
            REQUIRE(changes.response.status == 200U);
            REQUIRE(changes.response.body.find(bob.user_id) != std::string::npos);

            auto const query_body_json =
                std::string{"{\"device_keys\":{\""} + bob.user_id + "\":[\"" + bob.device_id + "\"]}}";
            auto const query = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/query", alice.access_token, query_body_json});
            REQUIRE(query.response.status == 200U);
            auto const query_body = parse_object(query.response.body);
            auto const* device_keys = object_member_as_object(query_body, "device_keys");
            REQUIRE(device_keys != nullptr);
            auto const* bob_devices = object_member_as_object(*device_keys, bob.user_id);
            REQUIRE(bob_devices != nullptr);
            auto const* bob_device = object_member_as_object(*bob_devices, bob.device_id);
            REQUIRE(bob_device != nullptr);
            auto const* bob_keys = object_member_as_object(*bob_device, "keys");
            REQUIRE(bob_keys != nullptr);
            REQUIRE(string_member(*bob_keys, "curve25519:" + bob.device_id) != nullptr);
            REQUIRE(string_member(*bob_keys, "ed25519:" + bob.device_id) != nullptr);

            auto const claim_body_json = std::string{"{\"one_time_keys\":{\""} + bob.user_id + "\":{\"" +
                                         bob.device_id + "\":\"signed_curve25519\"}}}";
            auto const claim = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/keys/claim", alice.access_token, claim_body_json});
            REQUIRE(claim.response.status == 200U);
            REQUIRE(claim.response.body.find("BOB_REG_OTK_VALUE") != std::string::npos);

            auto const send_to_device_body =
                std::string{"{\"messages\":{\""} + bob.user_id + "\":{\"" + bob.device_id +
                "\":{\"algorithm\":\"m.megolm.v1.aes-sha2\",\"room_id\":\"" + room_id +
                "\",\"session_id\":\"sid-reg-interop-1\",\"session_key\":\"skey-reg-interop-1\"}}}}";
            auto const send_to_device = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.room_key/txn-reg-room-key", alice.access_token,
                          send_to_device_body});
            REQUIRE(send_to_device.response.status == 200U);

            auto const bob_key_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/sync?since=" + sync_next_batch(bob_join_sync.response.body),
                          bob.access_token,
                          {}});
            REQUIRE(bob_key_sync.response.status == 200U);
            auto const bob_key_sync_body = parse_object(bob_key_sync.response.body);
            auto const* to_device = object_member_as_object(bob_key_sync_body, "to_device");
            REQUIRE(to_device != nullptr);
            auto const* to_device_events = object_member_as_array(*to_device, "events");
            REQUIRE(to_device_events != nullptr);
            REQUIRE(std::ranges::any_of(*to_device_events, [](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                auto const* session_id = content == nullptr ? nullptr : string_member(*content, "session_id");
                return type != nullptr && content != nullptr && session_id != nullptr && *type == "m.room_key" &&
                       *session_id == "sid-reg-interop-1";
            }));

            auto const send_body =
                std::string{"{\"algorithm\":\"m.megolm.v1.aes-sha2\",\"ciphertext\":\"opaque-ciphertext\","
                            "\"device_id\":\""} +
                alice.device_id + "\",\"sender_key\":\"ALICE_REG_CURVE\",\"session_id\":\"sid-reg-interop-1\"}";
            auto const send = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.encrypted/txn-reg-interop-event",
                          alice.access_token, send_body});
            REQUIRE(send.response.status == 200U);
            auto const event_id = response_string_field(send.response.body, "event_id");

            auto const bob_message_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/sync?since=" + sync_next_batch(bob_key_sync.response.body),
                          bob.access_token,
                          {}});
            REQUIRE(bob_message_sync.response.status == 200U);
            auto const bob_message_sync_body = parse_object(bob_message_sync.response.body);
            auto const* bob_message_rooms = object_member_as_object(bob_message_sync_body, "rooms");
            REQUIRE(bob_message_rooms != nullptr);
            auto const* bob_message_joins = object_member_as_object(*bob_message_rooms, "join");
            REQUIRE(bob_message_joins != nullptr);
            auto const* bob_message_room = object_member_as_object(*bob_message_joins, room_id);
            REQUIRE(bob_message_room != nullptr);
            auto const* timeline = object_member_as_object(*bob_message_room, "timeline");
            REQUIRE(timeline != nullptr);
            auto const* events = object_member_as_array(*timeline, "events");
            REQUIRE(events != nullptr);
            REQUIRE(std::ranges::any_of(*events, [&event_id](merovingian::canonicaljson::Value const& value) {
                auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                auto const* current_event_id = event == nullptr ? nullptr : string_member(*event, "event_id");
                auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                return current_event_id != nullptr && type != nullptr && *current_event_id == event_id &&
                       *type == "m.room.encrypted";
            }));

            auto const receipt = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id,
                          bob.access_token, "{}"});
            REQUIRE(receipt.response.status == 200U);

            auto const alice_receipt_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + alice_from, alice.access_token, {}});
            REQUIRE(alice_receipt_sync.response.status == 200U);
            REQUIRE(alice_receipt_sync.response.body.find("\"m.receipt\"") != std::string::npos);
            REQUIRE(alice_receipt_sync.response.body.find(bob.user_id) != std::string::npos);

            auto const leave = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/leave", bob.access_token, "{}"});
            REQUIRE(leave.response.status == 200U);

            THEN("the full registration-shaped encrypted-room flow works end to end")
            {
                auto const bob_joined_rooms = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/joined_rooms", bob.access_token, {}});
                REQUIRE(bob_joined_rooms.response.status == 200U);
                REQUIRE(bob_joined_rooms.response.body.find(room_id) == std::string::npos);

                auto const bob_member_state = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET",
                              "/_matrix/client/v3/rooms/" + room_id + "/state/m.room.member/%40bob_reg%3Aexample.org",
                              alice.access_token,
                              {}});
                REQUIRE(bob_member_state.response.status == 200U);
                auto const bob_member_state_body = parse_object(bob_member_state.response.body);
                auto const* membership = string_member(bob_member_state_body, "membership");
                REQUIRE(membership != nullptr);
                REQUIRE(*membership == "leave");
            }
        }
    }
}

SCENARIO("Integrated client-server flow fails closed on invalid config", "[homeserver][client-server][integration]")
{
    GIVEN("an invalid listener config")
    {
        auto listeners = merovingian::config::ListenersConfig{};
        listeners.client.bind = "0.0.0.0:not-a-port";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            listeners,
            merovingian::tests::in_memory_database_config(),
            merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{},
        };

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("startup fails before serving API requests")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "configuration is invalid");
            }
        }
    }
}

SCENARIO("POST /register without auth returns 401 UI-auth challenge", "[homeserver][client-server][register][uiauth]")
{
    GIVEN("a registration-enabled server")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client sends a register request without an auth field")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/register", {}, R"({"username":"alice","password":"CorrectHorse7!"})"});

            THEN("the server returns 401 with the registration_token flow and a session")
            {
                REQUIRE(response.response.status == 401U);
                REQUIRE(response.response.body.find("m.login.registration_token") != std::string::npos);
                REQUIRE(response.response.body.find("flows") != std::string::npos);
                REQUIRE(response.response.body.find("session") != std::string::npos);
            }
        }
    }
}

SCENARIO("POST /register with auth completes registration", "[homeserver][client-server][register][uiauth]")
{
    GIVEN("a registration-enabled server")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client sends a register request with a valid auth token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST",
                     "/_matrix/client/v3/register",
                     {},
                     merovingian::tests::registration_json("alice", "CorrectHorse7!")});

            THEN("the server returns 200 with the new user_id")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("user_id") != std::string::npos);
                REQUIRE(response.response.body.find("@alice:") != std::string::npos);
            }
        }
    }
}

SCENARIO("POST /account/password changes the authenticated user's password",
         "[homeserver][client-server][account][password]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const value_begin = begin + key.size();
        auto const value_end = login.response.body.find('"', value_begin);
        auto const token = login.response.body.substr(value_begin, value_end - value_begin);

        WHEN("the user changes their password with the correct current password in the auth block")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/v3/account/password", token,
                 R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!"},"new_password":"NewHorse99!!"})"});

            THEN("the server returns 200 and the new password is accepted at login")
            {
                REQUIRE(response.response.status == 200U);
                auto const relogin = merovingian::homeserver::handle_client_server_request(
                    rt,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"NewHorse99!!","device_id":"DEV2"})"});
                REQUIRE(relogin.response.status == 200U);
            }
        }
    }
}

SCENARIO("POST /account/password without an access token returns 401", "[homeserver][client-server][account][password]")
{
    GIVEN("a registration-enabled server with no authenticated session")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a password change is attempted without providing an access token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/account/password", {}, R"({"new_password":"NewHorse99!!"})"});

            THEN("the server returns 401 M_MISSING_TOKEN")
            {
                // Spec §5.7.2: M_MISSING_TOKEN when no bearer token is provided at all.
                // M_UNKNOWN_TOKEN applies only when a token is present but not recognised.
                REQUIRE(response.response.status == 401U);
                REQUIRE(response.response.body.find("M_MISSING_TOKEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /profile/{userId} for an unknown user returns 404", "[homeserver][client-server][profile]")
{
    GIVEN("a registration-enabled server with no registered users")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a client requests the profile for a user that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40missing%3Aexample.org", {}, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19, GET /profile/{userId} and GET /profile/{userId}/{keyName};
// Server-Server API v1.19, GET /_matrix/federation/v1/query/profile.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1queryprofile
//
// A user of another server has no profile here: "Performs a query to get profile information ... for
// a given user. Homeservers MUST only query profiles for users that belong to the target server". So
// this server asks the user's server and answers with what it says, and its 404 ("The user does not
// exist, does not have a profile or the queried field does not exist") is a 404 here.
SCENARIO("GET /profile/{userId} for a user of another server asks that server over federation",
         "[homeserver][client-server][profile][fed-endpoints]")
{
    GIVEN("a server and a remote server that answers query/profile for @bob but not for @nobody")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto tls_context = std::move(*tls.context);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        rt.homeserver.test_forced_outbound_resolution["remote.example.net"] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        auto const ok_profile = merovingian::tests::tls_mock::json_http_response(
            "200 OK", R"({"displayname":"Bob","avatar_url":"mxc://remote.example.net/a","evil":"ignored"})");
        auto const not_found = merovingian::tests::tls_mock::json_http_response(
            "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"no such user"})");
        auto const responses = std::vector<std::pair<std::string, std::string>>{
            {"user_id=%40bob%3Aremote.example.net&field=displayname", ok_profile},
            {"user_id=%40bob%3Aremote.example.net",                   ok_profile},
            {"user_id=%40nobody%3Aremote.example.net",                not_found },
        };
        auto captured = std::vector<std::string>{};
        auto server_thread = std::thread{[&]() {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
        }};
        auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("a client reads the whole profile of @bob:remote.example.net")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40bob%3Aremote.example.net", {}, {}});

            THEN("the answer is 200 with displayname and avatar_url only, from one federation request")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"displayname\":\"Bob\"") != std::string::npos);
                REQUIRE(response.response.body.find("mxc://remote.example.net/a") != std::string::npos);
                // Rule 6: a remote answer is relayed only in its spec fields.
                REQUIRE(response.response.body.find("evil") == std::string::npos);
                REQUIRE(captured.size() == 1U);
                REQUIRE(captured[0].find("GET /_matrix/federation/v1/query/profile?user_id=") == 0U);
            }
        }

        WHEN("a client reads only the displayname")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40bob%3Aremote.example.net/displayname", {}, {}});

            THEN("the answer is 200 with just that field and the federation request named it")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"displayname\":\"Bob\"") != std::string::npos);
                REQUIRE(response.response.body.find("avatar_url") == std::string::npos);
                REQUIRE(captured.size() == 1U);
                REQUIRE(captured[0].find("&field=displayname") != std::string::npos);
            }
        }

        WHEN("the remote server says the user does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40nobody%3Aremote.example.net/displayname", {}, {}});

            THEN("the client gets 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/displayname updates the authenticated user's displayname",
         "[homeserver][client-server][profile]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(
            begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user updates their displayname")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                     R"({"displayname":"Alice Beta"})"});

            THEN("the server returns 200 and the profile reflects the new displayname")
            {
                REQUIRE(response.response.status == 200U);
                auto const profile = merovingian::homeserver::handle_client_server_request(
                    rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org", {}, {}});
                REQUIRE(profile.response.status == 200U);
                REQUIRE(profile.response.body.find("Alice Beta") != std::string::npos);
            }
        }
    }
}

SCENARIO("PUT /profile/{userId}/displayname for another user returns 403", "[homeserver][client-server][profile]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(
            begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user attempts to update another user's displayname")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", "/_matrix/client/v3/profile/%40bob%3Aexample.org/displayname", token,
                     R"({"displayname":"Bob Impersonated"})"});

            THEN("the server returns 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /profile/{userId}/{keyName} returns only the requested field", "[homeserver][client-server][profile]")
{
    GIVEN("a registered user with a displayname set")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(
            begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());
        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"PUT", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", token,
                 R"({"displayname":"Alice Beta"})"});

        WHEN("the displayname field is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/displayname", {}, {}});

            THEN("the server returns 200 with only that field")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("Alice Beta") != std::string::npos);
                REQUIRE(response.response.body.find("avatar_url") == std::string::npos);
            }
        }

        WHEN("an unset field is requested")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/profile/%40alice%3Aexample.org/avatar_url", {}, {}});

            THEN("the server returns 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /rooms/{roomId}/state for an unknown room returns 403", "[homeserver][client-server][rooms][state]")
{
    GIVEN("a registered and logged-in user")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        std::ignore = merovingian::homeserver::handle_client_server_request(
            rt, {"POST",
                 "/_matrix/client/v3/register",
                 {},
                 merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        auto const login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"DEV1"})"});
        REQUIRE(login.response.status == 200U);
        auto const key = std::string{"\"access_token\":\""};
        auto const begin = login.response.body.find(key);
        REQUIRE(begin != std::string::npos);
        auto const token = login.response.body.substr(
            begin + key.size(), login.response.body.find('"', begin + key.size()) - begin - key.size());

        WHEN("the user requests state for a room that does not exist")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/rooms/!bad-room%3Aexample.org/state", token, {}});

            THEN("the server returns 403 M_FORBIDDEN")
            {
                REQUIRE(response.response.status == 403U);
                REQUIRE(response.response.body.find("M_FORBIDDEN") != std::string::npos);
            }
        }
    }
}

SCENARIO("GET /_merovingian/admin/audit filters by category and event_type query parameters",
         "[homeserver][admin][audit]")
{
    GIVEN("a started homeserver runtime with an admin user and a seeded audit row")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_runtime(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        // The audit-sink install is now bound to `started.runtime`'s
        // lifetime via its `audit_sink_scope` member, so no explicit
        // scope guard is needed at this call site. The sink is
        // installed on runtime construction (against the local
        // `started` storage, which is the caller's stable address
        // via C++17 NRVO) and cleared on `started` going out of
        // scope — so the pointer never leaks into a later test in
        // the same process.

        // Bootstrap the admin user so the audit endpoint will accept the
        // request without returning 401. After bootstrap, log in once to
        // mint the access_token used as the `access_token` field below.
        auto const admin_bootstrap = merovingian::homeserver::bootstrap_admin_user(runtime, "ops", "CorrectHorse7!");
        REQUIRE(admin_bootstrap.ok);
        auto const admin_login = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, "@ops:example.org|CorrectHorse7!|OPSDEV"});
        REQUIRE(admin_login.status == 200U);
        // The local-router login handler returns the access token in
        // the response body as a plain string (no JSON wrapper). The
        // /admin/audit endpoint accepts the token in the `access_token`
        // field of the LocalHttpRequest, which is where the auth header
        // would be parsed in production.
        auto const admin_token = admin_login.body;

        // Seed an `auth` row by issuing a bad login — the local-router
        // path will route it through `log_diagnostic_audit` and append a
        // `login.rejected` row at category=auth.
        std::ignore = merovingian::homeserver::handle_local_http_request(
            runtime, {"POST", "/_matrix/client/v3/login", {}, "@nope:example.org|wrong-password|DEV1"});

        WHEN("the audit endpoint is called with ?category=auth&event_type=login.rejected")
        {
            auto const response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit?category=auth&event_type=login.rejected", admin_token, {}});

            THEN("the response is 200 and contains the seeded auth row")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("filter_category=auth") != std::string::npos);
                REQUIRE(response.body.find("filter_event_type=login.rejected") != std::string::npos);
                REQUIRE(response.body.find("entry=auth:login.rejected") != std::string::npos);
            }
        }

        WHEN("the audit endpoint is called with a bogus category")
        {
            auto const response = merovingian::homeserver::handle_local_http_request(
                runtime, {"GET", "/_merovingian/admin/audit?category=authz", admin_token, {}});

            THEN("the response is 400 with a clear error message")
            {
                REQUIRE(response.status == 400U);
                REQUIRE(response.body.find("unknown audit category") != std::string::npos);
            }
        }
    }
}

// WS3: /_merovingian/admin/* routes are now wired into the production
// client-server dispatch (previously they 404'd on the public client port —
// only reachable via the test-only local router). This scenario exercises the
// full handle_client_server_request path: the allow() rate-limit gate runs
// first, then the admin branch dispatches to the local router. It asserts the
// per-IP /_merovingian/admin/ prefix policy (30/60s) inherited from
// default_client_rate_limit_config() is enforced end-to-end and that a second
// source IP is unaffected — proving admin routes are served AND throttled in
// production, with no double-count (a single allow() call per request).
SCENARIO("/_merovingian/admin/* routes are served and rate-limited on the client port",
         "[homeserver][admin][rate-limit][integration]")
{
    GIVEN("a started client-server runtime with a bootstrapped and logged-in admin")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        // start_client_server installs the production rate-limit engine built
        // from default_client_rate_limit_config(), which carries the
        // /_merovingian/admin/ -> 30/60s per-IP prefix policy under test.

        auto const admin_bootstrap =
            merovingian::homeserver::bootstrap_admin_user(rt.homeserver, "ops", "CorrectHorse7!");
        REQUIRE(admin_bootstrap.ok);
        // Log in through the production dispatch path so the admin carries a
        // real session token the admin_auth_denied gate will accept.
        auto const admin_login = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@ops:example.org"},"password":"CorrectHorse7!","device_id":"OPSDEV"})"});
        REQUIRE(admin_login.response.status == 200U);
        auto const admin_token = response_string_field(admin_login.response.body, "access_token");

        // LocalHttpRequest aggregate-init order: method, target, access_token,
        // body, headers, remote_addr. Setting remote_addr drives the per-IP
        // bucket key in allow(); an empty remote_addr would collapse to the
        // "unknown" bucket and mask per-IP isolation.
        auto const admin_health = [&](std::string const& ip) {
            return merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_merovingian/admin/health", admin_token, {}, {}, ip});
        };

        WHEN("30 admin health requests arrive from one source IP")
        {
            for (std::uint32_t i = 0U; i < 30U; ++i)
            {
                auto const resp = admin_health("10.0.0.1");
                REQUIRE(resp.response.status == 200U);
            }

            THEN("the 31st request from that IP is rejected 429 M_LIMIT_EXCEEDED")
            {
                auto const denied = admin_health("10.0.0.1");
                REQUIRE(denied.response.status == 429U);
                REQUIRE(denied.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
            AND_THEN("a request from a different source IP is unaffected")
            {
                auto const other = admin_health("10.0.0.2");
                REQUIRE(other.response.status == 200U);
            }
        }
    }
}

SCENARIO("Typing notifications are delivered via ephemeral events in /sync",
         "[homeserver][client-server][integration][sync][typing][regression]")
{
    GIVEN("two joined users with active sync streams")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = register_session(runtime, "alice_typing", "CorrectHorse7!");
        auto const bob = register_session(runtime, "bob_typing", "CorrectHorse8!");

        auto const create_body = std::string{"{\"preset\":\"private_chat\",\"invite\":[\""} + bob.user_id + "\"]}";
        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice.access_token, create_body});
        REQUIRE(create.response.status == 200U);
        auto const room_id = response_string_field(create.response.body, "room_id");

        auto const bob_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", bob.access_token, {}});
        REQUIRE(bob_initial_sync.response.status == 200U);
        auto const bob_from = sync_next_batch(bob_initial_sync.response.body);

        auto const join = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob.access_token, "{}"});
        REQUIRE(join.response.status == 200U);

        // Drain alice's initial sync so she has a since token to detect new ephemeral data.
        auto const alice_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", alice.access_token, {}});
        REQUIRE(alice_initial_sync.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_initial_sync.response.body);

        WHEN("one user starts typing in the room")
        {
            auto const typing_body = std::string{"{\"typing\":true,\"timeout\":30000}"};
            auto const typing = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/typing/" + bob.user_id, bob.access_token,
                          typing_body});
            REQUIRE(typing.response.status == 200U);

            auto const alice_sync = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/sync?since=" + alice_from, alice.access_token, {}});
            REQUIRE(alice_sync.response.status == 200U);
            auto const alice_sync_body = parse_object(alice_sync.response.body);
            auto const* rooms = object_member_as_object(alice_sync_body, "rooms");
            REQUIRE(rooms != nullptr);
            auto const* joins = object_member_as_object(*rooms, "join");
            REQUIRE(joins != nullptr);
            auto const* room = object_member_as_object(*joins, room_id);
            REQUIRE(room != nullptr);
            auto const* ephemeral = object_member_as_object(*room, "ephemeral");
            REQUIRE(ephemeral != nullptr);
            auto const* events = object_member_as_array(*ephemeral, "events");
            REQUIRE(events != nullptr);

            THEN("the recipient's /sync includes an m.typing ephemeral event naming the typing user")
            {
                REQUIRE(std::ranges::any_of(*events, [&bob](merovingian::canonicaljson::Value const& value) {
                    auto const* event = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
                    auto const* type = event == nullptr ? nullptr : string_member(*event, "type");
                    auto const* content = event == nullptr ? nullptr : object_member_as_object(*event, "content");
                    auto const* user_ids = content == nullptr ? nullptr : object_member_as_array(*content, "user_ids");
                    return type != nullptr && *type == "m.typing" && user_ids != nullptr &&
                           std::ranges::any_of(*user_ids, [&bob](merovingian::canonicaljson::Value const& id) {
                               auto const* text = std::get_if<std::string>(&id.storage());
                               return text != nullptr && *text == bob.user_id;
                           });
                }));
            }
        }
    }
}

SCENARIO("Typing notifications can stop and restart via ephemeral events in /sync",
         "[homeserver][client-server][integration][sync][typing][regression]")
{
    GIVEN("two joined users with active sync streams")
    {
        auto const config = registration_enabled_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = register_session(runtime, "alice_typing_restart", "CorrectHorse7!");
        auto const bob = register_session(runtime, "bob_typing_restart", "CorrectHorse8!");

        auto const create_body = std::string{"{\"preset\":\"private_chat\",\"invite\":[\""} + bob.user_id + "\"]}";
        auto const create = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice.access_token, create_body});
        REQUIRE(create.response.status == 200U);
        auto const room_id = response_string_field(create.response.body, "room_id");

        auto const bob_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", bob.access_token, {}});
        REQUIRE(bob_initial_sync.response.status == 200U);
        std::ignore = sync_next_batch(bob_initial_sync.response.body);

        auto const join = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob.access_token, "{}"});
        REQUIRE(join.response.status == 200U);

        auto const alice_initial_sync = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync", alice.access_token, {}});
        REQUIRE(alice_initial_sync.response.status == 200U);
        auto const alice_from = sync_next_batch(alice_initial_sync.response.body);

        WHEN("one user starts typing, stops, and starts typing again")
        {
            auto const do_typing = [&runtime, &room_id, &bob](bool const typing) {
                auto const body = std::string{"{\"typing\":"} + (typing ? "true" : "false") + ",\"timeout\":30000}";
                return merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/typing/" + bob.user_id, bob.access_token, body});
            };
            auto const do_sync = [&runtime, &alice](std::string const& since) {
                return merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/sync?since=" + since, alice.access_token, {}});
            };

            auto const start = do_typing(true);
            REQUIRE(start.response.status == 200U);
            auto const sync_start = do_sync(alice_from);
            REQUIRE(sync_start.response.status == 200U);
            auto const after_start = sync_next_batch(sync_start.response.body);

            auto const stop = do_typing(false);
            REQUIRE(stop.response.status == 200U);
            auto const sync_stop = do_sync(after_start);
            REQUIRE(sync_stop.response.status == 200U);
            auto const after_stop = sync_next_batch(sync_stop.response.body);

            auto const restart = do_typing(true);
            REQUIRE(restart.response.status == 200U);
            auto const sync_restart = do_sync(after_stop);
            REQUIRE(sync_restart.response.status == 200U);

            THEN("each transition is delivered as a distinct ephemeral event")
            {
                REQUIRE(typing_user_ids_from_sync(sync_start.response.body, room_id) ==
                        std::vector<std::string>{bob.user_id});
                REQUIRE(typing_user_ids_from_sync(sync_stop.response.body, room_id).empty());
                REQUIRE(typing_user_ids_from_sync(sync_restart.response.body, room_id) ==
                        std::vector<std::string>{bob.user_id});
            }
        }
    }
}

// The conformance suite asserts only that a NON-sender's membership is omitted
// when lazy_load_members is set, because the spec makes the sender's membership
// optional ("MAY contain the membership events for the senders"). That leaves a
// hole a conformance test cannot close: an implementation returning NO state at
// all satisfies an absence-only assertion. This pins what this server actually
// does, which is a fair thing to assert outside the conformance suite — and it
// is not hypothetical, since this codebase has already shipped an endpoint
// returning a hardcoded empty object while its tests passed.
SCENARIO("GET /messages returns the chunk sender's membership when lazy loading",
         "[client-server][integration][lazyload]")
{
    GIVEN("a room where one member sends the only event in the chunk")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const alice = register_and_login(runtime, "alice", "CorrectHorse7!", "ALICE_DEV");
        auto const room = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/createRoom", alice, "{}"});
        REQUIRE(room.response.status == 200U);
        auto const room_id = response_string_field(room.response.body, "room_id");
        REQUIRE(!room_id.empty());

        auto const sent = merovingian::homeserver::handle_client_server_request(
            runtime, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-lazy-1", alice,
                      R"({"msgtype":"m.text","body":"hello"})"});
        REQUIRE(sent.response.status == 200U);

        WHEN("/messages is requested with lazy_load_members and a single-event chunk")
        {
            auto const target = "/_matrix/client/v3/rooms/" + room_id +
                                "/messages?dir=b&limit=1&filter=%7B%22lazy_load_members%22%3Atrue%7D";
            auto const response =
                merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, alice, {}});

            THEN("state is not empty and carries the sender's membership")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("\"state\":[]") == std::string::npos);
                REQUIRE(response.response.body.find("@alice:example.org") != std::string::npos);
            }
        }
    }
}

// ADR-0182: a profile change is answered once the field is stored; propagation is best effort. A
// stored profile field this server cannot serialise (here an avatar URL that is not UTF-8, which no
// client request can write) leaves no membership event to build, so nothing is sent to the user's
// rooms and the request still succeeds. The spec's 200 and the stored field are covered by the
// profile-propagation conformance scenario.
SCENARIO("A profile change whose membership event cannot be serialised sends nothing",
         "[integration][client-server][profile-propagation]")
{
    GIVEN("a user in a room whose stored avatar URL cannot be serialised")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice", "CorrectHorse7!", "DEVICE1");
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})"})
                    .response.status == 200U);
        auto& store = runtime.homeserver.database.persistent_store;
        REQUIRE(merovingian::database::store_profile(store, {"@alice:example.org", {}, "mxc://example.org/\xff"}));
        auto const events_before = store.events.size();

        WHEN("the user sets a display name")
        {
            auto const put = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/profile/@alice:example.org/displayname", token,
                          R"({"displayname":"Alice Liddell"})"});

            THEN("the request succeeds and no membership event is stored")
            {
                REQUIRE(put.response.status == 200U);
                REQUIRE(store.events.size() == events_before);
            }
        }
    }
}

namespace
{

// A room of @alice:example.org with one message at origin_server_ts 5000 (everything else at 100), and
// @bob:remote.example.net joined, so another server is in the room to be asked.
struct RoomWithRemoteMember final
{
    std::string alice{};
    std::string room_id{};
    std::string message_id{};
};

[[nodiscard]] auto room_with_remote_member(merovingian::homeserver::ClientServerRuntime& rt) -> RoomWithRemoteMember
{
    rt.homeserver.test_frozen_event_clock_ms = 100;
    auto room = RoomWithRemoteMember{};
    room.alice = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE1");
    auto const created = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/createRoom", room.alice, "{}"});
    REQUIRE(created.response.status == 200U);
    room.room_id = response_string_field(created.response.body, "room_id");
    rt.homeserver.test_frozen_event_clock_ms = 5000;
    auto const sent = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/rooms/" + room.room_id + "/send/m.room.message/ts1", room.alice,
             R"({"msgtype":"m.text","body":"hello"})"});
    REQUIRE(sent.response.status == 200U);
    room.message_id = response_string_field(sent.response.body, "event_id");
    rt.homeserver.database.persistent_store.memberships.push_back(
        {room.room_id, "@bob:remote.example.net", "join", 4U});
    return room;
}

// A message at origin_server_ts 8000 whose only prev_event this server does not hold: the ADR-0289 graph
// hole, behind which a closer event may lie.
auto add_event_behind_a_gap(merovingian::homeserver::ClientServerRuntime& rt, std::string const& room_id) -> void
{
    auto gap = merovingian::database::PersistentEvent{};
    gap.event_id = "$gap:example.org";
    gap.room_id = room_id;
    gap.sender_user_id = "@alice:example.org";
    gap.json =
        R"({"type":"m.room.message","sender":"@alice:example.org","origin_server_ts":8000,"content":{"body":"x"}})";
    gap.depth = 50U;
    gap.stream_ordering = 1000000U;
    gap.prev_event_ids = {"$missing:example.org"};
    REQUIRE(rt.homeserver.database.persistent_store.events.push_back(std::move(gap)));
}

[[nodiscard]] auto timestamp_to_event_get(merovingian::homeserver::ClientServerRuntime& rt,
                                          RoomWithRemoteMember const& room, std::string const& query)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        rt, {"GET", "/_matrix/client/v1/rooms/" + room.room_id + "/timestamp_to_event?" + query, room.alice, {}});
}

} // namespace

// Spec: Matrix Client-Server API v1.19, GET /rooms/{roomId}/timestamp_to_event: "If the server does not
// have all of the room history and does not have an event suitably close to the requested timestamp, it
// can use the corresponding federation endpoint to ask other servers for a suitable event." Server-Server
// API v1.19, GET /timestamp_to_event/{roomId}: the answer is used only if its `origin_server_ts` is closer
// than the local one, and the event is then fetched with `/event/{event_id}`. A remote answer is untrusted.
// URL: ../../docs/matrix-v1.19-spec/server-server-api.md#get_matrixfederationv1timestamp_to_eventroomid
SCENARIO("GET /timestamp_to_event asks a server of the room only when its own history may be incomplete",
         "[homeserver][client-server][timestamp-to-event][fed-endpoints]")
{
    GIVEN("a room with a message at 5000 and a remote member, and a remote server that answers with a closer event")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const room = room_with_remote_member(rt);

        auto certificate = merovingian::tests::tls_mock::write_test_tls_certificate("localhost");
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto tls_context = std::move(*tls.context);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        rt.homeserver.test_forced_outbound_resolution["remote.example.net"] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", acceptor.bound_port(), {"127.0.0.1"}, certificate.certificate_pem};

        WHEN("the local answer is complete: an event lies after the timestamp and nothing is missing before it")
        {
            auto const response = timestamp_to_event_get(rt, room, "ts=1000&dir=f");

            THEN("it is answered locally without asking anybody")
            {
                REQUIRE(response.response.status == 200U);
                // Nothing accepts on the remote's listener, so a connection attempt would still be
                // waiting in its backlog: an empty backlog shows nobody was asked.
                REQUIRE(merovingian::tests::tls_mock::accept_loopback(acceptor, 0) < 0);
                REQUIRE(response.response.body.find(room.message_id) != std::string::npos);
                REQUIRE(response.response.body.find("\"origin_server_ts\":5000") != std::string::npos);
            }
        }

        WHEN("the only client-outbound slot is busy for a moment when the lookup needs it")
        {
            // ADR-0306: the lookup waits for a slot within its own deadline instead of being refused at
            // once, so parallel lookups by one client are served in turn.
            rt.homeserver.client_outbound_proxy_policy.global_cap = 1U;
            auto held = merovingian::homeserver::admit_client_outbound_proxy(rt.homeserver, "another-lookup");
            REQUIRE(held.has_value());
            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"no event"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"timestamp_to_event", not_found}
            };
            auto captured = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            auto releaser = std::thread{[&held]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
                held.reset();
            }};
            auto const response = timestamp_to_event_get(rt, room, "ts=999999&dir=f");
            releaser.join();

            THEN("it waits, then asks the remote server instead of being refused")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(captured.size() == 1U);
            }
        }

        WHEN("no local event lies after the timestamp and the remote server has none either")
        {
            auto const not_found = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"no event"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"timestamp_to_event", not_found}
            };
            auto captured = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            auto const response = timestamp_to_event_get(rt, room, "ts=999999&dir=f");

            THEN("one server is asked, with the timestamp and direction, and the client gets 404 M_NOT_FOUND")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(response.response.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(captured.size() == 1U);
                REQUIRE(captured[0].find("GET /_matrix/federation/v1/timestamp_to_event/") == 0U);
                REQUIRE(captured[0].find("?ts=999999&dir=f") != std::string::npos);
            }
        }

        WHEN("the remote server names an event on the wrong side of the timestamp")
        {
            auto const wrong_side = merovingian::tests::tls_mock::json_http_response(
                "200 OK", R"({"event_id":"$early:remote.example.net","origin_server_ts":10})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"timestamp_to_event", wrong_side}
            };
            auto captured = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            auto const response = timestamp_to_event_get(rt, room, "ts=999999&dir=f");

            THEN("the answer is not used and the event is not even fetched")
            {
                REQUIRE(response.response.status == 404U);
                REQUIRE(captured.size() == 1U);
            }
        }

        WHEN("the local answer lies behind a gap and the remote server names a closer event it then cannot serve")
        {
            add_event_behind_a_gap(rt, room.room_id);
            auto const closer = merovingian::tests::tls_mock::json_http_response(
                "200 OK", R"({"event_id":"$closer:remote.example.net","origin_server_ts":7500})");
            auto const gone = merovingian::tests::tls_mock::json_http_response(
                "404 Not Found", R"({"errcode":"M_NOT_FOUND","error":"no such event"})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"timestamp_to_event", closer},
                {"/event/",            gone  }
            };
            auto captured = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            auto const response = timestamp_to_event_get(rt, room, "ts=7000&dir=f");

            THEN("the event is asked for by ID, and failing to get it the client is given the local answer")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("$gap:example.org") != std::string::npos);
                REQUIRE(response.response.body.find("closer") == std::string::npos);
                REQUIRE(captured.size() == 2U);
                REQUIRE(captured[1].find("GET /_matrix/federation/v1/event/") == 0U);
                REQUIRE(captured[1].find("closer") != std::string::npos);
            }
        }

        WHEN("the remote server names a farther event than the one behind the gap")
        {
            add_event_behind_a_gap(rt, room.room_id);
            auto const farther = merovingian::tests::tls_mock::json_http_response(
                "200 OK", R"({"event_id":"$farther:remote.example.net","origin_server_ts":9000})");
            auto const responses = std::vector<std::pair<std::string, std::string>>{
                {"timestamp_to_event", farther}
            };
            auto captured = std::vector<std::string>{};
            auto server_thread = std::thread{[&]() {
                merovingian::tests::tls_mock::run_path_dispatch_tls_server(acceptor, tls_context, responses, &captured);
            }};
            auto const join_server = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};
            auto const response = timestamp_to_event_get(rt, room, "ts=7000&dir=f");

            THEN("it is ignored: the local event is closer, and nothing is fetched")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("$gap:example.org") != std::string::npos);
                REQUIRE(captured.size() == 1U);
            }
        }
    }
}

// ADR-0079: a client request that calls another server holds a slot of the client-outbound budget, and makes
// no outbound call without one. GET /timestamp_to_event waits for a slot within its deadline (ADR-0306); when
// none comes it is refused with 429 M_LIMIT_EXCEEDED, or, with an answer in hand, answered locally.
SCENARIO("GET /timestamp_to_event does not call another server without a client-outbound slot",
         "[homeserver][client-server][timestamp-to-event][adr-0079]")
{
    GIVEN("a room with a remote member, and a budget with no slot to give within a one-second deadline")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const room = room_with_remote_member(rt);
        add_event_behind_a_gap(rt, room.room_id);
        rt.homeserver.client_outbound_proxy_policy.global_cap = 0U;
        rt.homeserver.client_outbound_proxy_policy.directory_deadline_seconds = 1U;

        WHEN("no local event lies after the timestamp")
        {
            auto const response = timestamp_to_event_get(rt, room, "ts=999999&dir=f");

            THEN("the client is told to retry shortly")
            {
                REQUIRE(response.response.status == 429U);
                REQUIRE(response.response.body.find("M_LIMIT_EXCEEDED") != std::string::npos);
            }
        }

        WHEN("the local answer lies behind a gap")
        {
            auto const response = timestamp_to_event_get(rt, room, "ts=7000&dir=f");

            THEN("the client is given the local answer")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(response.response.body.find("$gap:example.org") != std::string::npos);
            }
        }

        WHEN("the local answer lies behind a gap, and alice leaves and forgets the room while the lookup waits")
        {
            // The wait releases runtime.mutex, so the access judged before it may be gone after it.
            auto leaver = std::thread{[&rt, &room]() {
                std::this_thread::sleep_for(std::chrono::milliseconds{300});
                auto const base = "/_matrix/client/v3/rooms/" + room.room_id;
                std::ignore = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", base + "/leave", room.alice, "{}"});
                std::ignore = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", base + "/forget", room.alice, "{}"});
            }};
            auto const join_leaver = merovingian::tests::tls_mock::ScopedThreadJoin{leaver};
            auto const response = timestamp_to_event_get(rt, room, "ts=7000&dir=f");

            THEN("she is refused: her access is judged again after the wait")
            {
                CAPTURE(response.response.body);
                REQUIRE(response.response.status == 403U);
            }
        }
    }
}
