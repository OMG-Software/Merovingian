// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

auto upload_one_time_key(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& token,
                         std::string_view user_id, std::string_view device_id, std::string_view key_id,
                         std::string_view key_value) -> void
{
    auto const body =
        std::string{R"({"one_time_keys":{"signed_curve25519:)" + std::string{key_id} + R"(":{"key":")" +
                    std::string{key_value} + R"(","signatures":{"})" + std::string{user_id} + R"(":{"ed25519:)" +
                    std::string{device_id} + R"(":")" + std::string{key_value} + R"(_SIG"}}}}})"};
    auto const upload = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/keys/upload", token, body});
    REQUIRE(upload.response.status == 200U);
}

[[nodiscard]] auto sync_next_batch(std::string const& body) -> std::string
{
    return response_string_field(body, "next_batch");
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

SCENARIO("Integrated Matrix v1.18 interop flow covers login join key exchange messaging receipts and leave",
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
        upload_device_keys(runtime, bob, "@bob:example.org", "BOB_DEV", "BOB_CURVE", "BOB_ED");
        upload_one_time_key(runtime, bob, "@bob:example.org", "BOB_DEV", "BOB_OTK_AAAA", "BOB_OTK_VALUE");

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

            auto const changes = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/keys/changes?from=" + alice_from + "&to=s999", alice, {}});
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

SCENARIO("Integrated client-server flow fails closed on invalid config", "[homeserver][client-server][integration]")
{
    GIVEN("an invalid listener config")
    {
        auto listeners = merovingian::config::ListenersConfig{};
        listeners.client.bind = "0.0.0.0:not-a-port";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           listeners,
            merovingian::config::DatabaseConfig{},         merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

        WHEN("the user changes their password")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/account/password", token, R"({"new_password":"NewHorse99!!"})"});

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
