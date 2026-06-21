// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto sliding_sync_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// Register and log in; returns the access token for subsequent requests.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt, std::string_view localpart,
                                      std::string_view password, std::string_view device_id) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(reg.response.status == 200U);

    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            std::string{localpart} + ":example.org\"},\"password\":\"" + std::string{password} +
                            "\",\"device_id\":\"" + std::string{device_id} + "\"}";
    auto const login =
        merovingian::homeserver::handle_client_server_request(rt, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);

    auto const body = parse_object(login.response.body);
    auto const* tok = string_member(body, "access_token");
    REQUIRE(tok != nullptr);
    return *tok;
}

// Create a private room owned by token; returns the room_id.
[[nodiscard]] auto create_room(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token)
    -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"private_chat"})"});
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* room_id = string_member(body, "room_id");
    REQUIRE(room_id != nullptr);
    return *room_id;
}

// Issue a sliding sync POST; returns the DispatchResult (can_wait = false so it
// never blocks on a long-poll — tests always prime events first).
[[nodiscard]] auto sliding_sync(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                                std::string const& body, std::string const& pos = {})
    -> merovingian::homeserver::DispatchResult
{
    auto const target = pos.empty() ? std::string{"/_matrix/client/unstable/org.matrix.msc4186/sync"}
                                    : "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + pos;
    return merovingian::homeserver::handle_client_server_request(rt, {"POST", target, token, body}, /*can_wait=*/false);
}

// Extract the "pos" string from a sliding sync 200 response body.
[[nodiscard]] auto sliding_sync_pos(std::string const& response_body) -> std::string
{
    auto const obj = parse_object(response_body);
    auto const* pos = string_member(obj, "pos");
    REQUIRE(pos != nullptr);
    REQUIRE(!pos->empty());
    return *pos;
}

// Extract the ops array for a named list from a 200 response body.
// Returns a copy: parse_object is local and destroyed on return, so the caller
// must not hold raw pointers into the original parse tree.
[[nodiscard]] auto list_ops(std::string const& response_body, std::string_view list_name)
    -> std::optional<merovingian::canonicaljson::Array>
{
    auto const obj = parse_object(response_body);
    auto const* lists = object_member_as_object(obj, "lists");
    if (lists == nullptr)
        return std::nullopt;
    auto const* named_list = object_member_as_object(*lists, list_name);
    if (named_list == nullptr)
        return std::nullopt;
    auto const* ops = object_member_as_array(*named_list, "ops");
    if (ops == nullptr)
        return std::nullopt;
    return *ops; // copy before local obj is destroyed
}

// Return the "rooms" object from a sliding sync response (may be null if empty).
[[nodiscard]] auto rooms_object(std::string const& response_body) -> merovingian::canonicaljson::Object
{
    auto const obj = parse_object(response_body);
    auto const* rooms = object_member_as_object(obj, "rooms");
    if (rooms == nullptr)
        return {};
    return *rooms;
}

// Send an m.room.message event from token into room_id.
auto send_message(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                  std::string const& room_id, std::string_view text) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn1", token,
             std::string{R"({"msgtype":"m.text","body":")"} + std::string{text} + "\"}"});
    REQUIRE(resp.response.status == 200U);
}

} // namespace

// ── Advertisement ────────────────────────────────────────────────────────────

SCENARIO("MSC4186 is advertised in /_matrix/client/versions unstable_features",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a running homeserver")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("GET /_matrix/client/versions is called")
        {
            auto const resp =
                merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/versions", {}, {}});

            THEN("unstable_features contains both MSC4186 feature names for client compatibility")
            {
                REQUIRE(resp.response.status == 200U);
                auto const body = parse_object(resp.response.body);
                auto const* unstable = object_member_as_object(body, "unstable_features");
                REQUIRE(unstable != nullptr);
                auto const* msc4186 = bool_member(*unstable, "org.matrix.msc4186");
                REQUIRE(msc4186 != nullptr);
                REQUIRE(*msc4186 == true);
                auto const* simplified_3575 = bool_member(*unstable, "org.matrix.simplified_msc3575");
                REQUIRE(simplified_3575 != nullptr);
                REQUIRE(*simplified_3575 == true);
            }
        }
    }
}

// ── Initial sync ─────────────────────────────────────────────────────────────

SCENARIO("MSC4186 initial sliding sync returns pos and a SYNC op for each joined room",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user with one joined room")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        WHEN("an initial sliding sync is issued (no pos) with the room in the window")
        {
            auto const result = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})");

            THEN("the response is 200 with a pos token")
            {
                REQUIRE(result.response.status == 200U);
                auto const pos = sliding_sync_pos(result.response.body);
                REQUIRE(!pos.empty());
            }

            THEN("the list contains a SYNC op that includes the joined room")
            {
                REQUIRE(result.response.status == 200U);
                auto const ops = list_ops(result.response.body, "rooms");
                REQUIRE(ops.has_value());
                REQUIRE(!ops->empty());

                // At least one op must be SYNC and must carry the room_id.
                auto const found = std::ranges::any_of(*ops, [&](auto const& val) {
                    auto const* op_obj = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                    if (op_obj == nullptr)
                        return false;
                    auto const* op_name = string_member(*op_obj, "op");
                    if (op_name == nullptr || *op_name != "SYNC")
                        return false;
                    auto const* ids = object_member_as_array(*op_obj, "room_ids");
                    if (ids == nullptr)
                        return false;
                    return std::ranges::any_of(*ids, [&](auto const& id_val) {
                        auto const* s = std::get_if<std::string>(&id_val.storage());
                        return s != nullptr && *s == room_id;
                    });
                });
                REQUIRE(found);
            }

            THEN("the rooms object contains an entry for the joined room with initial = true")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                auto const* initial = bool_member(*rm, "initial");
                REQUIRE(initial != nullptr);
                REQUIRE(*initial == true);
            }
        }
    }
}

// ── required_state wildcards ──────────────────────────────────────────────────

SCENARIO("MSC4186 required_state wildcard [\"*\",\"*\"] returns all room state events",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user with a joined room")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        WHEN("sliding sync requests required_state [[\"*\",\"*\"]]")
        {
            auto const result =
                sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]],"required_state":[["*","*"]]}}})");

            THEN("the room response includes state events including m.room.create")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                auto const* state = object_member_as_array(*rm, "required_state");
                REQUIRE(state != nullptr);
                REQUIRE(!state->empty());

                // m.room.create is always present in any room.
                auto const has_create = std::ranges::any_of(*state, [](auto const& val) {
                    auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                    if (ev == nullptr)
                        return false;
                    auto const* type = string_member(*ev, "type");
                    return type != nullptr && *type == "m.room.create";
                });
                REQUIRE(has_create);
            }
        }

        WHEN("sliding sync requests only m.room.name state")
        {
            auto const result = sliding_sync(
                rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]],"required_state":[["m.room.name",""]]}}})");

            THEN("the room response does NOT include m.room.create")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                // required_state may be absent or empty when no events match.
                auto const* state = object_member_as_array(*rm, "required_state");
                auto const has_create = (state != nullptr) && std::ranges::any_of(*state, [](auto const& val) {
                                            auto const* ev =
                                                std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                                            if (ev == nullptr)
                                                return false;
                                            auto const* type = string_member(*ev, "type");
                                            return type != nullptr && *type == "m.room.create";
                                        });
                REQUIRE_FALSE(has_create);
            }
        }
    }
}

// ── timeline_limit ────────────────────────────────────────────────────────────

SCENARIO("MSC4186 timeline_limit caps the number of timeline events returned per room",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a room with three messages sent")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        send_message(rt, token, room_id, "message one");
        send_message(rt, token, room_id, "message two");
        send_message(rt, token, room_id, "message three");

        WHEN("sliding sync is issued with timeline_limit: 1")
        {
            auto const result = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]],"timeline_limit":1}}})");

            THEN("the timeline for the room contains at most 1 event")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                auto const* tl = object_member_as_object(*rm, "timeline");
                if (tl != nullptr)
                {
                    auto const* events = object_member_as_array(*tl, "events");
                    if (events != nullptr)
                    {
                        REQUIRE(events->size() <= 1U);
                    }
                }
            }
        }
    }
}

// ── Incremental sync ──────────────────────────────────────────────────────────

SCENARIO("MSC4186 incremental sync does not mark a previously-seen room as initial",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user who has already received an initial sliding sync for a room")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        // Perform the initial sync and capture the pos.
        auto const first = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})");
        REQUIRE(first.response.status == 200U);
        auto const pos = sliding_sync_pos(first.response.body);

        // Send a new event so the incremental sync has something to return
        // (avoids the handler returning needs_wait on an idle store).
        send_message(rt, token, room_id, "new message");

        WHEN("a second sliding sync is issued with the captured pos")
        {
            auto const second = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})", pos);

            THEN("the response is 200 with a new pos")
            {
                REQUIRE(second.response.status == 200U);
                auto const new_pos = sliding_sync_pos(second.response.body);
                REQUIRE(!new_pos.empty());
            }

            THEN("the room entry for the already-seen room does NOT have initial = true")
            {
                REQUIRE(second.response.status == 200U);
                auto const rooms = rooms_object(second.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                if (rm != nullptr)
                {
                    // If the room is present on the second response, initial must be absent or false.
                    auto const* initial = bool_member(*rm, "initial");
                    REQUIRE((initial == nullptr || *initial == false));
                }
            }
        }
    }
}

// ── to_device extension ───────────────────────────────────────────────────────

SCENARIO("MSC4186 to_device extension delivers pending to-device messages", "[homeserver][sliding-sync][integration]")
{
    GIVEN("a pending to-device message queued for alice's device")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        auto const pushed = merovingian::homeserver::push_to_device_message(
            rt, {
                    .stream_id = 0U,
                    .sender_user_id = "@sender:example.org",
                    .target_user_id = "@alice:example.org",
                    .target_device_id = "ALICE",
                    .message_type = "m.room_key",
                    .content_json = R"({"algorithm":"m.megolm.v1.aes-sha2"})",
                });
        REQUIRE(pushed);

        WHEN("sliding sync is issued with the to_device extension enabled")
        {
            auto const result = sliding_sync(rt, token, R"({"extensions":{"to_device":{"enabled":true}}})");

            THEN("the response includes the pending message in extensions.to_device.events")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* td = object_member_as_object(*ext, "to_device");
                REQUIRE(td != nullptr);
                auto const* events = object_member_as_array(*td, "events");
                REQUIRE(events != nullptr);
                REQUIRE(!events->empty());

                // The queued m.room_key event must appear.
                auto const has_key = std::ranges::any_of(*events, [](auto const& val) {
                    auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                    if (ev == nullptr)
                        return false;
                    auto const* type = string_member(*ev, "type");
                    return type != nullptr && *type == "m.room_key";
                });
                REQUIRE(has_key);
            }

            THEN("the response includes extensions.to_device.next_batch")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* td = object_member_as_object(*ext, "to_device");
                REQUIRE(td != nullptr);
                auto const* nb = string_member(*td, "next_batch");
                REQUIRE(nb != nullptr);
                REQUIRE(!nb->empty());
            }
        }

        WHEN("the extension is absent from the request")
        {
            auto const result = sliding_sync(rt, token, R"({})");

            THEN("the response does not include extensions.to_device")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                if (ext != nullptr)
                {
                    auto const* td = object_member_as_object(*ext, "to_device");
                    REQUIRE(td == nullptr);
                }
            }
        }
    }
}

// ── e2ee extension ────────────────────────────────────────────────────────────

SCENARIO("MSC4186 e2ee extension returns device_one_time_keys_count after key upload",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user who has uploaded one-time keys")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        // Upload device keys so the server knows about ALICE.
        static constexpr auto keys_body =
            R"({"device_keys":{"user_id":"@alice:example.org","device_id":"ALICE","algorithms":["m.olm.v1.curve25519-aes-sha2"],"keys":{"curve25519:ALICE":"ALICECURVE","ed25519:ALICE":"ALICEED"}}})";
        auto const keys_upload = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/keys/upload", token, keys_body});
        REQUIRE(keys_upload.response.status == 200U);

        WHEN("sliding sync is issued with the e2ee extension enabled")
        {
            auto const result = sliding_sync(rt, token, R"({"extensions":{"e2ee":{"enabled":true}}})");

            THEN("the response includes extensions.e2ee with device_one_time_keys_count")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* e2ee = object_member_as_object(*ext, "e2ee");
                REQUIRE(e2ee != nullptr);
                // device_one_time_keys_count must be present (may be an empty object).
                auto const* otk_counts = object_member_as_object(*e2ee, "device_one_time_keys_count");
                REQUIRE(otk_counts != nullptr);
            }
        }

        WHEN("the e2ee extension is disabled in the request")
        {
            auto const result = sliding_sync(rt, token, R"({"extensions":{"e2ee":{"enabled":false}}})");

            THEN("the response does not include extensions.e2ee")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                if (ext != nullptr)
                {
                    auto const* e2ee = object_member_as_object(*ext, "e2ee");
                    REQUIRE(e2ee == nullptr);
                }
            }
        }
    }
}

// ── Room subscriptions ────────────────────────────────────────────────────────

SCENARIO("MSC4186 explicit room_subscriptions include rooms outside the list window",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user with two rooms and a list window of size 1")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_a = create_room(rt, token);
        auto const room_b = create_room(rt, token);

        WHEN("sliding sync is issued with a 1-room window and an explicit subscription to room_b")
        {
            auto const body = std::string{"{\"lists\":{\"rooms\":{\"ranges\":[[0,0]]}},\"room_subscriptions\":{\""} +
                              room_b + std::string{"\":{\"required_state\":[[\"m.room.create\",\"\"]]}}}"};
            auto const result = sliding_sync(rt, token, body);

            THEN("the rooms object includes room_b even though it may be outside the list window")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                // room_b must appear via the explicit subscription.
                auto const* rb = object_member_as_object(rooms, room_b);
                REQUIRE(rb != nullptr);
            }
        }
    }
}

// ── MSC3575 compatibility alias ───────────────────────────────────────────────

SCENARIO("MSC4186 sliding sync is reachable at the org.matrix.simplified_msc3575 compatibility path",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a registered user")
    {
        auto const config = sliding_sync_config();
        auto started      = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt          = started.runtime;
        auto const token  = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        WHEN("POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync is called")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token,
                 R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/false);

            THEN("the response is 200 — the alias is routed to the same MSC4186 handler")
            {
                // matrix-rust-sdk calls this path; the server MUST serve it.
                REQUIRE(result.response.status == 200U);
                auto const obj  = parse_object(result.response.body);
                auto const* pos = string_member(obj, "pos");
                REQUIRE(pos != nullptr); // MSC4186 MUST include pos in every response
                REQUIRE(!pos->empty());
            }
        }
    }
}

SCENARIO("MSC4186 incremental sync works via the simplified_msc3575 path using pos from the prior response",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user whose initial sliding sync was completed via the simplified_msc3575 path")
    {
        auto const config = sliding_sync_config();
        auto started      = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt          = started.runtime;
        auto const token  = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        auto const initial = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token,
             R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
            /*can_wait=*/false);
        REQUIRE(initial.response.status == 200U);
        auto const pos = sliding_sync_pos(initial.response.body);

        WHEN("an incremental request is sent via simplified_msc3575 with the returned pos")
        {
            auto const target = std::string{"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos="} + pos;
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", target, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/false);

            THEN("the response is 200 with a new pos token")
            {
                REQUIRE(result.response.status == 200U);
                auto const new_pos = sliding_sync_pos(result.response.body);
                REQUIRE(!new_pos.empty());
            }
        }
    }
}

SCENARIO("MSC4186 pos token is interchangeable between the msc4186 and simplified_msc3575 paths",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user whose initial sliding sync was completed via the msc4186 path")
    {
        auto const config = sliding_sync_config();
        auto started      = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt          = started.runtime;
        auto const token  = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        auto const initial = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})");
        REQUIRE(initial.response.status == 200U);
        auto const pos = sliding_sync_pos(initial.response.body);

        WHEN("an incremental request is sent via the simplified_msc3575 path using the msc4186 pos")
        {
            auto const target = std::string{"/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos="} + pos;
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", target, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/false);

            THEN("the response is 200 — pos tokens are path-independent")
            {
                // Both paths hit the same handler and share connection state, so
                // a pos obtained from one path MUST be accepted by the other.
                REQUIRE(result.response.status == 200U);
                auto const new_pos = sliding_sync_pos(result.response.body);
                REQUIRE(!new_pos.empty());
            }
        }
    }
}
