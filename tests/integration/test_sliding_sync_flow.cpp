// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/serializer.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/local_services.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

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

// Log in an already-registered user; returns the access token for subsequent requests.
[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& rt, std::string_view localpart,
                         std::string_view password, std::string_view device_id) -> std::string;

// Register and log in; returns the access token for subsequent requests.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt, std::string_view localpart,
                                      std::string_view password, std::string_view device_id) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        rt, {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(localpart, password)});
    REQUIRE(reg.response.status == 200U);
    return login(rt, localpart, password, device_id);
}

// Log in an already-registered user; returns the access token for subsequent requests.
[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& rt, std::string_view localpart,
                         std::string_view password, std::string_view device_id) -> std::string
{
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

// Send an m.room.message event and return its event_id.
[[nodiscard]] auto send_message_get_id(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                                       std::string const& room_id, std::string_view text) -> std::string
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/rooms/" + room_id + "/send/m.room.message/txn-elementx", token,
             std::string{R"({"msgtype":"m.text","body":")"} + std::string{text} + "\"}"});
    REQUIRE(resp.response.status == 200U);
    auto const body = parse_object(resp.response.body);
    auto const* event_id = string_member(body, "event_id");
    REQUIRE(event_id != nullptr);
    return *event_id;
}

// ── Element X / matrix-rust-sdk request fidelity ────────────────────────────
//
// Element X runs sliding sync through matrix-sdk-ui's `SyncService`, which
// wires up two independent sliding sync connections against the same
// homeserver (see matrix-org/matrix-rust-sdk, crates/matrix-sdk-ui/src/
// sync_service.rs and matrix-org/matrix-rust-sdk#1928 "The Two Sync Loops"):
//
//   - "room-list" (`RoomListService::DEFAULT_CONNECTION_ID`, room_list_service/
//     mod.rs): the single `all_rooms` list, `DEFAULT_REQUIRED_STATE`,
//     `timeline_limit=1`, and the account_data/receipts/typing extensions.
//     `receipts` is requested with `rooms:["*"]`
//     (`ExtensionRoomConfig::AllSubscribed` serializes to `"*"`).
//   - "encryption" (encryption_sync_service.rs): no lists or subscriptions at
//     all, only the to_device/e2ee extensions — a dedicated background
//     connection so encryption keys keep flowing without paying for room-list
//     computation, and so it isn't blocked by the main sync being reset.
//
// The bodies below reproduce those two connections byte-for-byte (down to the
// literal `conn_id` strings and the exact `required_state` pairs) so these
// tests exercise the requests our server actually receives from Element X,
// not a simplified stand-in.

// matrix-rust-sdk's `DEFAULT_REQUIRED_STATE`
// (room_list_service/mod.rs). "$LAZY" and "$ME" are MSC4186 sentinel values
// for lazy-loaded / own membership, not literal state keys.
auto constexpr element_x_required_state =
    R"(["m.room.name",""],["m.room.encryption",""],["m.room.member","$LAZY"],["m.room.member","$ME"],)"
    R"(["m.room.topic",""],["m.room.avatar",""],["m.room.canonical_alias",""],["m.room.power_levels",""],)"
    R"(["org.matrix.msc3401.call.member","*"],["m.room.join_rules",""],["m.room.tombstone",""],)"
    R"(["m.room.create",""],["m.room.history_visibility",""],["io.element.functional_members",""],)"
    R"(["m.space.parent","*"],["m.space.child","*"],["org.matrix.msc3672.beacon_info","*"])";

// Element X's "room-list" connection body (initial and incremental — the
// list/extensions shape does not change between polls).
[[nodiscard]] auto element_x_room_list_body() -> std::string
{
    return std::string{R"({"conn_id":"room-list","lists":{"all_rooms":{"ranges":[[0,19]],"required_state":[)"} +
           element_x_required_state +
           R"(],"timeline_limit":1}},"extensions":{"account_data":{"enabled":true},)"
           R"("receipts":{"enabled":true,"rooms":["*"]},"typing":{"enabled":true}}})";
}

// Element X's "encryption" connection body: no lists/subscriptions, only
// to_device/e2ee.
[[nodiscard]] auto element_x_encryption_body() -> std::string
{
    return R"({"conn_id":"encryption","extensions":{"to_device":{"enabled":true},"e2ee":{"enabled":true}}})";
}

// PUT the caller's own m.ignored_user_list account-data event. Spec:
// docs/matrix-v1.19-spec/client-server-api.md#ignoring-users.
// `percent_encoded_user_id` is the caller's own mxid, percent-encoded for
// the path segment (PUT /user/{userId}/account_data/{type} requires userId
// == the authenticated caller).
auto set_ignored_users(merovingian::homeserver::ClientServerRuntime& rt, std::string const& token,
                       std::string const& percent_encoded_user_id, std::string const& ignored_users_body) -> void
{
    auto const resp = merovingian::homeserver::handle_client_server_request(
        rt, {"PUT", "/_matrix/client/v3/user/" + percent_encoded_user_id + "/account_data/m.ignored_user_list", token,
             ignored_users_body});
    REQUIRE(resp.response.status == 200U);
}

// True when some event in `events` has the given top-level "event_id" — i.e.
// that exact event was actually delivered as an element of the array, not
// merely referenced by another (legitimately delivered) event's
// "prev_events"/"auth_events" DAG-linkage fields. Ignoring is a
// client-delivery filter, not an event-graph rewrite: a correctly-delivered
// event sent AFTER a suppressed one still names the suppressed event's
// event_id verbatim in its own prev_events, so a raw substring search over
// the serialized timeline array would find an ignored sender's event_id even
// when their event object was withheld. Checking the per-event top-level
// field is the only sound way to assert "this event was/was not delivered".
[[nodiscard]] auto array_has_event_id(merovingian::canonicaljson::Array const& events, std::string const& event_id)
    -> bool
{
    return std::ranges::any_of(events, [&](merovingian::canonicaljson::Value const& value) {
        auto const* obj = std::get_if<merovingian::canonicaljson::Object>(&value.storage());
        auto const* id = obj != nullptr ? string_member(*obj, "event_id") : nullptr;
        return id != nullptr && *id == event_id;
    });
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

// ── list + room_subscription required_state combination (MSC4186) ──────────────

SCENARIO("MSC4186 combines list and room_subscription required_state for the same room",
         "[homeserver][sliding-sync][integration][room-config-combine]")
{
    GIVEN("a user with a joined room present in a list window")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        // Helper: does the room's required_state array contain an event of the
        // given type?
        auto const has_state_event = [](merovingian::canonicaljson::Object const* rm, std::string_view event_type) {
            if (rm == nullptr)
            {
                return false;
            }
            auto const* state = object_member_as_array(*rm, "required_state");
            if (state == nullptr)
            {
                return false;
            }
            return std::ranges::any_of(*state, [&](auto const& val) {
                auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                if (ev == nullptr)
                {
                    return false;
                }
                auto const* type = string_member(*ev, "type");
                return type != nullptr && *type == event_type;
            });
        };

        WHEN("the list requests m.room.power_levels and a subscription to the same room requests m.room.create")
        {
            auto const body = std::string{"{\"lists\":{\"rooms\":{\"ranges\":[[0,9]],"
                                          "\"required_state\":[[\"m.room.power_levels\",\"\"]]}},"
                                          "\"room_subscriptions\":{\""} +
                              room_id + std::string{"\":{\"required_state\":[[\"m.room.create\",\"\"]]}}}"};
            auto const result = sliding_sync(rt, token, body);

            THEN("the room response carries the union: both m.room.power_levels and m.room.create")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                // Before the merge, the subscription overrode the list and only
                // m.room.create was returned. Per MSC4186 both must appear.
                REQUIRE(has_state_event(rm, "m.room.power_levels"));
                REQUIRE(has_state_event(rm, "m.room.create"));
            }
        }
    }
}

// ── multi-list required_state combination (MSC4186) ─────────────────────────
// Per MSC4186, a room that appears in MORE THAN ONE list window must have its
// configs combined across ALL matching lists — not just the first matching list.

SCENARIO("MSC4186 combines required_state across two list windows for the same room",
         "[homeserver][sliding-sync][integration][room-config-combine][multi-list]")
{
    GIVEN("a user with a joined room present in two list windows")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const room_id = create_room(rt, token);

        auto const has_state_event = [](merovingian::canonicaljson::Object const* rm, std::string_view event_type) {
            if (rm == nullptr)
            {
                return false;
            }
            auto const* state = object_member_as_array(*rm, "required_state");
            if (state == nullptr)
            {
                return false;
            }
            return std::ranges::any_of(*state, [&](auto const& val) {
                auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                if (ev == nullptr)
                {
                    return false;
                }
                auto const* type = string_member(*ev, "type");
                return type != nullptr && *type == event_type;
            });
        };

        WHEN("two named lists with disjoint required_state both window the room")
        {
            // Both lists window [0,9] so the single joined room is in each window.
            // List "a" requests m.room.power_levels; list "b" requests m.room.create.
            auto const body =
                std::string{"{\"lists\":{"
                            "\"a\":{\"ranges\":[[0,9]],\"required_state\":[[\"m.room.power_levels\",\"\"]]},"
                            "\"b\":{\"ranges\":[[0,9]],\"required_state\":[[\"m.room.create\",\"\"]]}"
                            "}}"};
            auto const result = sliding_sync(rt, token, body);

            THEN("the room response carries the union of both lists' required_state")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                // Before multi-list combination, only the first matching list's
                // required_state (m.room.power_levels) was returned. Per MSC4186 both
                // matching list windows must combine.
                REQUIRE(has_state_event(rm, "m.room.power_levels"));
                REQUIRE(has_state_event(rm, "m.room.create"));
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
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

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
                auto const obj = parse_object(result.response.body);
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
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

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
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

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

SCENARIO("MSC4186 pos token from simplified_msc3575 is accepted by the msc4186 path",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a user whose initial sliding sync was completed via the simplified_msc3575 path")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        auto const initial = merovingian::homeserver::handle_client_server_request(
            rt,
            {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token,
             R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
            /*can_wait=*/false);
        REQUIRE(initial.response.status == 200U);
        auto const pos = sliding_sync_pos(initial.response.body);

        WHEN("an incremental request is sent via the msc4186 path using the simplified_msc3575 pos")
        {
            auto const result = sliding_sync(rt, token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})", pos);

            THEN("the response is 200 — cross-path pos interop is symmetric")
            {
                REQUIRE(result.response.status == 200U);
                auto const new_pos = sliding_sync_pos(result.response.body);
                REQUIRE(!new_pos.empty());
            }
        }
    }
}

SCENARIO("simplified_msc3575 sync with timeout=0 responds immediately without long-polling",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a registered user with no pending events")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        WHEN("POST simplified_msc3575/sync?timeout=0 is called")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?timeout=0", token,
                 R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/true); // allow waiting — timeout=0 must still return immediately

            THEN("the response is 200 with a pos — timeout=0 means respond immediately")
            {
                REQUIRE(result.response.status == 200U);
                auto const obj = parse_object(result.response.body);
                auto const* pos = string_member(obj, "pos");
                REQUIRE(pos != nullptr);
                REQUIRE(!pos->empty());
            }
        }
    }
}

SCENARIO("simplified_msc3575 long-poll does not wake for an event in a room the caller has not joined",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("two users, each with their own room, and alice already caught up via an initial sync")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        std::ignore = create_room(rt, alice_token);
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const bob_room = create_room(rt, bob_token);

        auto const initial = sliding_sync(rt, alice_token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})");
        REQUIRE(initial.response.status == 200U);
        auto const pos = sliding_sync_pos(initial.response.body);

        WHEN("bob sends a message in his own room, then alice long-polls from that pos with a nonzero timeout")
        {
            send_message(rt, bob_token, bob_room, "hi");

            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos=" + pos + "&timeout=30000",
                 alice_token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/true);

            THEN("the handler parks the long-poll rather than returning an empty snapshot for an unrelated room")
            {
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
            }
        }
    }
}

SCENARIO("simplified_msc3575 sync with a joined room returns SYNC ops for that room",
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

        WHEN("initial sliding sync is issued via the simplified_msc3575 path with the room in range")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token,
                 R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/false);

            THEN("the response contains a SYNC op for the joined room")
            {
                REQUIRE(result.response.status == 200U);
                auto const ops = list_ops(result.response.body, "rooms");
                REQUIRE(ops.has_value());
                REQUIRE(!ops->empty());
                // First op on an initial sync MUST be SYNC.
                auto const* first = std::get_if<merovingian::canonicaljson::Object>(&ops->at(0).storage());
                REQUIRE(first != nullptr);
                auto const* op = string_member(*first, "op");
                REQUIRE(op != nullptr);
                REQUIRE(*op == "SYNC");
                // The SYNC op MUST reference the joined room.
                auto const* room_ids = object_member_as_array(*first, "room_ids");
                REQUIRE(room_ids != nullptr);
                REQUIRE(!room_ids->empty());
            }
        }
    }
}

SCENARIO("simplified_msc3575 sync rejects an unauthenticated request with 401",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("a running homeserver")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("POST simplified_msc3575/sync is called with no access token")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", /*token=*/"",
                 R"({"lists":{"rooms":{"ranges":[[0,9]]}}})"},
                /*can_wait=*/false);

            THEN("the response is 401 M_MISSING_TOKEN")
            {
                REQUIRE(result.response.status == 401U);
                auto const obj = parse_object(result.response.body);
                auto const* errcode = string_member(obj, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_MISSING_TOKEN");
            }
        }
    }
}

SCENARIO("simplified_msc3575 sync rejects a malformed JSON body with 400", "[homeserver][sliding-sync][integration]")
{
    GIVEN("a registered user")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        WHEN("POST simplified_msc3575/sync is called with an invalid JSON body")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token, "not-valid-json{{{"},
                /*can_wait=*/false);

            THEN("the response is 400 M_BAD_JSON")
            {
                REQUIRE(result.response.status == 400U);
                auto const obj = parse_object(result.response.body);
                auto const* errcode = string_member(obj, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}

SCENARIO("simplified_msc3575 sync rejects overlapping list ranges with 400", "[homeserver][sliding-sync][integration]")
{
    GIVEN("a registered user")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");

        WHEN("POST simplified_msc3575/sync is called with overlapping ranges [[0,10],[5,20]]")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt,
                {"POST", "/_matrix/client/unstable/org.matrix.simplified_msc3575/sync", token,
                 R"({"lists":{"rooms":{"ranges":[[0,10],[5,20]]}}})"},
                /*can_wait=*/false);

            THEN("the response is 400 M_BAD_JSON — overlapping ranges are invalid")
            {
                // MSC4186 MUST: ranges MUST NOT overlap.
                REQUIRE(result.response.status == 400U);
                auto const obj = parse_object(result.response.body);
                auto const* errcode = string_member(obj, "errcode");
                REQUIRE(errcode != nullptr);
                REQUIRE(*errcode == "M_BAD_JSON");
            }
        }
    }
}

SCENARIO("MSC4186 sliding sync shows rooms created on another device of the same user",
         "[homeserver][sliding-sync][integration][cross-device]")
{
    GIVEN("a user who created a room on a desktop device")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;

        auto constexpr password = "CorrectHorse7!";
        auto const desktop_token = register_and_login(rt, "alice", password, "DESKTOP");
        auto const room_id = create_room(rt, desktop_token);

        WHEN("the same user logs in on a mobile device and issues sliding sync")
        {
            auto const mobile_token = login(rt, "alice", password, "MOBILE");
            auto const result = sliding_sync(rt, mobile_token, R"({"lists":{"rooms":{"ranges":[[0,9]]}}})");

            THEN("the response is 200 and the list contains the room created on the desktop")
            {
                REQUIRE(result.response.status == 200U);
                auto const ops = list_ops(result.response.body, "rooms");
                REQUIRE(ops.has_value());
                REQUIRE(!ops->empty());

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

            THEN("the rooms object contains the room with initial = true")
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

// ── Element X compatibility: dual room-list + encryption connections ───────
//
// See the "Element X / matrix-rust-sdk request fidelity" note above for what
// these two connections are and where their shape comes from.

SCENARIO("Element X's room-list connection reports room encryption via required_state",
         "[homeserver][sliding-sync][integration][elementx]")
{
    // Spec: MSC4186 required_state — a room's current m.room.encryption state
    // event must be included when required_state names it, so Element X can
    // mark the room as encrypted. private_chat rooms are auto-encrypted per
    // the Client-Server API's createRoom preset behaviour.
    GIVEN("alice and bob sharing an auto-encrypted private_chat room")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_id = create_room(rt, alice_token); // private_chat preset

        // private_chat rooms default to join_rule=invite, so bob needs an
        // invite from alice before he can join.
        auto const invite_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite_resp.response.status == 200U);

        auto const join_url = "/_matrix/client/v3/rooms/" + room_id + "/join";
        auto const bob_join =
            merovingian::homeserver::handle_client_server_request(rt, {"POST", join_url, bob_token, "{}"});
        REQUIRE(bob_join.response.status == 200U);

        WHEN("alice performs Element X's initial \"room-list\" sliding sync")
        {
            auto const result = sliding_sync(rt, alice_token, element_x_room_list_body());

            THEN("the room is present, initial, and its required_state includes m.room.encryption")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* room = object_member_as_object(rooms, room_id);
                REQUIRE(room != nullptr);
                auto const* initial = bool_member(*room, "initial");
                REQUIRE(initial != nullptr);
                REQUIRE(*initial == true);

                auto const* required_state = object_member_as_array(*room, "required_state");
                REQUIRE(required_state != nullptr);
                auto const has_encryption =
                    std::ranges::any_of(*required_state, [](merovingian::canonicaljson::Value const& v) {
                        auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                        if (ev == nullptr)
                            return false;
                        auto const* type = string_member(*ev, "type");
                        return type != nullptr && *type == "m.room.encryption";
                    });
                REQUIRE(has_encryption);
            }

            THEN("required_state includes alice's own member event (\"$ME\") and bob's (\"$LAZY\", the most "
                 "recent timeline sender)")
            {
                REQUIRE(result.response.status == 200U);
                auto const rooms = rooms_object(result.response.body);
                auto const* room = object_member_as_object(rooms, room_id);
                REQUIRE(room != nullptr);
                auto const* required_state = object_member_as_array(*room, "required_state");
                REQUIRE(required_state != nullptr);

                auto const has_member = [&](std::string_view user_id) {
                    return std::ranges::any_of(*required_state, [&](merovingian::canonicaljson::Value const& v) {
                        auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                        if (ev == nullptr)
                            return false;
                        auto const* type = string_member(*ev, "type");
                        auto const* state_key = string_member(*ev, "state_key");
                        return type != nullptr && *type == "m.room.member" && state_key != nullptr &&
                               *state_key == user_id;
                    });
                };
                REQUIRE(has_member("@alice:example.org"));
                REQUIRE(has_member("@bob:example.org"));
            }
        }
    }
}

SCENARIO("Element X's encryption-only connection parks through activity it never requested",
         "[homeserver][sliding-sync][integration][elementx][notifier]")
{
    // Regression coverage for the sync-storm fix: EncryptionSyncService opens
    // a connection with no lists/subscriptions and only to_device/e2ee
    // enabled. A message, typing notification, or receipt in a room it never
    // asked about must not wake it — it must park until its own timeout.
    GIVEN("alice and bob sharing a room, with alice's encryption connection parked at its initial pos")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_id = create_room(rt, alice_token);

        // private_chat rooms default to join_rule=invite, so bob needs an
        // invite from alice before he can join.
        auto const invite_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite_resp.response.status == 200U);

        auto const join_url = "/_matrix/client/v3/rooms/" + room_id + "/join";
        auto const bob_join =
            merovingian::homeserver::handle_client_server_request(rt, {"POST", join_url, bob_token, "{}"});
        REQUIRE(bob_join.response.status == 200U);

        // Seed both connections exactly as SyncService::build does: room-list
        // first, then the encryption connection.
        auto const room_list_init = sliding_sync(rt, alice_token, element_x_room_list_body());
        REQUIRE(room_list_init.response.status == 200U);

        auto const enc_init = sliding_sync(rt, alice_token, element_x_encryption_body());
        REQUIRE(enc_init.response.status == 200U);
        auto const enc_pos = sliding_sync_pos(enc_init.response.body);

        WHEN("bob is active in the shared room: typing, a message, and a read receipt")
        {
            auto const typing_url = "/_matrix/client/v3/rooms/" + room_id + "/typing/@bob:example.org";
            auto const typing_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"PUT", typing_url, bob_token, R"({"typing":true,"timeout":30000})"});
            REQUIRE(typing_resp.response.status == 200U);

            auto const event_id = send_message_get_id(rt, bob_token, room_id, "hi alice");

            auto const receipt_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, bob_token, "{}"});
            REQUIRE(receipt_resp.response.status == 200U);

            THEN("alice's encryption connection long-poll (can_wait=true) parks instead of firing an empty response")
            {
                auto const target =
                    "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + enc_pos + "&timeout=30000";
                auto const result = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", target, alice_token, element_x_encryption_body()}, /*can_wait=*/true);

                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
            }
        }
    }
}

SCENARIO("Element X's encryption-only connection wakes and delivers device_lists.changed on a key upload",
         "[homeserver][sliding-sync][integration][elementx][e2ee]")
{
    // The flip side of the storm fix: a signal the encryption connection did
    // ask for (e2ee) must still wake it promptly.
    GIVEN("alice and bob sharing a room, with alice's encryption connection parked at its initial pos")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_id = create_room(rt, alice_token);

        // private_chat rooms default to join_rule=invite, so bob needs an
        // invite from alice before he can join.
        auto const invite_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite_resp.response.status == 200U);

        auto const join_url = "/_matrix/client/v3/rooms/" + room_id + "/join";
        auto const bob_join =
            merovingian::homeserver::handle_client_server_request(rt, {"POST", join_url, bob_token, "{}"});
        REQUIRE(bob_join.response.status == 200U);

        auto const enc_init = sliding_sync(rt, alice_token, element_x_encryption_body());
        REQUIRE(enc_init.response.status == 200U);
        auto const enc_pos = sliding_sync_pos(enc_init.response.body);

        WHEN("bob uploads device keys")
        {
            auto const keys_body = R"({"device_keys":{"user_id":"@bob:example.org","device_id":"BOB",)"
                                   R"("algorithms":["m.olm.v1.curve25519-aes-sha2"],)"
                                   R"("keys":{"curve25519:BOB":"BOBCURVE","ed25519:BOB":"BOBED"}}})";
            auto const upload = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/keys/upload", bob_token, keys_body});
            REQUIRE(upload.response.status == 200U);

            THEN("alice's encryption connection long-poll returns complete with bob in device_lists.changed")
            {
                auto const target =
                    "/_matrix/client/unstable/org.matrix.msc4186/sync?pos=" + enc_pos + "&timeout=30000";
                auto const result = merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", target, alice_token, element_x_encryption_body()}, /*can_wait=*/true);

                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);

                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* e2ee = object_member_as_object(*ext, "e2ee");
                REQUIRE(e2ee != nullptr);
                auto const* dl = object_member_as_object(*e2ee, "device_lists");
                REQUIRE(dl != nullptr);
                auto const* changed = object_member_as_array(*dl, "changed");
                REQUIRE(changed != nullptr);
                auto const saw_bob = std::ranges::any_of(*changed, [](merovingian::canonicaljson::Value const& v) {
                    auto const* uid = std::get_if<std::string>(&v.storage());
                    return uid != nullptr && *uid == "@bob:example.org";
                });
                REQUIRE(saw_bob);
            }
        }
    }
}

SCENARIO("Element X's room-list connection delivers receipts requested with rooms:[\"*\"]",
         "[homeserver][sliding-sync][integration][elementx][receipts]")
{
    // RoomListService enables the receipts extension with
    // `rooms: Some(vec![ExtensionRoomConfig::AllSubscribed])`, which
    // serializes to `"rooms":["*"]` (ruma's ExtensionRoomConfig::AllSubscribed
    // -> "*"), not an explicit room ID list and not an omitted field. The
    // server must treat "*" the same as "no room filter" (all rooms in the
    // response), matching every other homeserver's interpretation of the
    // MSC4186 AllSubscribed sentinel.
    GIVEN("alice and bob sharing a room, with alice's room-list connection caught up")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_id = create_room(rt, alice_token);

        // private_chat rooms default to join_rule=invite, so bob needs an
        // invite from alice before he can join.
        auto const invite_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite_resp.response.status == 200U);

        auto const join_url = "/_matrix/client/v3/rooms/" + room_id + "/join";
        auto const bob_join =
            merovingian::homeserver::handle_client_server_request(rt, {"POST", join_url, bob_token, "{}"});
        REQUIRE(bob_join.response.status == 200U);

        auto const init = sliding_sync(rt, alice_token, element_x_room_list_body());
        REQUIRE(init.response.status == 200U);
        auto const pos = sliding_sync_pos(init.response.body);

        WHEN("bob sends a message and alice reads it, then alice re-polls with pos")
        {
            auto const event_id = send_message_get_id(rt, bob_token, room_id, "hi alice");

            auto const receipt_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/receipt/m.read/" + event_id, bob_token, "{}"});
            REQUIRE(receipt_resp.response.status == 200U);

            auto const result = sliding_sync(rt, alice_token, element_x_room_list_body(), pos);

            THEN("extensions.receipts.rooms includes the room's receipt, not a literal room named \"*\"")
            {
                REQUIRE(result.response.status == 200U);
                auto const body = parse_object(result.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* receipts = object_member_as_object(*ext, "receipts");
                REQUIRE(receipts != nullptr);
                auto const* receipt_rooms = object_member_as_object(*receipts, "rooms");
                REQUIRE(receipt_rooms != nullptr);
                auto const* room_receipt = object_member_as_object(*receipt_rooms, room_id);
                REQUIRE(room_receipt != nullptr);
            }
        }
    }
}

SCENARIO("Sliding sync receipts/typing extensions wrap content in a type-tagged event, not bare content",
         "[homeserver][sliding-sync][integration][elementx][receipts][typing]")
{
    // m.receipt and m.typing are EphemeralRoom-kind events (ruma's
    // SyncReceiptEvent / SyncTypingEvent, both requiring {"type":...,
    // "content":...}). Sending bare content instead — verified against
    // ruma-client-api's own deserializer — fails client-side deserialization
    // with "missing field `type`", which matrix-rust-sdk treats as a failed
    // sync iteration: the position never advances and the client retries
    // forever, producing a busy-loop storm on any poll that returns a
    // non-empty receipt or typing notification.
    GIVEN("alice and bob, two rooms, repeated polling like the storm report")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_a = create_room(rt, alice_token);
        auto const invite1 = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_a + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite1.response.status == 200U);
        auto const join1 = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_a + "/join", bob_token, "{}"});
        REQUIRE(join1.response.status == 200U);
        auto const room_b = create_room(rt, alice_token);
        auto const invite2 = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_b + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite2.response.status == 200U);
        auto const join2 = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_b + "/join", bob_token, "{}"});
        REQUIRE(join2.response.status == 200U);

        auto const init = sliding_sync(rt, alice_token, element_x_room_list_body());
        REQUIRE(init.response.status == 200U);
        auto const pos1 = sliding_sync_pos(init.response.body);

        auto const event_id = send_message_get_id(rt, bob_token, room_a, "hello alice");
        auto const typing_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"PUT", "/_matrix/client/v3/rooms/" + room_a + "/typing/@bob:example.org", bob_token,
                 R"({"typing":true,"timeout":30000})"});
        REQUIRE(typing_resp.response.status == 200U);
        auto const receipt_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_a + "/receipt/m.read/" + event_id, alice_token, "{}"});
        REQUIRE(receipt_resp.response.status == 200U);

        WHEN("alice re-polls and receives the receipt and typing notification")
        {
            auto const second = sliding_sync(rt, alice_token, element_x_room_list_body(), pos1);
            REQUIRE(second.response.status == 200U);

            THEN("extensions.receipts.rooms[roomId] is a type-tagged event, not bare receipt content")
            {
                auto const body = parse_object(second.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* receipts = object_member_as_object(*ext, "receipts");
                REQUIRE(receipts != nullptr);
                auto const* receipt_rooms = object_member_as_object(*receipts, "rooms");
                REQUIRE(receipt_rooms != nullptr);
                auto const* room_receipt = object_member_as_object(*receipt_rooms, room_a);
                REQUIRE(room_receipt != nullptr);

                auto const* type = string_member(*room_receipt, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.receipt");
                auto const* content = object_member_as_object(*room_receipt, "content");
                REQUIRE(content != nullptr);
                // Bare (pre-fix) shape had the event_id directly at the top
                // level instead of nested under "content" — assert it is not
                // present there.
                REQUIRE(object_member_as_object(*room_receipt, event_id) == nullptr);
            }

            THEN("extensions.typing.rooms[roomId] is a type-tagged event, not bare {user_ids}")
            {
                auto const body = parse_object(second.response.body);
                auto const* ext = object_member_as_object(body, "extensions");
                REQUIRE(ext != nullptr);
                auto const* typing = object_member_as_object(*ext, "typing");
                REQUIRE(typing != nullptr);
                auto const* typing_rooms = object_member_as_object(*typing, "rooms");
                REQUIRE(typing_rooms != nullptr);
                auto const* room_typing = object_member_as_object(*typing_rooms, room_a);
                REQUIRE(room_typing != nullptr);

                auto const* type = string_member(*room_typing, "type");
                REQUIRE(type != nullptr);
                REQUIRE(*type == "m.typing");
                auto const* content = object_member_as_object(*room_typing, "content");
                REQUIRE(content != nullptr);
                auto const* user_ids = object_member_as_array(*content, "user_ids");
                REQUIRE(user_ids != nullptr);
                // Bare (pre-fix) shape had "user_ids" directly at the top
                // level instead of nested under "content".
                REQUIRE(object_member_as_array(*room_typing, "user_ids") == nullptr);
            }
        }
    }
}

// ── timeline / required_state event_id ──────────────────────────────────────
//
// Stored event JSON is the signed PDU wire format, which does not carry
// event_id (it is derived from a reference hash). Client-facing events MUST
// carry event_id (docs/matrix-v1.19-spec/client-server-api.md#room-event-format).
// A prior regression sent the raw stored PDU JSON straight through for both
// timeline and required_state entries: no event_id, plus federation-only
// fields (auth_events, prev_events, hashes, signatures, depth) that must
// never reach a client. Verified against the real ruma-events deserializer
// (the type matrix-rust-sdk uses to parse each sliding sync timeline entry):
// it rejects the un-fixed shape with "missing field `event_id`" and accepts
// the fixed shape. That silent per-event parse failure — not a top-level
// response error — is why pos still advanced normally while messages never
// appeared on Element X.
SCENARIO("MSC4186 sliding sync timeline and required_state events carry event_id",
         "[homeserver][sliding-sync][integration]")
{
    GIVEN("an Element X room-list connection already established between two joined users")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const room_id = create_room(rt, alice_token);
        auto const invite_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                 R"({"user_id":"@bob:example.org"})"});
        REQUIRE(invite_resp.response.status == 200U);
        auto const join_resp = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob_token, "{}"});
        REQUIRE(join_resp.response.status == 200U);

        auto const init = sliding_sync(rt, alice_token, element_x_room_list_body());
        REQUIRE(init.response.status == 200U);
        auto const pos1 = sliding_sync_pos(init.response.body);

        WHEN("bob sends a message and alice polls again on the established connection")
        {
            auto const sent_event_id = send_message_get_id(rt, bob_token, room_id, "hello from bob");
            auto const second = sliding_sync(rt, alice_token, element_x_room_list_body(), pos1);
            REQUIRE(second.response.status == 200U);

            THEN("the timeline event carries the real event_id, not the raw PDU shape")
            {
                auto const rooms = rooms_object(second.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                auto const* timeline = object_member_as_array(*rm, "timeline");
                REQUIRE(timeline != nullptr);
                REQUIRE(!timeline->empty());

                auto const* last_event = std::get_if<merovingian::canonicaljson::Object>(&timeline->back().storage());
                REQUIRE(last_event != nullptr);
                auto const* event_id = string_member(*last_event, "event_id");
                REQUIRE(event_id != nullptr);
                REQUIRE(*event_id == sent_event_id);
            }
        }

        WHEN("alice's own join event is delivered via $ME required_state on the initial poll")
        {
            THEN("the required_state event carries event_id")
            {
                auto const rooms = rooms_object(init.response.body);
                auto const* rm = object_member_as_object(rooms, room_id);
                REQUIRE(rm != nullptr);
                auto const* required_state = object_member_as_array(*rm, "required_state");
                REQUIRE(required_state != nullptr);

                auto const found_alice_member = std::ranges::any_of(*required_state, [](auto const& val) {
                    auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&val.storage());
                    if (ev == nullptr)
                        return false;
                    auto const* type = string_member(*ev, "type");
                    if (type == nullptr || *type != "m.room.member")
                        return false;
                    auto const* state_key = string_member(*ev, "state_key");
                    if (state_key == nullptr || *state_key != "@alice:example.org")
                        return false;
                    auto const* event_id = string_member(*ev, "event_id");
                    return event_id != nullptr && !event_id->empty();
                });
                REQUIRE(found_alice_member);
            }
        }
    }
}

// ── Ignoring Users (spec: docs/matrix-v1.19-spec/client-server-api.md
// #ignoring-users) — sliding sync builds its own timeline independently of
// legacy /sync, so it must not bypass the same server-side filter.

SCENARIO("MSC4186 sliding sync withholds a non-state timeline event from an ignored sender, but not from an "
         "unignored one",
         "[homeserver][sliding-sync][integration][ignoring-users]")
{
    GIVEN("alice, bob, and carol joined to a room, and alice has ignored bob")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const carol_token = register_and_login(rt, "carol", "CorrectHorse7!", "CAROL");
        auto const room_id = create_room(rt, alice_token);

        for (auto const& user_id : std::vector<std::string>{"@bob:example.org", "@carol:example.org"})
        {
            auto const invite_resp = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/invite", alice_token,
                     R"({"user_id":")" + user_id + R"("})"});
            REQUIRE(invite_resp.response.status == 200U);
        }
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", bob_token, "{}"})
                    .response.status == 200U);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + room_id + "/join", carol_token, "{}"})
                    .response.status == 200U);

        set_ignored_users(rt, alice_token, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        WHEN("bob and carol each send a message and alice polls sliding sync")
        {
            auto const bob_event_id = send_message_get_id(rt, bob_token, room_id, "hello from bob");
            auto const carol_event_id = send_message_get_id(rt, carol_token, room_id, "hello from carol");

            auto const result =
                sliding_sync(rt, alice_token, R"({"lists":{"rooms":{"ranges":[[0,9]],"timeline_limit":10}}})");
            REQUIRE(result.response.status == 200U);

            THEN("the timeline contains carol's message but not bob's")
            {
                auto const rooms = rooms_object(result.response.body);
                auto const* room = object_member_as_object(rooms, room_id);
                REQUIRE(room != nullptr);
                auto const* timeline = object_member_as_array(*room, "timeline");
                REQUIRE(timeline != nullptr);

                // Structural check, not a substring search over the
                // serialized array — see array_has_event_id's comment: carol's
                // message legitimately names bob's event_id in its own
                // "prev_events" field, so a raw text search would find bob's
                // event_id even when his event object was correctly withheld.
                REQUIRE(array_has_event_id(*timeline, carol_event_id));
                REQUIRE_FALSE(array_has_event_id(*timeline, bob_event_id));
            }
        }
    }
}

// Spec MUST (Server behaviour): "Servers must not send room invites from
// ignored users to clients." MSC4186 has no separate invite-state surface
// like legacy /sync's rooms.invite.<room_id>.invite_state; an invite reaches
// a sliding sync client through an explicit room_subscription's
// required_state (a client that already knows the room_id — e.g. from a
// push notification — can subscribe to it before "joining" it). This proves
// the same suppression applies there.
SCENARIO("MSC4186 sliding sync withholds an ignored user's room invite from an explicitly-subscribed room's "
         "required_state",
         "[homeserver][sliding-sync][integration][ignoring-users]")
{
    GIVEN("alice has ignored bob, and both bob and carol have invited her to a room")
    {
        auto const config = sliding_sync_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const alice_token = register_and_login(rt, "alice", "CorrectHorse7!", "ALICE");
        auto const bob_token = register_and_login(rt, "bob", "CorrectHorse7!", "BOB");
        auto const carol_token = register_and_login(rt, "carol", "CorrectHorse7!", "CAROL");

        set_ignored_users(rt, alice_token, "%40alice%3Aexample.org", R"({"ignored_users":{"@bob:example.org":{}}})");

        auto const bob_room = create_room(rt, bob_token);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + bob_room + "/invite", bob_token,
                         R"({"user_id":"@alice:example.org"})"})
                    .response.status == 200U);
        auto const carol_room = create_room(rt, carol_token);
        REQUIRE(merovingian::homeserver::handle_client_server_request(
                    rt, {"POST", "/_matrix/client/v3/rooms/" + carol_room + "/invite", carol_token,
                         R"({"user_id":"@alice:example.org"})"})
                    .response.status == 200U);

        WHEN("alice subscribes to both rooms with required_state naming her own membership")
        {
            auto const body = R"({"room_subscriptions":{")" + bob_room +
                              R"(":{"required_state":[["m.room.member","$ME"]],"timeline_limit":0},")" + carol_room +
                              R"(":{"required_state":[["m.room.member","$ME"]],"timeline_limit":0}}})";
            auto const result = sliding_sync(rt, alice_token, body);
            REQUIRE(result.response.status == 200U);

            THEN("bob's invite is withheld from required_state while carol's is present")
            {
                auto const rooms = rooms_object(result.response.body);

                auto const* bob_room_obj = object_member_as_object(rooms, bob_room);
                REQUIRE(bob_room_obj != nullptr);
                auto const* bob_required_state = object_member_as_array(*bob_room_obj, "required_state");
                auto const bob_has_own_member =
                    bob_required_state != nullptr &&
                    std::ranges::any_of(*bob_required_state, [](merovingian::canonicaljson::Value const& v) {
                        auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                        if (ev == nullptr)
                            return false;
                        auto const* state_key = string_member(*ev, "state_key");
                        return state_key != nullptr && *state_key == "@alice:example.org";
                    });
                REQUIRE_FALSE(bob_has_own_member);

                auto const* carol_room_obj = object_member_as_object(rooms, carol_room);
                REQUIRE(carol_room_obj != nullptr);
                auto const* carol_required_state = object_member_as_array(*carol_room_obj, "required_state");
                REQUIRE(carol_required_state != nullptr);
                auto const carol_has_own_member =
                    std::ranges::any_of(*carol_required_state, [](merovingian::canonicaljson::Value const& v) {
                        auto const* ev = std::get_if<merovingian::canonicaljson::Object>(&v.storage());
                        if (ev == nullptr)
                            return false;
                        auto const* state_key = string_member(*ev, "state_key");
                        return state_key != nullptr && *state_key == "@alice:example.org";
                    });
                REQUIRE(carol_has_own_member);
            }
        }
    }
}
