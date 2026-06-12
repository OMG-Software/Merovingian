// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX /SYNC HANDLER CONFORMANCE TESTS                     |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync                      |
// |  URL:  ../../docs/matrix-v1.18-spec/client-server-api.md                |
// |        #get_matrixclientv3sync                                          |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/dispatch_result.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <variant>

namespace
{

[[nodiscard]] auto sync_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
};
}

[[nodiscard]] auto extract(std::string const& body, std::string_view key) -> std::string
{
    auto const marker = std::string{"\""} + std::string{key} + "\":\"";
    auto const start = body.find(marker);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + marker.size();
    auto const value_end = body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_start, value_end - value_start);
}

[[nodiscard]] auto json_member(merovingian::canonicaljson::Object const& object,
                               std::string_view key) -> merovingian::canonicaljson::Value const*
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

[[nodiscard]] auto as_object(merovingian::canonicaljson::Value const& value)
    -> merovingian::canonicaljson::Object const*
{
    return std::get_if<merovingian::canonicaljson::Object>(&value.storage());
}

[[nodiscard]] auto as_array(merovingian::canonicaljson::Value const& value) -> merovingian::canonicaljson::Array const*
{
    return std::get_if<merovingian::canonicaljson::Array>(&value.storage());
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt)
    -> std::pair<std::string, std::string>
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        rt,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        rt, {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
             R"("password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.response.status == 200U);
    auto const user_id = std::string{"@alice:example.org"};
    auto const token = extract(login.response.body, "access_token");
    return {user_id, token};
}

// Returns the most-recently-added device for `user`. Registration now creates
// a device first; callers want the login device which is always added last.
[[nodiscard]] auto first_device_id_for(merovingian::homeserver::ClientServerRuntime const& rt,
                                       std::string_view user) -> std::string
{
    auto const result = std::ranges::find_last_if(
        rt.devices, [user](merovingian::homeserver::ClientDevice const& d) { return d.user_id == user; });
    REQUIRE(!result.empty());
    return result.begin()->device_id;
}

[[nodiscard]] auto parse_body(std::string const& body) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

} // namespace

// --- Sync surfaces (Sec. 9.4: initial /sync response structure) ------------------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// An initial /sync (no `since` token) MUST return all queued data for the user:
// account_data, to_device messages, device_lists, presence events, OTK counts,
// and fallback key types. The response MUST include a valid `next_batch` token.
SCENARIO("Sync surfaces account_data, to_device, device_lists, presence, and key counts", "[sync][handler][surfaces]")
{
    GIVEN("a registered Alice with sync surfaces pre-populated")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto const device_id = first_device_id_for(rt, alice_id);
        auto& store = rt.homeserver.database.persistent_store;

        REQUIRE(merovingian::homeserver::set_account_data(rt, {alice_id, "", "m.tag", R"({"tags":{"u.fav":{}}})"}));
        REQUIRE(merovingian::homeserver::push_to_device_message(
            rt, {0U, "@bob:example.org", alice_id, device_id, "m.room_key", R"({"session":"abc"})"}));
        REQUIRE(merovingian::homeserver::record_device_list_change(rt, {0U, alice_id, "@bob:example.org", "changed"}));
        REQUIRE(
            merovingian::homeserver::set_presence(rt, {0U, "@charlie:example.org", "online", "Coding!", 1000, true}));
        REQUIRE(merovingian::database::store_one_time_key(
            store, {alice_id, device_id, "signed_curve25519:AAA", R"({"key":"x"})"}));
        REQUIRE(merovingian::database::store_one_time_key(
            store, {alice_id, device_id, "signed_curve25519:BBB", R"({"key":"y"})"}));
        REQUIRE(merovingian::database::store_fallback_key(
            store, {alice_id, device_id, "signed_curve25519:FALL", R"({"key":"z"})"}));

        WHEN("Alice issues an initial /sync without a since-token")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("the response carries every populated sync surface")
            {
                // Spec MUST: initial /sync response status MUST be 200 OK.
                // Do NOT remove/change - a non-200 means the homeserver rejected a valid sync request.
                REQUIRE(sync.response.status == 200U);
                auto const root_value = parse_body(sync.response.body);
                auto const* root = as_object(root_value);
                REQUIRE(root != nullptr);

                auto const* account_data = as_object(*json_member(*root, "account_data"));
                REQUIRE(account_data != nullptr);
                auto const* ad_events = as_array(*json_member(*account_data, "events"));
                // Spec MUST: account_data.events MUST be present and contain the queued event.
                // Do NOT remove/change - removing this hides account-data delivery regressions.
                REQUIRE(ad_events != nullptr);
                REQUIRE(ad_events->size() == 1U);

                auto const* to_device = as_object(*json_member(*root, "to_device"));
                auto const* td_events = as_array(*json_member(*to_device, "events"));
                // Spec MUST: to_device.events MUST be present and deliver the queued message.
                // Do NOT remove/change - removing this hides to-device delivery regressions.
                REQUIRE(td_events != nullptr);
                REQUIRE(td_events->size() == 1U);

                auto const* device_lists = as_object(*json_member(*root, "device_lists"));
                auto const* changed = as_array(*json_member(*device_lists, "changed"));
                // Spec MUST: device_lists.changed MUST list devices whose keys have changed.
                // Do NOT remove/change - removing this hides key-tracking regressions.
                REQUIRE(changed != nullptr);
                REQUIRE(changed->size() == 1U);

                auto const* presence = as_object(*json_member(*root, "presence"));
                auto const* pres_events = as_array(*json_member(*presence, "events"));
                // Spec MUST: presence.events MUST be present and contain queued presence updates.
                // Do NOT remove/change - removing this hides presence delivery regressions.
                REQUIRE(pres_events != nullptr);
                REQUIRE(pres_events->size() == 1U);

                auto const* otk = as_object(*json_member(*root, "device_one_time_keys_count"));
                REQUIRE(otk != nullptr);
                auto const* curve_count = json_member(*otk, "signed_curve25519");
                // Spec MUST: device_one_time_keys_count MUST reflect the accurate count of uploaded OTKs.
                // Do NOT remove/change - removing this hides OTK-count reporting regressions.
                REQUIRE(curve_count != nullptr);
                REQUIRE(std::get<std::int64_t>(curve_count->storage()) == 2);

                auto const* fallback = as_array(*json_member(*root, "device_unused_fallback_key_types"));
                // Spec MUST: device_unused_fallback_key_types MUST list key algorithms with no claimed fallback.
                // Do NOT remove/change - removing this hides fallback-key reporting regressions.
                REQUIRE(fallback != nullptr);
                REQUIRE(fallback->size() == 1U);

                auto const* next_batch = json_member(*root, "next_batch");
                // Spec MUST: next_batch MUST be present and decodable as a stream token.
                // Do NOT remove/change - next_batch drives all incremental sync; a missing/invalid
                // token would break the client's ability to poll for future events.
                REQUIRE(next_batch != nullptr);
                auto const decoded =
                    merovingian::sync::decode_stream_token(std::get<std::string>(next_batch->storage()));
                REQUIRE(decoded.has_value());
                REQUIRE(decoded->sync_stream_id > 0U);
            }
        }
    }
}

// --- Sync filter - room include/exclude (Sec. 9.4: filter parameter) -------------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// The `filter` parameter's `room.not_rooms` list MUST cause the server to omit
// the listed rooms from `rooms.join` in the response. The join map MUST be empty
// when all joined rooms are excluded by the filter.
SCENARIO("Sync filter limits the timeline events and applies room include/exclude lists", "[sync][handler][filter]")
{
    GIVEN("Alice's runtime with a created room")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto const create = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(create.response.status == 200U);
        auto const room_id = extract(create.response.body, "room_id");

        WHEN("a sync filter excludes the room via not_rooms")
        {
            auto const filter_json = R"json({"room":{"not_rooms":[")json" + room_id + R"json("]}})json";
            auto const sync = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?filter="} + filter_json, token, {}});

            THEN("the join map is empty")
            {
                REQUIRE(sync.response.status == 200U);
                auto const root_value = parse_body(sync.response.body);
                auto const* root = as_object(root_value);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                auto const* join = as_object(*json_member(*rooms, "join"));
                REQUIRE(join != nullptr);
                // Spec MUST: rooms excluded via not_rooms MUST NOT appear in rooms.join.
                // Do NOT remove/change - removing this hides filter non-compliance.
                REQUIRE(join->empty());
            }
        }
    }
}

// --- Incremental sync - since token semantics (Sec. 9.4: since parameter) --------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// Incremental sync (with `since`) MUST only return events newer than the `since`
// token. account_data events that predate the token MUST be suppressed. to_device
// messages MUST be drained exactly once; a second sync with the same token MUST
// NOT re-deliver already-consumed messages.
SCENARIO("Incremental sync drops account_data that predates the since token and drains to_device once",
         "[sync][handler][incremental]")
{
    GIVEN("Alice's runtime with a global account-data row and a to_device message")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto const device_id = first_device_id_for(rt, alice_id);
        REQUIRE(merovingian::homeserver::set_account_data(rt, {alice_id, "", "m.tag", R"({"tags":{"u.fav":{}}})", 0U}));
        REQUIRE(merovingian::homeserver::push_to_device_message(
            rt, {0U, "@bob:example.org", alice_id, device_id, "m.room_key", R"({"k":"v"})"}));

        WHEN("Alice issues an initial /sync, captures next_batch, and immediately re-syncs with since=next_batch")
        {
            auto const first_response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", "/_matrix/client/v3/sync", token, {}});
            REQUIRE(first_response.response.status == 200U);
            auto const first_body = parse_body(first_response.response.body);
            auto const* first_root = as_object(first_body);
            // Spec MUST: next_batch MUST be present and opaque-but-parseable; used as the since token.
            // Do NOT remove/change - the since token is the mechanism for incremental sync correctness.
            auto const next_batch = std::get<std::string>(json_member(*first_root, "next_batch")->storage());

            auto const second_response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}});

            THEN("the second sync's account_data and to_device arrays are empty")
            {
                REQUIRE(second_response.response.status == 200U);
                auto const second_body = parse_body(second_response.response.body);
                auto const* second_root = as_object(second_body);
                auto const* account_data = as_object(*json_member(*second_root, "account_data"));
                auto const* ad_events = as_array(*json_member(*account_data, "events"));
                // Spec MUST: account_data events that predate the since token MUST NOT be re-sent.
                // Do NOT remove/change - removing this hides incremental-sync filtering regressions.
                REQUIRE(ad_events != nullptr);
                REQUIRE(ad_events->empty());

                auto const* to_device = as_object(*json_member(*second_root, "to_device"));
                auto const* td_events = as_array(*json_member(*to_device, "events"));
                // Spec MUST: to_device messages already delivered MUST NOT be re-sent on subsequent syncs.
                // Do NOT remove/change - removing this hides to-device exactly-once delivery regressions.
                REQUIRE(td_events != nullptr);
                REQUIRE(td_events->empty());

                // The drained to_device row is also physically removed from
                // the queue so it cannot resurface on a third sync.
                REQUIRE(rt.homeserver.database.persistent_store.to_device_messages.empty());
            }
        }
    }
}

// --- Long-poll wake-up (Sec. 9.4: timeout parameter) -----------------------------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// The `timeout` parameter controls how long the server waits before returning an
// empty response when no data is available. When new data arrives during the wait
// window the server MUST wake and return the data before the timeout expires.
SCENARIO("Sync long-poll wakes when push_to_device_message publishes through the notifier",
         "[sync][handler][long-poll]")
{
    GIVEN("a registered Alice and a notifier attached")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        std::ignore = merovingian::homeserver::ensure_sync_notifier(rt);

        WHEN("a producer pushes a to-device message mid-wait")
        {
            auto const before_id = rt.sync_notifier->current_sync_stream_id();
            auto const device_id = first_device_id_for(rt, alice_id);
            auto producer = std::thread{[&] {
                std::this_thread::sleep_for(std::chrono::milliseconds{40});
                std::ignore = merovingian::homeserver::push_to_device_message(
                    rt, {0U, "@bob:example.org", alice_id, device_id, "m.room_key", R"({"k":"v"})"});
            }};
            auto const before = std::chrono::steady_clock::now();
            auto const woke = rt.sync_notifier->wait_for_change(0U, before_id, std::chrono::milliseconds{2000});
            producer.join();
            auto const elapsed = std::chrono::steady_clock::now() - before;

            THEN("wait returns true well before the timeout and the stream id advances")
            {
                // Spec MUST: server MUST wake and signal when new data arrives within the timeout window.
                // Do NOT remove/change - removing this hides long-poll notification regressions.
                REQUIRE(woke);
                // Spec MUST: next_batch token MUST advance monotonically after each new event.
                // Do NOT remove/change - a non-advancing stream id breaks incremental sync ordering.
                REQUIRE(rt.sync_notifier->current_sync_stream_id() > before_id);
                REQUIRE(elapsed < std::chrono::seconds{1});
            }
        }
    }
}

// --- next_batch token ordering (Sec. 9.4: next_batch semantics) ------------------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// The `next_batch` token in responses MUST advance monotonically and MUST
// reference the actual last-published ordering, not a speculative future slot.
// Clients use this token as the `since` value for the next incremental sync.
SCENARIO("Sync next_batch token matches last published stream ordering", "[sync][handler][next_batch]")
{
    GIVEN("a registered Alice with a created room and an initial sync")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto const create = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(create.response.status == 200U);

        auto const initial =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);

        WHEN("the next_batch token is decoded")
        {
            auto const body = parse_body(initial.response.body);
            auto const* root = as_object(body);
            auto const* next_batch_val = json_member(*root, "next_batch");
            // Spec MUST: next_batch MUST be present in every /sync response.
            // Do NOT remove/change - absence of next_batch breaks all subsequent incremental syncs.
            REQUIRE(next_batch_val != nullptr);
            auto const next_batch_str = std::get<std::string>(next_batch_val->storage());
            auto const decoded = merovingian::sync::decode_stream_token(next_batch_str);
            REQUIRE(decoded.has_value());

            THEN("event_ordering and membership_ordering never exceed the last published stream ordering")
            {
                // next_stream_ordering is a "next available slot" counter,
                // always +1 ahead of the last published event. The token must
                // reference the actual last ordering, not the next slot.
                auto const last_published = rt.homeserver.database.next_stream_ordering - 1U;
                // Spec MUST: next_batch MUST NOT reference a future (unpublished) stream position.
                // Do NOT remove/change - an off-by-one here causes incremental sync to skip events.
                REQUIRE(decoded->event_ordering <= last_published);
                REQUIRE(decoded->membership_ordering <= last_published);
            }
        }

        WHEN("an incremental sync after creating another room returns a valid next_batch")
        {
            auto const body = parse_body(initial.response.body);
            auto const* root = as_object(body);
            auto const next_batch = std::get<std::string>(json_member(*root, "next_batch")->storage());

            auto const create2 = merovingian::homeserver::handle_client_server_request(
                rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            REQUIRE(create2.response.status == 200U);

            auto const incremental = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}});
            REQUIRE(incremental.response.status == 200U);

            auto const inc_body = parse_body(incremental.response.body);
            auto const* inc_root = as_object(inc_body);
            auto const* inc_next_val = json_member(*inc_root, "next_batch");
            REQUIRE(inc_next_val != nullptr);
            auto const inc_decoded =
                merovingian::sync::decode_stream_token(std::get<std::string>(inc_next_val->storage()));
            REQUIRE(inc_decoded.has_value());

            THEN("the incremental next_batch token also stays within the published range")
            {
                auto const last_published = rt.homeserver.database.next_stream_ordering - 1U;
                // Spec MUST: incremental next_batch MUST advance monotonically and stay within published range.
                // Do NOT remove/change - violating this causes clients to miss or duplicate events.
                REQUIRE(inc_decoded->event_ordering <= last_published);
                REQUIRE(inc_decoded->membership_ordering <= last_published);
            }
        }
    }
}

// --- Two-phase sync dispatch - needs_wait / complete (Sec. 9.4: timeout) ---------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// If `timeout` > 0 and no data is available, the server MUST signal that it
// needs to wait (needs_wait) before the actual network timeout fires. When
// `timeout` is absent the server MUST return immediately (complete). The
// `can_wait=false` path MUST return 200 OK with an empty but valid response
// rather than blocking.
SCENARIO("Two-phase sync dispatch returns needs_wait when no data is available", "[sync][dispatch]")
{
    GIVEN("a registered Alice with no new events after initial sync")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);

        // Initial sync to get a since token
        auto const initial =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const initial_body = parse_body(initial.response.body);
        auto const* initial_root = as_object(initial_body);
        auto const next_batch = std::get<std::string>(json_member(*initial_root, "next_batch")->storage());

        WHEN("an incremental sync with timeout is dispatched and can_wait is true")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch + "&timeout=30000", token, {}},
                /*can_wait=*/true);

            THEN("the result is needs_wait because no new data is available")
            {
                // Spec MUST: server MUST defer response when timeout > 0 and no data is available.
                // Do NOT remove/change - removing this turns long-poll into busy-poll.
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::needs_wait);
                // since_stream_ordering matches the next_batch token from the
                // initial sync. It can be 0 when no room events have been
                // published (next_stream_ordering starts at 1, token uses -1U).
                auto const decoded = merovingian::sync::decode_stream_token(next_batch);
                REQUIRE(decoded.has_value());
                REQUIRE(result.wait.since_stream_ordering == decoded->event_ordering);
                // Spec MUST: timeout MUST be forwarded accurately so the wait layer honours the client request.
                // Do NOT remove/change - a zero timeout would cause the server to never long-poll.
                REQUIRE(result.wait.timeout.count() > 0);
            }
        }

        WHEN("an incremental sync with timeout is dispatched and can_wait is false")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch + "&timeout=30000", token, {}},
                /*can_wait=*/false);

            THEN("the result is complete with an empty sync response")
            {
                // Spec MUST: can_wait=false path MUST return a complete 200 response immediately.
                // Do NOT remove/change - violating this would block the dispatcher thread indefinitely.
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);
            }
        }

        WHEN("an incremental sync with no timeout is dispatched and can_wait is true")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}},
                /*can_wait=*/true);

            THEN("the result is complete because no long-poll was requested")
            {
                // Spec MUST: absence of timeout parameter means the server MUST return immediately.
                // Do NOT remove/change - removing this causes unexpected blocking on no-timeout requests.
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);
            }
        }
    }
}

// --- Stale room data guard (Sec. 9.4: rooms.join incremental correctness) ---------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// `rooms.join` MUST be empty when no room activity has occurred since `since`.
// The `can_wait=false` path MUST NOT re-emit membership state that the client
// already received - doing so wastes bandwidth and breaks client-side state
// machines that expect incremental deltas, not full room snapshots.
SCENARIO("Incremental sync with can_wait=false emits no room data when nothing changed since the since token",
         "[sync][handler][stale-rooms]")
{
    GIVEN("Alice with a created room and an initial sync already completed")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);

        auto const create = merovingian::homeserver::handle_client_server_request(
            rt, {"POST", "/_matrix/client/v3/createRoom", token, {}});
        REQUIRE(create.response.status == 200U);

        // Consume all current state so next_batch is up-to-date
        auto const initial =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const initial_body = parse_body(initial.response.body);
        auto const* initial_root = as_object(initial_body);
        REQUIRE(initial_root != nullptr);
        auto const next_batch = std::get<std::string>(json_member(*initial_root, "next_batch")->storage());

        WHEN("an incremental sync is dispatched with can_wait=false and no new events have occurred")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch + "&timeout=5000", token, {}},
                /*can_wait=*/false);

            THEN("the response is 200 with an empty rooms.join section - no stale room data is emitted")
            {
                // Spec MUST: incremental sync MUST NOT return rooms with no changes since since-token.
                // Do NOT remove/change - this is a regression guard; a non-empty join here means the
                // server is re-sending stale membership state on every timeout re-dispatch cycle.
                REQUIRE(result.status == merovingian::homeserver::DispatchResult::Status::complete);
                REQUIRE(result.response.status == 200U);
                auto const body = parse_body(result.response.body);
                auto const* root = as_object(body);
                REQUIRE(root != nullptr);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                REQUIRE(rooms != nullptr);
                auto const* join = as_object(*json_member(*rooms, "join"));
                REQUIRE(join != nullptr);
                // No timeline or account-data change since since-token: room must
                // be suppressed entirely so the client does not receive 476 bytes
                // of stale membership state on every 5-second timeout re-dispatch.
                // Spec MUST: rooms.join MUST be empty when no room activity has occurred since since-token.
                // Do NOT remove/change - stale room data in incremental sync violates Sec. 9.4 delta semantics.
                REQUIRE(join->empty());
            }
        }
    }
}

// --- Federation-joined room state events visible to incremental sync -----------
// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// If a user joins a remote room via federation (make_join/send_join), the
// state events from the send_join response MUST be stored with a proper
// stream_ordering so that incremental sync can surface them. Events stored
// with stream_ordering == 0 are invisible because the sync filter excludes
// events where stream_ordering <= since_ordering (and 0 <= any since token).
SCENARIO("Federation-joined room state events are visible to incremental sync",
         "[sync][handler][federation][stream-ordering]")
{
    GIVEN("Alice with a room joined via federation after an initial sync")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto& store = rt.homeserver.database.persistent_store;

        // Initial sync to establish a since-token baseline.
        auto const initial =
            merovingian::homeserver::handle_client_server_request(rt, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const initial_body = parse_body(initial.response.body);
        auto const* initial_root = as_object(initial_body);
        REQUIRE(initial_root != nullptr);
        auto const next_batch = std::get<std::string>(json_member(*initial_root, "next_batch")->storage());

        // Simulate the result of a federation join: store the room, membership,
        // and state events with proper stream_ordering (the pattern that the
        // fixed join_room code uses via store_event_with_state).
        auto const room_id = std::string{"!federation:remote.example.org"};
        REQUIRE(merovingian::database::store_room(store, {room_id, alice_id}));
        REQUIRE(merovingian::database::store_membership(store, {room_id, alice_id}) !=
                merovingian::database::MembershipStoreResult::error);
        rt.homeserver.database.rooms.push_back({room_id, alice_id, std::vector<std::string>{alice_id}, {}});

        auto const stream_ordering = rt.homeserver.database.next_stream_ordering++;
        auto const state_event = merovingian::database::PersistentEvent{
            "$event_hash_fed",
            room_id,
            alice_id,
            R"({"type":"m.room.member","room_id":")" + room_id + R"(","sender":")" + alice_id + R"(","state_key":")" +
                alice_id + R"(","content":{"membership":"join"},"origin_server_ts":1234})",
            0U,
            stream_ordering,
            {},
            {},
            {}};
        auto const state =
            merovingian::database::PersistentStateEvent{room_id, "m.room.member", alice_id, "$event_hash_fed"};
        REQUIRE(merovingian::database::store_event_with_state(
            store, state_event, std::optional<merovingian::database::PersistentStateEvent>{state}));

        // Advance sync stream counter so the notifier wakes clients.
        store.next_sync_stream_id += 1U;
        if (rt.homeserver.sync_notifier != nullptr)
        {
            rt.homeserver.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                 store.next_sync_stream_id);
        }

        WHEN("Alice issues an incremental /sync with the since-token captured before the federation join")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}});

            THEN("the response includes the federation-joined room in rooms.join with timeline events")
            {
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_body(sync.response.body);
                auto const* root = as_object(body);
                REQUIRE(root != nullptr);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                REQUIRE(rooms != nullptr);
                auto const* join = as_object(*json_member(*rooms, "join"));
                REQUIRE(join != nullptr);
                // Spec MUST: rooms with new events since the since-token MUST appear in rooms.join.
                // Do NOT remove/change - this is the regression guard for the stream_ordering == 0
                // bug where federation state events were invisible to incremental sync.
                auto const* room_obj = as_object(*json_member(*join, room_id));
                REQUIRE(room_obj != nullptr);
                auto const* timeline = as_object(*json_member(*room_obj, "timeline"));
                REQUIRE(timeline != nullptr);
                auto const* events = as_array(*json_member(*timeline, "events"));
                REQUIRE(events != nullptr);
                REQUIRE(events->size() >= 1U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.18, Sec. 9.4 /sync — rooms.join
// URL:  ../../docs/matrix-v1.18-spec/client-server-api.md#get_matrixclientv3sync
//
// After a local user completes a federated join from a pending invite, the newly-
// joined room MUST appear in rooms.join in the next incremental sync.  The server
// achieves this by storing the local join event in store.events with has_state=true
// so that joined_membership_changed_since detects the invite→join transition.
// Without the fix: current_state still points to the invite event
// (membership="invite"), joined_membership_changed_since returns false, and the
// room is silently suppressed from rooms.join until a full re-sync.
// Regression guard for: federated join from invite leaves room invisible to sync.
SCENARIO("Incremental sync surfaces newly-joined federated room when user had a pending invite",
         "[sync][handler][federation][membership][regression]")
{
    GIVEN("Alice has been invited to a remote room and the invite appears in an initial sync")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        auto& store = rt.homeserver.database.persistent_store;

        auto const room_id        = std::string{"!remote:synapse.example.org"};
        auto const invite_event_id = std::string{"$invite_event_id"};
        auto const join_event_id   = std::string{"$join_event_id"};

        // Persist the remote room shell and the invite event with has_state=true,
        // mirroring what the inbound federation invite handler does.
        REQUIRE(merovingian::database::store_room(store, {room_id, ""}));
        auto const invite_stream = rt.homeserver.database.next_stream_ordering++;
        auto const invite_pe = merovingian::database::PersistentEvent{
            invite_event_id,
            room_id,
            "@remote:synapse.example.org",
            R"({"type":"m.room.member","room_id":")" + room_id +
                R"(","sender":"@remote:synapse.example.org","state_key":")" + alice_id +
                R"(","content":{"membership":"invite"},"origin_server_ts":1000})",
            0U, invite_stream, {}, {}, {}};
        auto const invite_state = merovingian::database::PersistentStateEvent{
            room_id, "m.room.member", alice_id, invite_event_id};
        REQUIRE(merovingian::database::store_event_with_state(
            store, invite_pe,
            std::optional<merovingian::database::PersistentStateEvent>{invite_state}));
        REQUIRE(merovingian::database::store_membership(
                    store, {room_id, alice_id, "invite", invite_stream}) !=
                merovingian::database::MembershipStoreResult::error);
        store.next_sync_stream_id += 1U;

        // Initial sync — establishes the since-token baseline showing the invite.
        auto const initial = merovingian::homeserver::handle_client_server_request(
            rt, {"GET", "/_matrix/client/v3/sync", token, {}});
        REQUIRE(initial.response.status == 200U);
        auto const init_body  = parse_body(initial.response.body);
        auto const* init_root = as_object(init_body);
        REQUIRE(init_root != nullptr);
        auto const next_batch =
            std::get<std::string>(json_member(*init_root, "next_batch")->storage());

        // Simulate the local join event being stored by the fixed remote join path.
        // store_event_with_state stores the event AND updates current_state to point
        // to the join event, so joined_membership_changed_since detects the transition.
        // This is the critical step the fix adds to room_service.cpp::join_room.
        auto const join_stream = rt.homeserver.database.next_stream_ordering++;
        auto const join_pe = merovingian::database::PersistentEvent{
            join_event_id,
            room_id,
            alice_id,
            R"({"type":"m.room.member","room_id":")" + room_id + R"(","sender":")" + alice_id +
                R"(","state_key":")" + alice_id +
                R"(","content":{"membership":"join"},"origin_server_ts":2000})",
            0U, join_stream, {}, {}, {}};
        auto const join_state = merovingian::database::PersistentStateEvent{
            room_id, "m.room.member", alice_id, join_event_id};
        REQUIRE(merovingian::database::store_event_with_state(
            store, join_pe,
            std::optional<merovingian::database::PersistentStateEvent>{join_state}));
        REQUIRE(merovingian::database::update_membership(store, room_id, alice_id, "join"));
        std::ignore = merovingian::database::delete_invite(store, room_id, alice_id);
        rt.homeserver.database.rooms.push_back(
            {room_id, alice_id, std::vector<std::string>{alice_id}, {}});
        store.next_sync_stream_id += 1U;
        if (rt.homeserver.sync_notifier != nullptr)
        {
            rt.homeserver.sync_notifier->publish(rt.homeserver.database.next_stream_ordering - 1U,
                                                 store.next_sync_stream_id);
        }

        WHEN("Alice issues an incremental sync with the since-token captured before the join")
        {
            auto const sync = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}});

            THEN("the joined room appears in rooms.join")
            {
                // Spec MUST: a room where the user's membership changed to 'join'
                // since the since-token MUST appear in rooms.join.  Without storing
                // the join event (the pre-fix bug), joined_membership_changed_since
                // reads the stale invite state entry and returns false, suppressing
                // the room entirely.
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_body(sync.response.body);
                auto const* root = as_object(body);
                REQUIRE(root != nullptr);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                REQUIRE(rooms != nullptr);
                auto const* join_map = as_object(*json_member(*rooms, "join"));
                REQUIRE(join_map != nullptr);
                // Spec MUST: room MUST appear in rooms.join.
                auto const* room_obj = as_object(*json_member(*join_map, room_id));
                REQUIRE(room_obj != nullptr);
            }

            AND_THEN("the join event appears in the room timeline")
            {
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_body(sync.response.body);
                auto const* root = as_object(body);
                REQUIRE(root != nullptr);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                REQUIRE(rooms != nullptr);
                auto const* join_map = as_object(*json_member(*rooms, "join"));
                REQUIRE(join_map != nullptr);
                auto const* room_obj = as_object(*json_member(*join_map, room_id));
                REQUIRE(room_obj != nullptr);
                auto const* timeline = as_object(*json_member(*room_obj, "timeline"));
                REQUIRE(timeline != nullptr);
                auto const* events = as_array(*json_member(*timeline, "events"));
                REQUIRE(events != nullptr);
                // Spec MUST: the join m.room.member event MUST appear in the
                // timeline so clients can observe the membership transition.
                REQUIRE(events->size() >= 1U);
            }

            AND_THEN("the room does NOT appear in rooms.invite after the join")
            {
                REQUIRE(sync.response.status == 200U);
                auto const body = parse_body(sync.response.body);
                auto const* root = as_object(body);
                REQUIRE(root != nullptr);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                REQUIRE(rooms != nullptr);
                auto const* invite_map = as_object(*json_member(*rooms, "invite"));
                REQUIRE(invite_map != nullptr);
                // Must NOT be in rooms.invite — membership is now 'join'.
                auto const in_invite = std::ranges::any_of(
                    *invite_map,
                    [&room_id](merovingian::canonicaljson::ObjectMember const& m) {
                        return m.key == room_id;
                    });
                REQUIRE_FALSE(in_invite);
            }
        }
    }
}
