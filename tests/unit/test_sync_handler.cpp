// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
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

[[nodiscard]] auto json_member(merovingian::canonicaljson::Object const& object, std::string_view key)
    -> merovingian::canonicaljson::Value const*
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
    REQUIRE(reg.status == 200U);
    auto const login = merovingian::homeserver::handle_client_server_request(
        rt, {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
             R"("password":"CorrectHorse7!","device_id":"DEVICE1"})"});
    REQUIRE(login.status == 200U);
    auto const user_id = std::string{"@alice:example.org"};
    auto const token = extract(login.body, "access_token");
    return {user_id, token};
}

[[nodiscard]] auto first_device_id_for(merovingian::homeserver::ClientServerRuntime const& rt, std::string_view user)
    -> std::string
{
    auto const it = std::ranges::find_if(rt.devices, [user](merovingian::homeserver::ClientDevice const& d) {
        return d.user_id == user;
    });
    REQUIRE(it != rt.devices.end());
    return it->device_id;
}

[[nodiscard]] auto parse_body(std::string const& body) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

} // namespace

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
                REQUIRE(sync.status == 200U);
                auto const root_value = parse_body(sync.body);
                auto const* root = as_object(root_value);
                REQUIRE(root != nullptr);

                auto const* account_data = as_object(*json_member(*root, "account_data"));
                REQUIRE(account_data != nullptr);
                auto const* ad_events = as_array(*json_member(*account_data, "events"));
                REQUIRE(ad_events != nullptr);
                REQUIRE(ad_events->size() == 1U);

                auto const* to_device = as_object(*json_member(*root, "to_device"));
                auto const* td_events = as_array(*json_member(*to_device, "events"));
                REQUIRE(td_events != nullptr);
                REQUIRE(td_events->size() == 1U);

                auto const* device_lists = as_object(*json_member(*root, "device_lists"));
                auto const* changed = as_array(*json_member(*device_lists, "changed"));
                REQUIRE(changed != nullptr);
                REQUIRE(changed->size() == 1U);

                auto const* presence = as_object(*json_member(*root, "presence"));
                auto const* pres_events = as_array(*json_member(*presence, "events"));
                REQUIRE(pres_events != nullptr);
                REQUIRE(pres_events->size() == 1U);

                auto const* otk = as_object(*json_member(*root, "device_one_time_keys_count"));
                REQUIRE(otk != nullptr);
                auto const* curve_count = json_member(*otk, "signed_curve25519");
                REQUIRE(curve_count != nullptr);
                REQUIRE(std::get<std::int64_t>(curve_count->storage()) == 2);

                auto const* fallback = as_array(*json_member(*root, "device_unused_fallback_key_types"));
                REQUIRE(fallback != nullptr);
                REQUIRE(fallback->size() == 1U);

                auto const* next_batch = json_member(*root, "next_batch");
                REQUIRE(next_batch != nullptr);
                auto const decoded =
                    merovingian::sync::decode_stream_token(std::get<std::string>(next_batch->storage()));
                REQUIRE(decoded.has_value());
                REQUIRE(decoded->sync_stream_id > 0U);
            }
        }
    }
}

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
        REQUIRE(create.status == 200U);
        auto const room_id = extract(create.body, "room_id");

        WHEN("a sync filter excludes the room via not_rooms")
        {
            auto const filter_json = R"json({"room":{"not_rooms":[")json" + room_id + R"json("]}})json";
            auto const sync = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?filter="} + filter_json, token, {}});

            THEN("the join map is empty")
            {
                REQUIRE(sync.status == 200U);
                auto const root_value = parse_body(sync.body);
                auto const* root = as_object(root_value);
                auto const* rooms = as_object(*json_member(*root, "rooms"));
                auto const* join = as_object(*json_member(*rooms, "join"));
                REQUIRE(join != nullptr);
                REQUIRE(join->empty());
            }
        }
    }
}

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
            REQUIRE(first_response.status == 200U);
            auto const first_body = parse_body(first_response.body);
            auto const* first_root = as_object(first_body);
            auto const next_batch = std::get<std::string>(json_member(*first_root, "next_batch")->storage());

            auto const second_response = merovingian::homeserver::handle_client_server_request(
                rt, {"GET", std::string{"/_matrix/client/v3/sync?since="} + next_batch, token, {}});

            THEN("the second sync's account_data and to_device arrays are empty")
            {
                REQUIRE(second_response.status == 200U);
                auto const second_body = parse_body(second_response.body);
                auto const* second_root = as_object(second_body);
                auto const* account_data = as_object(*json_member(*second_root, "account_data"));
                auto const* ad_events = as_array(*json_member(*account_data, "events"));
                REQUIRE(ad_events != nullptr);
                REQUIRE(ad_events->empty());

                auto const* to_device = as_object(*json_member(*second_root, "to_device"));
                auto const* td_events = as_array(*json_member(*to_device, "events"));
                REQUIRE(td_events != nullptr);
                REQUIRE(td_events->empty());

                // The drained to_device row is also physically removed from
                // the queue so it cannot resurface on a third sync.
                REQUIRE(rt.homeserver.database.persistent_store.to_device_messages.empty());
            }
        }
    }
}

SCENARIO("Sync long-poll wakes when push_to_device_message publishes through the notifier",
         "[sync][handler][long-poll]")
{
    GIVEN("a registered Alice and a notifier attached")
    {
        auto started = merovingian::homeserver::start_client_server(sync_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const [alice_id, token] = register_and_login(rt);
        (void)merovingian::homeserver::ensure_sync_notifier(rt);

        WHEN("a producer pushes a to-device message mid-wait")
        {
            auto const before_id = rt.sync_notifier->current_stream_id();
            auto const device_id = first_device_id_for(rt, alice_id);
            auto producer = std::thread{[&] {
                std::this_thread::sleep_for(std::chrono::milliseconds{40});
                (void)merovingian::homeserver::push_to_device_message(
                    rt, {0U, "@bob:example.org", alice_id, device_id, "m.room_key", R"({"k":"v"})"});
            }};
            auto const before = std::chrono::steady_clock::now();
            auto const woke = rt.sync_notifier->wait_for_change(before_id, std::chrono::milliseconds{2000});
            producer.join();
            auto const elapsed = std::chrono::steady_clock::now() - before;

            THEN("wait returns true well before the timeout and the stream id advances")
            {
                REQUIRE(woke);
                REQUIRE(rt.sync_notifier->current_stream_id() > before_id);
                REQUIRE(elapsed < std::chrono::seconds{1});
            }
        }
    }
}
