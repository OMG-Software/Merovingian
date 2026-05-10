// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/homeserver/client_server_mvp.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto login_token(std::string const& body) -> std::string
{
    auto const key = std::string{"\"access_token\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

[[nodiscard]] auto room_id(std::string const& body) -> std::string
{
    auto const key = std::string{"\"room_id\":\""};
    auto const begin = body.find(key);
    REQUIRE(begin != std::string::npos);
    auto const value_begin = begin + key.size();
    auto const value_end = body.find('"', value_begin);
    REQUIRE(value_end != std::string::npos);
    return body.substr(value_begin, value_end - value_begin);
}

} // namespace

SCENARIO("Client-server MVP wraps errors in stable Matrix-style shapes", "[homeserver][client-server]")
{
    GIVEN("a Matrix error")
    {
        WHEN("it is rendered")
        {
            auto const body = merovingian::homeserver::matrix_error("M_FORBIDDEN", "denied");
            auto const response = merovingian::homeserver::LocalHttpResponse{403U, body};

            THEN("the response has a stable Matrix error body")
            {
                REQUIRE(body == R"({"errcode":"M_FORBIDDEN","error":"denied"})");
                REQUIRE(merovingian::homeserver::is_matrix_error_response(response));
            }
        }
    }
}

SCENARIO("Client-server MVP account and device endpoints use real sessions", "[homeserver][client-server]")
{
    GIVEN("a started MVP runtime")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a user registers and logs in")
        {
            auto const registered = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}
            );
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"}
            );
            auto const token = login_token(login.body);
            auto const whoami = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/account/whoami", token, {}}
            );
            auto const devices = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/devices", token, {}}
            );
            auto const update = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/devices/DEVICE1", token, "Alice laptop"}
            );
            auto const updated_devices = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"GET", "/_matrix/client/v3/devices", token, {}}
            );

            THEN("identity, device listing, and device updates work through token validation")
            {
                REQUIRE(registered.status == 200U);
                REQUIRE(login.status == 200U);
                REQUIRE(whoami.status == 200U);
                REQUIRE(whoami.body.find("@alice:example.org") != std::string::npos);
                REQUIRE(devices.status == 200U);
                REQUIRE(devices.body.find("DEVICE1") != std::string::npos);
                REQUIRE(update.status == 200U);
                REQUIRE(updated_devices.body.find("Alice laptop") != std::string::npos);
                REQUIRE(merovingian::homeserver::device_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server MVP escapes login and device JSON strings", "[homeserver][client-server]")
{
    GIVEN("a logged-in MVP user with a device value requiring JSON escapes")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}).status == 200U);

        WHEN("the device id and display name include quotes and backslashes")
        {
            auto const login = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, R"(@alice:example.org|CorrectHorse7!|DEV"\ICE)"});
            auto const token = login_token(login.body);
            auto const update = merovingian::homeserver::handle_client_server_request(runtime, {"PUT", R"(/_matrix/client/v3/devices/DEV"\ICE)", token, R"(Alice "Laptop" \ 1)"});
            auto const devices = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/devices", token, {}});

            THEN("login and device responses remain valid escaped JSON strings")
            {
                REQUIRE(login.status == 200U);
                REQUIRE(login.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(update.status == 200U);
                REQUIRE(devices.status == 200U);
                REQUIRE(devices.body.find(R"("device_id":"DEV\"\\ICE")") != std::string::npos);
                REQUIRE(devices.body.find(R"("display_name":"Alice \"Laptop\" \\ 1")") != std::string::npos);
            }
        }
    }
}

SCENARIO("Client-server MVP room state joined rooms and sync endpoints compose the homeserver path", "[homeserver][client-server]")
{
    GIVEN("a logged-in MVP user")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}).status == 200U);
        auto const login = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/login", {}, "@alice:example.org|CorrectHorse7!|DEVICE1"});
        REQUIRE(login.status == 200U);
        auto const token = login_token(login.body);

        WHEN("the user creates a room, sends encrypted-looking content, and syncs")
        {
            auto const room = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/createRoom", token, {}});
            auto const id = room_id(room.body);
            auto const send = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/rooms/" + id + "/send", token, R"({"type":"m.room.encrypted","content":"secret"})"});
            auto const state = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/rooms/" + id + "/state", token, {}});
            auto const joined = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/joined_rooms", token, {}});
            auto const sync = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/sync", token, {}});

            THEN("room and sync responses are bounded summaries without plaintext event content")
            {
                REQUIRE(room.status == 200U);
                REQUIRE(send.status == 200U);
                REQUIRE(state.status == 200U);
                REQUIRE(joined.status == 200U);
                REQUIRE(joined.body.find(id) != std::string::npos);
                REQUIRE(sync.status == 200U);
                REQUIRE(sync.body.find(id) != std::string::npos);
                REQUIRE(sync.body.find("event_count") != std::string::npos);
                REQUIRE(sync.body.find("secret") == std::string::npos);
                REQUIRE(sync.body.find("m.room.encrypted") == std::string::npos);
                REQUIRE(merovingian::homeserver::joined_room_count(runtime, "@alice:example.org") == 1U);
            }
        }
    }
}

SCENARIO("Client-server MVP enforces request limits and Matrix-style errors", "[homeserver][client-server]")
{
    GIVEN("a started MVP runtime with tight limits")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_body_bytes = 4U;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("oversized and repeated requests are sent")
        {
            auto const oversized = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, "alice|CorrectHorse7!"}
            );
            runtime.limits.max_body_bytes = 4096U;
            auto const first = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const second = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the MVP API reports stable bounded errors")
            {
                REQUIRE(oversized.status == 413U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(oversized));
                REQUIRE(first.status == 401U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(first));
                REQUIRE(second.status == 429U);
                REQUIRE(merovingian::homeserver::is_matrix_error_response(second));
            }
        }
    }
}

SCENARIO("Client-server MVP normalizes route-template rate-limit buckets", "[homeserver][client-server]")
{
    GIVEN("a started MVP runtime with a one-request route bucket")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 64U;

        WHEN("different room IDs hit the same route template")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/rooms/!one:example.org/send", "bad", "{}"});
            auto const second = merovingian::homeserver::handle_client_server_request(runtime, {"POST", "/_matrix/client/v3/rooms/!two:example.org/send", "bad", "{}"});

            THEN("the second request is limited by the normalized route bucket")
            {
                REQUIRE(first.status == 401U);
                REQUIRE(second.status == 429U);
                REQUIRE(runtime.rate_limits.size() == 1U);
            }
        }
    }
}

SCENARIO("Client-server MVP rate-limit buckets reset after the logical window", "[homeserver][client-server]")
{
    GIVEN("a started MVP runtime with a short rate-limit window")
    {
        auto started = merovingian::homeserver::start_client_server_mvp(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        runtime.limits.max_requests_per_bucket = 1U;
        runtime.limits.rate_limit_window_requests = 2U;

        WHEN("a bucket is exhausted and the logical request window advances")
        {
            auto const first = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const limited = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});
            auto const reset = merovingian::homeserver::handle_client_server_request(runtime, {"GET", "/_matrix/client/v3/account/whoami", "bad", {}});

            THEN("the bucket becomes available again after the reset window")
            {
                REQUIRE(first.status == 401U);
                REQUIRE(limited.status == 429U);
                REQUIRE(reset.status == 401U);
            }
        }
    }
}
