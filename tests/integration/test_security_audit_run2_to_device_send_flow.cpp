// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-2, F-13 (ADR-0336) and F-14 (ADR-0335).
//
// F-13: PUT /sendToDevice enqueued each message by walking the whole shared queue, with a scan of
// the batch's evictions for every row, all under runtime.mutex: O(queue x recipients^2). A batch now
// costs one pass over the queue, and one request names at most `max_send_to_device_deliveries`
// local deliveries.
//
// F-14: the queue was bounded in rows, never in bytes. A message is refused over
// `max_to_device_message_bytes` and a recipient's oldest rows are evicted past
// `max_to_device_bytes_per_user_device`.
//
// Spec: client-server-api.md, "Send-to-Device messaging": "Servers should store pending messages
// for local users until they are successfully delivered", and `/sendToDevice` sends "to all known
// devices" for `*`. The spec states no size or delivery limit; the limits are ADR-0335 and
// ADR-0336 decisions.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentToDeviceMessage.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

// Content of exactly `bytes` bytes: {"p":"xxx..."}.
[[nodiscard]] auto content_of_size(std::size_t bytes) -> std::string
{
    auto const overhead = std::string_view{R"({"p":""})"}.size();
    REQUIRE(bytes > overhead);
    return std::string{R"({"p":")"} + std::string(bytes - overhead, 'x') + R"("})";
}

} // namespace

SCENARIO("a client's sendToDevice names a bounded number of deliveries and bounded content",
         "[homeserver][client-server][to-device][security][run2][f13][f14]")
{
    GIVEN("alice with four devices, who sends to herself")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = merovingian::tests::register_and_login_alice(runtime);
        for (auto const* device : {"DEVICE2", "DEVICE3"})
        {
            auto const login = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/login",
                 {},
                 std::string{
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":")"} +
                     device + R"("})"});
            REQUIRE(login.response.status == 200U);
        }
        auto const device_count = runtime.homeserver.database.persistent_store.devices.size();
        REQUIRE(device_count >= 3U);
        auto const send = [&](std::string_view txn, std::string body) {
            return merovingian::homeserver::handle_client_server_request(
                       runtime, {"PUT", "/_matrix/client/v3/sendToDevice/m.test.message/" + std::string{txn}, token,
                                 std::move(body)})
                .response;
        };

        WHEN("a wildcard send would make more local deliveries than one request may")
        {
            runtime.limits.max_send_to_device_deliveries = static_cast<std::uint32_t>(device_count - 1U);
            auto const response = send("wide", R"({"messages":{"@alice:example.org":{"*":{"k":1}}}})");

            THEN("it is refused with 413 M_TOO_LARGE, nothing is queued and the transaction is not recorded")
            {
                REQUIRE(response.status == 413U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
                REQUIRE_FALSE(merovingian::database::find_client_txn_event_id(
                                  runtime.homeserver.database.persistent_store, "@alice:example.org", "DEVICE1", "",
                                  "m.test.message", "wide")
                                  .has_value());
            }
        }

        WHEN("a wildcard send makes exactly as many deliveries as one request may")
        {
            runtime.limits.max_send_to_device_deliveries = static_cast<std::uint32_t>(device_count);
            auto const response = send("exact", R"({"messages":{"@alice:example.org":{"*":{"k":1}}}})");

            THEN("every device gets the message")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.size() == device_count);
            }
        }

        WHEN("a message's content is over the per-message byte limit")
        {
            runtime.homeserver.database.persistent_store.max_to_device_message_bytes = 64U;
            auto const response =
                send("big", R"({"messages":{"@alice:example.org":{"DEVICE1":)" + content_of_size(65U) + "}}}");

            THEN("it is refused with 413 M_TOO_LARGE and nothing is queued")
            {
                REQUIRE(response.status == 413U);
                REQUIRE(response.body.find("M_TOO_LARGE") != std::string::npos);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.empty());
            }
        }

        WHEN("a message's content is within the per-message byte limit")
        {
            runtime.homeserver.database.persistent_store.max_to_device_message_bytes = 64U;
            auto const response =
                send("small", R"({"messages":{"@alice:example.org":{"DEVICE1":)" + content_of_size(64U) + "}}}");

            THEN("it is queued")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(runtime.homeserver.database.persistent_store.to_device_messages.size() == 1U);
            }
        }
    }
}
