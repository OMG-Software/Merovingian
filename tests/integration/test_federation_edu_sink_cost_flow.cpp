// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit release gate (ADR-0603). One signed /send transaction could make the EDU sink scan the whole
// membership and user tables once per key an m.receipt or m.direct_to_device EDU named (up to 65536 per object),
// with runtime.mutex held. Now each key is an index lookup, and an EDU is read only as far as
// max_inbound_receipt_rooms_per_edu, max_inbound_receipt_users_per_edu, max_inbound_direct_to_device_users and
// max_inbound_direct_to_device_device_keys. Cost is shown with the store's rows-examined counters, never time.

#include "../support/E2eeCapsSupport.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/EduDispositionResult.hpp"
#include "merovingian/federation/EduDispositionStatus.hpp"
#include "merovingian/federation/EduType.hpp"
#include "merovingian/federation/InboundEduEnvelope.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/LocalHttpRouter.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using merovingian::homeserver::ClientServerRuntime;
using merovingian::tests::caps_config;
using merovingian::tests::register_and_login_alice;

constexpr auto remote_origin = std::string_view{"remote.example.org"};

[[nodiscard]] auto deliver(ClientServerRuntime& runtime, merovingian::federation::EduType type,
                           std::string_view edu_type, std::string content)
    -> merovingian::federation::EduDispositionResult
{
    auto envelope = merovingian::federation::InboundEduEnvelope{};
    envelope.type = type;
    envelope.edu_type = std::string{edu_type};
    envelope.origin = std::string{remote_origin};
    envelope.content_json = std::move(content);
    merovingian::homeserver::wire_federation_callbacks(runtime.homeserver);
    REQUIRE(runtime.homeserver.federation.edu_sink != nullptr);
    return runtime.homeserver.federation.edu_sink(envelope);
}

// {"!ghost0:<host>":{"m.read":{"@carol:remote.example.org":{"data":{"ts":1},"event_ids":["$ev1"]}}},...}
[[nodiscard]] auto receipt_for_rooms(std::string_view prefix, std::size_t count) -> std::string
{
    auto body = std::string{"{"};
    for (auto index = std::size_t{0U}; index < count; ++index)
    {
        if (index != 0U)
        {
            body += ",";
        }
        body += "\"!" + std::string{prefix} + std::to_string(index) +
                R"(:example.org":{"m.read":{"@carol:remote.example.org":{"data":{"ts":1},"event_ids":["$ev1"]}}})";
    }
    return body + "}";
}

// Fills the membership table with rows of rooms nobody asks about, then brings the index in step.
auto add_filler_memberships(ClientServerRuntime& runtime, std::size_t rows) -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    for (auto index = std::size_t{0U}; index < rows; ++index)
    {
        store.memberships.push_back(
            {"!filler" + std::to_string(index) + ":other.example", "@filler:other.example", "join", 1U});
    }
    merovingian::database::rebuild_membership_index(store);
    merovingian::database::rebuild_key_indexes(store);
}

auto add_room_with_remote_member(ClientServerRuntime& runtime, std::string_view room_id) -> void
{
    auto& store = runtime.homeserver.database.persistent_store;
    store.memberships.push_back({std::string{room_id}, "@alice:example.org", "join", 1U});
    store.memberships.push_back({std::string{room_id}, "@carol:remote.example.org", "join", 1U});
    merovingian::database::rebuild_membership_index(store);
}

} // namespace

SCENARIO("a receipt EDU naming rooms this server is not in reads one membership row per room, whatever the table holds",
         "[integration][federation][edu][receipt][adr-0603]")
{
    GIVEN("two servers, one with 200 and one with 6000 foreign membership rows, and a receipt naming 300 unknown rooms")
    {
        auto small = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        auto large = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(small.started);
        REQUIRE(large.started);
        add_filler_memberships(small.runtime, 200U);
        add_filler_memberships(large.runtime, 6000U);
        auto const content = receipt_for_rooms("ghost", 300U);

        WHEN("the EDU is delivered to each")
        {
            auto& small_store = small.runtime.homeserver.database.persistent_store;
            auto& large_store = large.runtime.homeserver.database.persistent_store;
            auto const small_before = small_store.membership_rows_examined.value();
            auto const large_before = large_store.membership_rows_examined.value();
            auto const small_result =
                deliver(small.runtime, merovingian::federation::EduType::receipt, "m.receipt", content);
            auto const large_result =
                deliver(large.runtime, merovingian::federation::EduType::receipt, "m.receipt", content);
            auto const small_rows = small_store.membership_rows_examined.value() - small_before;
            auto const large_rows = large_store.membership_rows_examined.value() - large_before;

            THEN("both accept it, read exactly one row per room named, and store no receipt")
            {
                REQUIRE(small_result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(large_result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(small_rows == 300U);
                REQUIRE(large_rows == 300U);
                REQUIRE(large_store.receipts.empty());
            }
        }
    }

    GIVEN("a server holding 6000 foreign membership rows and a receipt naming 600 unknown rooms, over the room cap")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        add_filler_memberships(started.runtime, 6000U);
        auto& store = started.runtime.homeserver.database.persistent_store;

        WHEN("the EDU is delivered")
        {
            auto const before = store.membership_rows_examined.value();
            auto const result = deliver(started.runtime, merovingian::federation::EduType::receipt, "m.receipt",
                                        receipt_for_rooms("ghost", 600U));
            auto const rows = store.membership_rows_examined.value() - before;

            THEN("only the first max_inbound_receipt_rooms_per_edu rooms are looked at")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(rows == merovingian::homeserver::max_inbound_receipt_rooms_per_edu);
            }
        }
    }

    GIVEN("a server in 5 rooms with a joined user of the sending server in each")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        add_filler_memberships(started.runtime, 1000U);
        auto content = std::string{"{"};
        for (auto index = 0; index < 5; ++index)
        {
            auto const room = "!real" + std::to_string(index) + ":example.org";
            add_room_with_remote_member(started.runtime, room);
            content += (index == 0 ? "" : ",") + std::string{"\""} + room +
                       R"(":{"m.read":{"@carol:remote.example.org":{"data":{"ts":1},"event_ids":["$ev1"]}}})";
        }
        content += "}";

        WHEN("the receipt EDU naming the 5 rooms is delivered")
        {
            auto const result =
                deliver(started.runtime, merovingian::federation::EduType::receipt, "m.receipt", content);

            THEN("a receipt is stored for each room")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(started.runtime.homeserver.database.persistent_store.receipts.size() == 5U);
            }
        }
    }

    GIVEN("a room this server is in and a receipt naming 400 users of the sending server, over the user cap")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        add_filler_memberships(started.runtime, 1000U);
        add_room_with_remote_member(started.runtime, "!busy:example.org");
        auto content = std::string{R"({"!busy:example.org":{"m.read":{)"};
        for (auto index = 0; index < 400; ++index)
        {
            content += (index == 0 ? "" : ",") + std::string{"\"@u"} + std::to_string(index) +
                       R"(:remote.example.org":{"data":{"ts":1},"event_ids":["$ev1"]})";
        }
        content += "}}}";
        auto& store = started.runtime.homeserver.database.persistent_store;

        WHEN("the EDU is delivered")
        {
            auto const before = store.membership_rows_examined.value();
            auto const result =
                deliver(started.runtime, merovingian::federation::EduType::receipt, "m.receipt", content);
            auto const rows = store.membership_rows_examined.value() - before;

            THEN("one room lookup and only max_inbound_receipt_users_per_edu user lookups are made")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(rows == 1U + merovingian::homeserver::max_inbound_receipt_users_per_edu);
            }
        }
    }
}

SCENARIO("a direct-to-device EDU naming users that do not exist reads one user row per user, whatever the table holds",
         "[integration][federation][edu][to-device][adr-0603]")
{
    GIVEN("a server with a registered user and device, and an EDU naming 900 local users that do not exist")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        std::ignore = register_and_login_alice(started.runtime);
        auto& store = started.runtime.homeserver.database.persistent_store;
        auto content = std::string{R"({"sender":"@s:remote.example.org","type":"m.room.encrypted",)"} +
                       R"("message_id":"ghosts-1","messages":{)";
        for (auto index = 0; index < 900; ++index)
        {
            content += (index == 0 ? "" : ",") + std::string{"\"@ghost"} + std::to_string(index) +
                       R"(:example.org":{"DEV":{"x":1}})";
        }
        content += "}}";

        WHEN("the EDU is delivered")
        {
            auto const users_before = store.user_rows_examined.value();
            auto const devices_before = store.device_table_rows_examined.value();
            auto const result = deliver(started.runtime, merovingian::federation::EduType::direct_to_device,
                                        "m.direct_to_device", content);

            THEN("each user costs one lookup, no device row is read, and nothing is queued")
            {
                REQUIRE(result.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(store.user_rows_examined.value() - users_before == 900U);
                REQUIRE(store.device_table_rows_examined.value() == devices_before);
                REQUIRE(store.to_device_messages.empty());
            }
        }
    }

    GIVEN("an EDU naming more users than the cap")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        auto& store = started.runtime.homeserver.database.persistent_store;
        auto content = std::string{R"({"sender":"@s:remote.example.org","type":"m.room.encrypted",)"} +
                       R"("message_id":"ghosts-2","messages":{)";
        for (auto index = std::size_t{0U}; index < merovingian::homeserver::max_inbound_direct_to_device_users + 200U;
             ++index)
        {
            content += (index == 0U ? "" : ",") + std::string{"\"@ghost"} + std::to_string(index) +
                       R"(:example.org":{"DEV":{"x":1}})";
        }
        content += "}}";

        WHEN("the EDU is delivered")
        {
            auto const before = store.user_rows_examined.value();
            std::ignore = deliver(started.runtime, merovingian::federation::EduType::direct_to_device,
                                  "m.direct_to_device", content);

            THEN("only max_inbound_direct_to_device_users users are looked up")
            {
                REQUIRE(store.user_rows_examined.value() - before ==
                        merovingian::homeserver::max_inbound_direct_to_device_users);
            }
        }
    }

    GIVEN("a registered user with a device, and an EDU addressing the device by name and by '*'")
    {
        auto started = merovingian::homeserver::start_client_server(caps_config(100U, 100U, 100U));
        REQUIRE(started.started);
        std::ignore = register_and_login_alice(started.runtime);
        auto& store = started.runtime.homeserver.database.persistent_store;

        WHEN("the two EDUs are delivered")
        {
            auto const named = deliver(
                started.runtime, merovingian::federation::EduType::direct_to_device, "m.direct_to_device",
                R"({"sender":"@s:remote.example.org","type":"m.room.encrypted","message_id":"named","messages":{"@alice:example.org":{"DEVICE1":{"x":1},"NOPE":{"x":2}}}})");
            auto const all = deliver(
                started.runtime, merovingian::federation::EduType::direct_to_device, "m.direct_to_device",
                R"({"sender":"@s:remote.example.org","type":"m.room.encrypted","message_id":"star","messages":{"@alice:example.org":{"*":{"x":3}}}})");

            THEN("the named device gets one message, the wildcard one per device alice has, and the invented one none")
            {
                auto alice_devices = std::size_t{0U};
                for (auto const& device : store.devices)
                {
                    alice_devices += device.user_id == "@alice:example.org" ? 1U : 0U;
                }
                REQUIRE(alice_devices >= 2U);
                REQUIRE(named.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(all.status == merovingian::federation::EduDispositionStatus::accepted);
                REQUIRE(store.to_device_messages.size() == 1U + alice_devices);
                for (auto const& message : store.to_device_messages)
                {
                    REQUIRE(message.target_user_id == "@alice:example.org");
                    REQUIRE(message.target_device_id != "NOPE");
                }
            }
        }
    }
}
