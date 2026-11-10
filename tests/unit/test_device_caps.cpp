// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
// Security audit run-4 F-05 (ADR-0582). Device creation had no cap on a user's devices and none on a device's
// display name, and one device-list announcement scanned the device tables once per device under the runtime lock.
// Policy: a NEW device past `device_count_limit` is 403 M_FORBIDDEN with nothing written (a device the user already
// holds always logs in); a display name over `device_display_name_byte_limit` bytes is 400 M_TOO_LARGE with nothing
// stored, at POST /login, POST /register and PUT /devices/{deviceId}; an announcement of all of a user's devices makes
// a fixed number of passes over the device tables.

#include "../support/e2ee_caps_support.hpp"
#include "merovingian/database/PersistentDevice.hpp"
#include "merovingian/database/PersistentDeviceKey.hpp"
#include "merovingian/federation/DeviceListUpdateBatch.hpp"
#include "merovingian/federation/key_query.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/device_limits.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

namespace
{

// A store holding `own` devices of alice, each with a published key, and `other` devices of bob.
[[nodiscard]] auto store_with_devices(std::size_t own, std::size_t other) -> merovingian::database::PersistentStore
{
    auto store = merovingian::database::PersistentStore{};
    for (auto index = std::size_t{0U}; index < own + other; ++index)
    {
        auto const user = std::string{index < own ? "@alice:example.org" : "@bob:example.org"};
        auto const device = "D" + std::to_string(index);
        store.devices.push_back({user, device, "name " + device});
        store.device_keys.push_back({user, device,
                                     R"({"algorithms":["m.olm.v1.curve25519-aes-sha2"],"device_id":")" + device +
                                         R"(","keys":{"curve25519:)" + device + R"(":"AAAA","ed25519:)" + device +
                                         R"(":"BBBB"},"user_id":")" + user + R"("})"});
    }
    // One of alice's devices published nothing.
    store.devices.push_back({"@alice:example.org", "NOKEYS", {}});
    return store;
}

} // namespace

SCENARIO("announcing all of a user's devices makes a fixed number of passes over the device tables",
         "[federation][keys][edu][device-list-update][limits][f05]")
{
    namespace fed = merovingian::federation;

    GIVEN("two stores, one with 3 and one with 150 devices for the user, plus another user's devices")
    {
        auto const small = store_with_devices(3U, 4U);
        auto const large = store_with_devices(150U, 40U);

        WHEN("the announcement batch is built for the user in each")
        {
            auto const small_before = small.device_table_rows_examined.value();
            auto const small_batch = fed::build_device_list_update_batch(small, "@alice:example.org", std::nullopt, 9);
            auto const small_rows = small.device_table_rows_examined.value() - small_before;
            auto const large_before = large.device_table_rows_examined.value();
            auto const large_batch = fed::build_device_list_update_batch(large, "@alice:example.org", std::nullopt, 9);
            auto const large_rows = large.device_table_rows_examined.value() - large_before;

            THEN("every device has one entry, and each build reads the device table twice and the key table once")
            {
                REQUIRE(small_batch.entries.size() == 4U);
                REQUIRE(large_batch.entries.size() == 151U);
                REQUIRE(small_rows == 2U * small.devices.size() + small.device_keys.size());
                REQUIRE(large_rows == 2U * large.devices.size() + large.device_keys.size());
            }

            THEN("announcing the devices one at a time reads far more, so the count would show that regression")
            {
                auto const per_device_before = large.device_table_rows_examined.value();
                for (auto const& entry : large_batch.entries)
                {
                    REQUIRE(fed::build_device_list_update_content(large, "@alice:example.org", entry.device_id, 9)
                                .has_value());
                }
                auto const per_device_rows = large.device_table_rows_examined.value() - per_device_before;
                REQUIRE(per_device_rows > 50U * large_rows);
            }

            THEN("each entry is byte-for-byte what the single-device builder returns")
            {
                for (auto const& entry : large_batch.entries)
                {
                    auto const single =
                        fed::build_device_list_update_content(large, "@alice:example.org", entry.device_id, 9);
                    REQUIRE(single.has_value());
                    REQUIRE(entry.content == *single);
                }
                auto const nokeys = std::ranges::find_if(large_batch.entries, [](auto const& entry) {
                    return entry.device_id == "NOKEYS";
                });
                REQUIRE(nokeys != large_batch.entries.end());
                REQUIRE_FALSE(nokeys->has_keys);
                REQUIRE(std::ranges::count_if(large_batch.entries, [](auto const& entry) {
                            return entry.has_keys;
                        }) == 150);
            }
        }

        WHEN("the batch is limited to one device")
        {
            auto const batch = fed::build_device_list_update_batch(large, "@alice:example.org", "D7", 9);

            THEN("it holds that device alone")
            {
                REQUIRE(batch.entries.size() == 1U);
                REQUIRE(batch.entries.front().device_id == "D7");
                REQUIRE(batch.entries.front().has_keys);
                REQUIRE(batch.entries.front().content ==
                        *fed::build_device_list_update_content(large, "@alice:example.org", "D7", 9));
            }
        }
    }
}
