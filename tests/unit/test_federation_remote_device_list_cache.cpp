// SPDX-License-Identifier: GPL-3.0-or-later
// The remote device-list cache and the readers that fill it (G14, ADR-0560, ADR-0561).
// Spec: docs/matrix-v1.19-spec/server-server-api.md, "Device Management" and `m.device_list_update`.

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/federation/RemoteDeviceList.hpp"
#include "merovingian/federation/RemoteDeviceListCache.hpp"
#include "merovingian/federation/RemoteDeviceListOutcome.hpp"
#include "merovingian/federation/RemoteDeviceListUpdate.hpp"
#include "merovingian/federation/key_query.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

using merovingian::federation::RemoteCachedDevice;
using merovingian::federation::RemoteDeviceList;
using merovingian::federation::RemoteDeviceListCache;
using merovingian::federation::RemoteDeviceListOutcome;
using merovingian::federation::RemoteDeviceListUpdate;

namespace
{

constexpr auto bob = std::string_view{"@bob:remote.example"};

[[nodiscard]] auto one_device_list(std::int64_t stream_id) -> RemoteDeviceList
{
    auto list = RemoteDeviceList{};
    list.stream_id = stream_id;
    list.devices.emplace("BDEV", RemoteCachedDevice{R"({"device_id":"BDEV"})", "Phone"});
    return list;
}

[[nodiscard]] auto update(std::int64_t stream_id, std::vector<std::int64_t> prev_ids, std::string device_id,
                          std::string keys_json = R"({"k":1})") -> RemoteDeviceListUpdate
{
    auto result = RemoteDeviceListUpdate{};
    result.user_id = std::string{bob};
    result.device_id = std::move(device_id);
    result.stream_id = stream_id;
    result.prev_ids = std::move(prev_ids);
    result.device.keys_json = std::move(keys_json);
    return result;
}

[[nodiscard]] auto cached_at_five() -> RemoteDeviceListCache
{
    auto cache = RemoteDeviceListCache{};
    auto const ticket = cache.begin_resync(bob);
    REQUIRE(cache.store_snapshot(bob, ticket, one_device_list(5)));
    return cache;
}

[[nodiscard]] auto object_of(std::string const& json) -> merovingian::canonicaljson::Object
{
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    return *object;
}

} // namespace

SCENARIO("A filled device list is held until a gap or a removal", "[federation][device_lists][g14]")
{
    GIVEN("bob's list filled from a snapshot at stream_id 5")
    {
        auto cache = cached_at_five();

        WHEN("it is looked up")
        {
            auto const* list = cache.find_current(bob);

            THEN("the snapshot is served")
            {
                REQUIRE(list != nullptr);
                REQUIRE(list->stream_id == 5);
                REQUIRE(list->devices.contains("BDEV"));
                REQUIRE(cache.total_bytes() > 0U);
            }
        }

        WHEN("the next update names stream_id 5 as its prev_id")
        {
            auto const outcome = cache.apply_update(update(6, {5}, "BNEW"));

            THEN("it is applied and the list moves to stream_id 6")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::changed);
                REQUIRE(cache.find_current(bob)->stream_id == 6);
                REQUIRE(cache.find_current(bob)->devices.contains("BNEW"));
            }

            AND_WHEN("the same update arrives again, and then the one after it")
            {
                auto const repeat = cache.apply_update(update(6, {5}, "BNEW"));
                auto const next = cache.apply_update(update(7, {6}, "BNEW", R"({"k":2})"));

                THEN("the repeat changes nothing and the next one, naming 6, is applied")
                {
                    REQUIRE(repeat == RemoteDeviceListOutcome::unchanged);
                    REQUIRE(next == RemoteDeviceListOutcome::changed);
                    REQUIRE(cache.find_current(bob)->devices.at("BNEW").keys_json == R"({"k":2})");
                }
            }
        }

        WHEN("an update re-states a device exactly as held")
        {
            auto same = update(6, {5}, "BDEV", R"({"device_id":"BDEV"})");
            same.device.display_name = "Phone";
            auto const outcome = cache.apply_update(same);

            THEN("it is applied as unchanged: nothing a client sees is different")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::unchanged);
                REQUIRE(cache.find_current(bob)->stream_id == 6);
            }
        }

        WHEN("an update older than the snapshot arrives")
        {
            auto const outcome = cache.apply_update(update(4, {3}, "BOLD"));

            THEN("the snapshot already covers it")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::unchanged);
                REQUIRE_FALSE(cache.find_current(bob)->devices.contains("BOLD"));
            }
        }

        WHEN("an update names a prev_id this server never saw")
        {
            auto const outcome = cache.apply_update(update(9, {8}, "BNEW"));

            THEN("the list is stale and is no longer served")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::resync_needed);
                REQUIRE(cache.find_current(bob) == nullptr);
                REQUIRE(cache.apply_update(update(10, {9}, "BNEW")) == RemoteDeviceListOutcome::resync_needed);
            }
        }

        WHEN("an update with no prev_id arrives")
        {
            auto const outcome = cache.apply_update(update(6, {}, "BNEW"));

            THEN("it starts a sequence this list cannot place, so the list is stale")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::resync_needed);
                REQUIRE(cache.find_current(bob) == nullptr);
            }
        }

        WHEN("an update deletes the held device")
        {
            auto deleted = update(6, {5}, "BDEV");
            deleted.deleted = true;
            auto const outcome = cache.apply_update(deleted);

            THEN("the device is gone")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::changed);
                REQUIRE(cache.find_current(bob)->devices.empty());
            }
        }

        WHEN("the user is marked stale, or erased")
        {
            cache.mark_stale(bob);
            auto const stale = cache.find_current(bob);
            cache.erase(bob);

            THEN("nothing is served, and an erased user's updates find no list")
            {
                REQUIRE(stale == nullptr);
                REQUIRE(cache.size() == 0U);
                REQUIRE(cache.total_bytes() == 0U);
                REQUIRE(cache.apply_update(update(6, {5}, "BNEW")) == RemoteDeviceListOutcome::uncached);
            }
        }
    }
}

SCENARIO("A fill that an update overtook is not kept", "[federation][device_lists][g14][security]")
{
    GIVEN("a fill of bob's list in flight")
    {
        auto cache = RemoteDeviceListCache{};
        auto const ticket = cache.begin_resync(bob);
        REQUIRE(ticket != 0U);

        WHEN("an update for bob arrives before the answer is stored")
        {
            auto const outcome = cache.apply_update(update(6, {5}, "BNEW"));
            auto const kept = cache.store_snapshot(bob, ticket, one_device_list(5));

            THEN("the answer, which may predate the update, is not kept")
            {
                REQUIRE(outcome == RemoteDeviceListOutcome::resync_needed);
                REQUIRE_FALSE(kept);
                REQUIRE(cache.find_current(bob) == nullptr);
            }
        }

        WHEN("a second fill starts before the first is stored")
        {
            auto const second = cache.begin_resync(bob);

            THEN("only the latest ticket keeps its answer")
            {
                REQUIRE_FALSE(cache.store_snapshot(bob, ticket, one_device_list(5)));
                REQUIRE(cache.store_snapshot(bob, second, one_device_list(5)));
            }
        }
    }
}

SCENARIO("The cache refuses lists over its caps", "[federation][device_lists][g14][security]")
{
    GIVEN("a list with one device more than a user may have")
    {
        auto list = RemoteDeviceList{};
        for (auto index = std::size_t{0U}; index <= RemoteDeviceListCache::max_devices_per_user; ++index)
        {
            list.devices.emplace("D" + std::to_string(index), RemoteCachedDevice{"{}", std::nullopt});
        }
        auto cache = RemoteDeviceListCache{};
        auto const ticket = cache.begin_resync(bob);

        WHEN("it is stored")
        {
            auto const kept = cache.store_snapshot(bob, ticket, list);

            THEN("it is not kept and holds no bytes")
            {
                REQUIRE_FALSE(kept);
                REQUIRE(cache.size() == 0U);
                REQUIRE(cache.total_bytes() == 0U);
            }
        }
    }

    GIVEN("a held list one device below the cap")
    {
        auto list = RemoteDeviceList{};
        list.stream_id = 5;
        for (auto index = std::size_t{1U}; index < RemoteDeviceListCache::max_devices_per_user; ++index)
        {
            list.devices.emplace("D" + std::to_string(index), RemoteCachedDevice{"{}", std::nullopt});
        }
        auto cache = RemoteDeviceListCache{};
        REQUIRE(cache.store_snapshot(bob, cache.begin_resync(bob), list));

        WHEN("updates add the last allowed device and then one more")
        {
            auto const at_cap = cache.apply_update(update(6, {5}, "D0"));
            auto const over = cache.apply_update(update(7, {6}, "DX"));

            THEN("the list is held at the cap and dropped past it")
            {
                REQUIRE(at_cap == RemoteDeviceListOutcome::changed);
                REQUIRE(over == RemoteDeviceListOutcome::changed);
                REQUIRE(cache.find_current(bob) == nullptr);
                REQUIRE(cache.total_bytes() == 0U);
            }
        }
    }
}

SCENARIO("A GET /user/devices answer is accepted whole or not at all", "[federation][device_lists][g14][security]")
{
    GIVEN("an answer for bob with one named device")
    {
        auto const body = std::string{R"({"user_id":"@bob:remote.example","stream_id":7,"devices":[)"} +
                          R"({"device_id":"BDEV","device_display_name":"Phone",)" +
                          R"("keys":{"user_id":"@bob:remote.example","device_id":"BDEV","keys":{},)" +
                          R"("unsigned":{"device_display_name":"Old"}}}]})";

        WHEN("it is accepted for bob")
        {
            auto const list = merovingian::federation::accept_remote_user_devices_response("remote.example", bob, body);

            THEN("the device is kept without the remote unsigned, under the entry's display name")
            {
                REQUIRE(list.has_value());
                REQUIRE(list->stream_id == 7);
                auto const& device = list->devices.at("BDEV");
                REQUIRE(device.display_name == std::optional<std::string>{"Phone"});
                REQUIRE(device.keys_json.find("unsigned") == std::string::npos);
            }
        }

        WHEN("it is accepted for another user")
        {
            auto const list = merovingian::federation::accept_remote_user_devices_response(
                "remote.example", "@carol:remote.example", body);

            THEN("it is refused")
            {
                REQUIRE_FALSE(list.has_value());
            }
        }
    }

    GIVEN("answers with one entry wrong")
    {
        auto const misfiled = std::string{R"({"user_id":"@bob:remote.example","stream_id":7,"devices":[)"} +
                              R"({"device_id":"BDEV","keys":{"user_id":"@bob:remote.example","device_id":"OTHER"}}]})";
        auto const repeated = std::string{R"({"user_id":"@bob:remote.example","stream_id":7,"devices":[)"} +
                              R"({"device_id":"BDEV"},{"device_id":"BDEV"}]})";
        auto const no_stream = std::string{R"({"user_id":"@bob:remote.example","devices":[]})"};
        auto const bad_master = std::string{R"({"user_id":"@bob:remote.example","stream_id":7,"devices":[],)"} +
                                R"("master_key":{"user_id":"@carol:remote.example","usage":["master"],)" +
                                R"("keys":{"ed25519:abc":"abc"}}})";

        WHEN("each is accepted")
        {
            THEN("each is refused whole")
            {
                for (auto const& body : {misfiled, repeated, no_stream, bad_master})
                {
                    REQUIRE_FALSE(
                        merovingian::federation::accept_remote_user_devices_response("remote.example", bob, body)
                            .has_value());
                }
            }
        }
    }
}

SCENARIO("An m.device_list_update is read or refused", "[federation][device_lists][g14][security]")
{
    GIVEN("a well-formed update and malformed ones")
    {
        auto const good = object_of(R"({"user_id":"@bob:remote.example","device_id":"BDEV","stream_id":6,)"
                                    R"("prev_id":[5],"deleted":false,"device_display_name":"Phone",)"
                                    R"("keys":{"user_id":"@bob:remote.example","device_id":"BDEV"}})");
        auto const string_prev = object_of(R"({"user_id":"@bob:remote.example","device_id":"BDEV","stream_id":6,)"
                                           R"("prev_id":["5"]})");
        auto const misfiled = object_of(R"({"user_id":"@bob:remote.example","device_id":"BDEV","stream_id":6,)"
                                        R"("keys":{"user_id":"@bob:remote.example","device_id":"OTHER"}})");
        auto const no_stream = object_of(R"({"user_id":"@bob:remote.example","device_id":"BDEV"})");
        auto const long_device = object_of(std::string{R"({"user_id":"@bob:remote.example","device_id":")"} +
                                           std::string(256U, 'D') + R"(","stream_id":6})");

        WHEN("they are read")
        {
            auto const parsed = merovingian::federation::parse_remote_device_list_update(good);

            THEN("the good one carries its fields and every malformed one is refused")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->stream_id == 6);
                REQUIRE(parsed->prev_ids == std::vector<std::int64_t>{5});
                REQUIRE(parsed->device.display_name == std::optional<std::string>{"Phone"});
                REQUIRE_FALSE(parsed->device.keys_json.empty());
                for (auto const* bad : {&string_prev, &misfiled, &no_stream, &long_device})
                {
                    REQUIRE_FALSE(merovingian::federation::parse_remote_device_list_update(*bad).has_value());
                }
            }
        }
    }
}
