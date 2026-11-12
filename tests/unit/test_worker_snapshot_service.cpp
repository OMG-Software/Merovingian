// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C44, ADR-0733 and ADR-0735: main answers a federation worker's store requests. A worker may have
// a room read only under a permit main issued on its channel (the room list, or a room_sync main
// sent), each permit gives one read, and later pages come from memory. The sources here are
// functions that count their calls, so every bound is an exact count, never a time.

#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/homeserver/WorkerSnapshotService.hpp"
#include "merovingian/homeserver/WorkerSnapshotSources.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"

#include <catch2/catch_test_macros.hpp>

#include <barrier>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace hs = merovingian::homeserver;
namespace ipc = merovingian::ipc;

using ChannelKey = hs::WorkerSnapshotService::ChannelKey;

// What the fake sources were asked, in order. Written by the thread that called the service; read on the main thread
// after every such thread has been joined.
struct Calls final
{
    std::size_t lists{0U};
    std::vector<std::string> reads{};
    std::vector<std::string> log{};
    std::size_t key_rows_asked{0U};
    std::size_t events_per_room{3U};
    bool fail_reads{false};
    std::chrono::steady_clock::time_point now{};
};

[[nodiscard]] auto make_sources(Calls& calls) -> hs::WorkerSnapshotSources
{
    auto sources = hs::WorkerSnapshotSources{};
    sources.list_rooms = [&calls]() -> std::optional<std::vector<std::string>> {
        ++calls.lists;
        return std::vector<std::string>{"!a:local.example", "!b:local.example"};
    };
    sources.read_room = [&calls](std::string_view room_id) -> std::optional<db::RoomReloadSnapshot> {
        calls.log.emplace_back("read_begin");
        calls.reads.emplace_back(room_id);
        if (calls.fail_reads)
        {
            calls.log.emplace_back("read_end");
            return std::nullopt;
        }
        auto snapshot = db::RoomReloadSnapshot{};
        snapshot.room_id = std::string{room_id};
        snapshot.room = db::PersistentRoom{std::string{room_id}, "@alice:local.example", false};
        for (auto index = std::size_t{0U}; index < calls.events_per_room; ++index)
        {
            auto event = db::PersistentEvent{};
            event.event_id = "$event" + std::to_string(index);
            event.room_id = std::string{room_id};
            event.json = R"({"type":"m.room.message","content":{"body":"padding padding padding padding"}})";
            snapshot.events.push_back(std::move(event));
        }
        // The read transaction ends here, before read_room returns.
        calls.log.emplace_back("read_end");
        return snapshot;
    };
    sources.server_keys = [&calls](std::string_view server_name, std::size_t max_rows) {
        calls.key_rows_asked = max_rows;
        auto keys = std::vector<db::PersistentServerSigningKey>{};
        keys.emplace_back(std::string{server_name}, "ed25519:a", "public-a", 5000U);
        return keys;
    };
    sources.now = [&calls]() {
        return calls.now;
    };
    return sources;
}

[[nodiscard]] auto make_channel() -> ChannelKey
{
    return std::make_shared<int const>(0); // SHARED_PTR: reviewed - test stand-in for a channel's identity.
}

[[nodiscard]] auto ask_snapshot(hs::WorkerSnapshotService& service, ChannelKey const& channel, std::string room_id,
                                std::uint64_t generation, std::uint64_t page) -> std::optional<ipc::RoomSnapshotPage>
{
    return ipc::deserialize_room_snapshot_page(
        service.answer(channel, "room_snapshot_request",
                       ipc::serialize_room_snapshot_request({std::move(room_id), generation, page})));
}

[[nodiscard]] auto ask_list(hs::WorkerSnapshotService& service, ChannelKey const& channel, std::uint64_t page)
    -> std::optional<ipc::RoomListPage>
{
    return ipc::deserialize_room_list_page(
        service.answer(channel, "room_list_request", ipc::serialize_room_list_request(page)));
}

} // namespace

SCENARIO("A worker reads a listed room once, and nothing it was not given",
         "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a service and a worker channel that has asked for nothing yet")
    {
        auto calls = Calls{};
        auto service = hs::WorkerSnapshotService{make_sources(calls), 1U << 20U};
        auto const channel = make_channel();

        WHEN("the worker asks for a room before it was listed")
        {
            auto const page = ask_snapshot(service, channel, "!a:local.example", 0U, 0U);

            THEN("it is refused and nothing is read")
            {
                REQUIRE_FALSE(page.has_value());
                REQUIRE(calls.reads.empty());
            }
        }

        WHEN("the worker takes the list, reads each listed room, then asks again")
        {
            auto const list = ask_list(service, channel, 0U);
            auto const first = ask_snapshot(service, channel, "!a:local.example", 0U, 0U);
            auto const second = ask_snapshot(service, channel, "!b:local.example", 0U, 0U);
            auto const again = ask_snapshot(service, channel, "!a:local.example", 0U, 0U);
            auto const unlisted = ask_snapshot(service, channel, "!c:local.example", 0U, 0U);
            auto const relist = ask_list(service, channel, 0U);

            THEN("the list is read once, each listed room once, and the repeat, the unlisted room and the relist are "
                 "refused")
            {
                REQUIRE(list.has_value());
                REQUIRE(list->room_ids == std::vector<std::string>{"!a:local.example", "!b:local.example"});
                REQUIRE(first.has_value());
                REQUIRE(first->rows.events.size() == 3U);
                REQUIRE(second.has_value());
                REQUIRE_FALSE(again.has_value());
                REQUIRE_FALSE(unlisted.has_value());
                REQUIRE_FALSE(relist.has_value());
                REQUIRE(calls.lists == 1U);
                REQUIRE(calls.reads == std::vector<std::string>{"!a:local.example", "!b:local.example"});
            }
        }

        WHEN("a second channel takes the list and reads a room the first channel listed")
        {
            REQUIRE(ask_list(service, channel, 0U).has_value());
            auto const other = make_channel();
            auto const from_other_unlisted = ask_snapshot(service, other, "!a:local.example", 0U, 0U);
            auto const other_list = ask_list(service, other, 0U);
            auto const from_other = ask_snapshot(service, other, "!a:local.example", 0U, 0U);

            THEN("its permits are its own: refused before its own listing, served after")
            {
                REQUIRE_FALSE(from_other_unlisted.has_value());
                REQUIRE(other_list.has_value());
                REQUIRE(from_other.has_value());
                REQUIRE(calls.lists == 2U);
                REQUIRE(calls.reads.size() == 1U);
            }
        }

        WHEN("the read fails")
        {
            REQUIRE(ask_list(service, channel, 0U).has_value());
            calls.fail_reads = true;
            auto const failed = ask_snapshot(service, channel, "!a:local.example", 0U, 0U);
            calls.fail_reads = false;
            auto const retried = ask_snapshot(service, channel, "!a:local.example", 0U, 0U);

            THEN("the permit is spent all the same: the retry is refused without a read")
            {
                REQUIRE_FALSE(failed.has_value());
                REQUIRE_FALSE(retried.has_value());
                REQUIRE(calls.reads.size() == 1U);
            }
        }
    }
}

SCENARIO("A room_sync main sent lets the worker read that room once, at a generation it was sent",
         "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a service and a worker channel main sent room_sync generation 3 for one room")
    {
        auto calls = Calls{};
        auto service = hs::WorkerSnapshotService{make_sources(calls), 1U << 20U};
        auto const channel = make_channel();
        service.permit_reload(channel, "!a:local.example", 3U);

        WHEN("the worker reloads at generation 3, twice, then at generation 4 which was never sent")
        {
            auto const reload = ask_snapshot(service, channel, "!a:local.example", 3U, 0U);
            auto const repeat = ask_snapshot(service, channel, "!a:local.example", 3U, 0U);
            auto const unsent = ask_snapshot(service, channel, "!a:local.example", 4U, 0U);

            THEN("the first is served and the other two refused, with one read")
            {
                REQUIRE(reload.has_value());
                REQUIRE(reload->generation == 3U);
                REQUIRE_FALSE(repeat.has_value());
                REQUIRE_FALSE(unsent.has_value());
                REQUIRE(calls.reads.size() == 1U);
            }
        }

        WHEN("main sends generations 4 and 5 and the worker coalesces them into one reload at 5")
        {
            service.permit_reload(channel, "!a:local.example", 4U);
            service.permit_reload(channel, "!a:local.example", 5U);
            auto const coalesced = ask_snapshot(service, channel, "!a:local.example", 5U, 0U);
            auto const older = ask_snapshot(service, channel, "!a:local.example", 4U, 0U);

            THEN("generation 5 is served once and an older one is then refused")
            {
                REQUIRE(coalesced.has_value());
                REQUIRE_FALSE(older.has_value());
                REQUIRE(calls.reads.size() == 1U);
            }
        }

        WHEN("another channel asks for the same room and generation")
        {
            auto const other = make_channel();
            auto const page = ask_snapshot(service, other, "!a:local.example", 3U, 0U);

            THEN("it is refused: a permit belongs to the channel it was sent on")
            {
                REQUIRE_FALSE(page.has_value());
                REQUIRE(calls.reads.empty());
            }
        }
    }
}

SCENARIO("Two requests for one permit at once give exactly one read", "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a channel holding one reload permit and two threads released together")
    {
        auto calls = Calls{};
        auto service = hs::WorkerSnapshotService{make_sources(calls), 1U << 20U};
        auto const channel = make_channel();
        service.permit_reload(channel, "!a:local.example", 1U);
        auto const request = ipc::serialize_room_snapshot_request({"!a:local.example", 1U, 0U});
        auto answers = std::vector<std::string>(2U);
        auto start = std::barrier{2};

        WHEN("both ask for page 0 of that generation")
        {
            auto threads = std::vector<std::thread>{};
            for (auto index = std::size_t{0U}; index < 2U; ++index)
            {
                threads.emplace_back([&, index]() {
                    start.arrive_and_wait();
                    answers[index] = service.answer(channel, "room_snapshot_request", request);
                });
            }
            for (auto& thread : threads)
            {
                thread.join();
            }

            THEN("one is served, one refused, and the room was read once")
            {
                auto const served =
                    static_cast<std::size_t>(ipc::deserialize_room_snapshot_page(answers[0]).has_value()) +
                    static_cast<std::size_t>(ipc::deserialize_room_snapshot_page(answers[1]).has_value());
                REQUIRE(served == 1U);
                REQUIRE(calls.reads.size() == 1U);
            }
        }
    }
}

SCENARIO("No lock of the service is held across a read, and the read ends before page 0 is sent",
         "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a read that, while it runs, has another thread use the service and wait for it")
    {
        auto calls = Calls{};
        auto sources = make_sources(calls);
        auto inner = sources.read_room;
        auto other_finished = false;
        hs::WorkerSnapshotService* service_in_read = nullptr;
        sources.read_room = [&](std::string_view room_id) {
            // Joined before the read returns: if the service held its lock across the read, this thread could never
            // take it, and the test would hang (a timeout is a failure) instead of passing.
            auto other = std::thread{[&]() {
                service_in_read->permit_reload(make_channel(), "!x:local.example", 1U);
                other_finished = true;
            }};
            other.join();
            return inner(room_id);
        };
        auto service = hs::WorkerSnapshotService{std::move(sources), 1U << 20U};
        service_in_read = &service;
        auto const channel = make_channel();
        service.permit_reload(channel, "!a:local.example", 1U);

        WHEN("the worker reloads the room and main sends page 0")
        {
            auto const body = service.answer(channel, "room_snapshot_request",
                                             ipc::serialize_room_snapshot_request({"!a:local.example", 1U, 0U}));
            calls.log.emplace_back("send");

            THEN("the other thread used the service during the read, and the read ended before the send")
            {
                REQUIRE(other_finished);
                REQUIRE(ipc::deserialize_room_snapshot_page(body).has_value());
                REQUIRE(calls.log == std::vector<std::string>{"read_begin", "read_end", "send"});
            }
        }
    }
}

SCENARIO("Later pages come from memory, each once and in order, and expire",
         "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a room of 200 events, a small page budget and a reload permit")
    {
        auto calls = Calls{};
        calls.events_per_room = 200U;
        auto service = hs::WorkerSnapshotService{make_sources(calls), 2048U};
        auto const channel = make_channel();
        service.permit_reload(channel, "!a:local.example", 1U);
        auto const first = ask_snapshot(service, channel, "!a:local.example", 1U, 0U);
        REQUIRE(first.has_value());
        REQUIRE(first->pages > 3U);

        WHEN("the worker asks for every later page in order")
        {
            auto all_served = true;
            for (auto page = std::uint64_t{1U}; page < first->pages; ++page)
            {
                all_served = all_served && ask_snapshot(service, channel, "!a:local.example", 1U, page).has_value();
            }
            auto const past_end = ask_snapshot(service, channel, "!a:local.example", 1U, first->pages);

            THEN("each is served without another read, and none past the end")
            {
                REQUIRE(all_served);
                REQUIRE_FALSE(past_end.has_value());
                REQUIRE(calls.reads.size() == 1U);
            }
        }

        WHEN("the worker skips a page, or asks for one twice")
        {
            auto const skipped = ask_snapshot(service, channel, "!a:local.example", 1U, 2U);
            auto const one = ask_snapshot(service, channel, "!a:local.example", 1U, 1U);
            auto const twice = ask_snapshot(service, channel, "!a:local.example", 1U, 1U);

            THEN("the skip and the repeat are refused, the page in order is served")
            {
                REQUIRE_FALSE(skipped.has_value());
                REQUIRE(one.has_value());
                REQUIRE_FALSE(twice.has_value());
            }
        }

        WHEN("the next page is asked for 60 s after the read, and then 61 s after")
        {
            calls.now += hs::WorkerSnapshotService::held_pages_lifetime;
            auto const at_limit = ask_snapshot(service, channel, "!a:local.example", 1U, 1U);
            calls.now += std::chrono::seconds{1};
            auto const expired = ask_snapshot(service, channel, "!a:local.example", 1U, 2U);

            THEN("at the limit it is served; past it the pages are gone")
            {
                REQUIRE(at_limit.has_value());
                REQUIRE_FALSE(expired.has_value());
            }
        }
    }
}

SCENARIO("A key lookup needs no permit, is capped, and the channel's state dies with it",
         "[homeserver][c44][worker-snapshot-service]")
{
    GIVEN("a service and a channel")
    {
        auto calls = Calls{};
        auto service = hs::WorkerSnapshotService{make_sources(calls), 1U << 20U};
        auto channel = make_channel();

        WHEN("the worker asks for a server's keys, and sends a malformed request")
        {
            auto const keys = ipc::deserialize_server_keys_result(
                service.answer(channel, "server_keys_request", ipc::serialize_server_keys_request("remote.example")));
            auto const malformed = ipc::deserialize_server_keys_result(
                service.answer(channel, "server_keys_request", R"({"type":"server_keys_request"})"));

            THEN("the keys come back, asked for with the row cap; the malformed one is refused")
            {
                REQUIRE(keys.has_value());
                REQUIRE(keys->size() == 1U);
                REQUIRE(calls.key_rows_asked == hs::WorkerSnapshotService::max_server_key_rows);
                REQUIRE_FALSE(malformed.has_value());
            }
        }

        WHEN("the channel holds permits and then goes away")
        {
            service.permit_reload(channel, "!a:local.example", 1U);
            REQUIRE(service.channels_tracked() == 1U);
            channel.reset();

            THEN("its state is dropped")
            {
                REQUIRE(service.channels_tracked() == 0U);
            }
        }
    }
}
