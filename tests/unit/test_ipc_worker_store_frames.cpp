// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// C44, ADR-0733: the federation worker opens no database, so main sends it every row it reads over
// the IPC channel: the room list, each room's snapshot page by page, and a server's public signing
// keys. These are the frames: rows must arrive exactly (bytes that are not UTF-8, integers past
// 2^53), every page must fit the frame budget, a row too big for any page is refused rather than
// cut, and the worker's assembler refuses pages out of order or rows of another room.

#include "merovingian/database/PersistentServerSigningKey.hpp"
#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/ipc/FederationIpcFrames.hpp"
#include "merovingian/ipc/RoomSnapshotAssembler.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace db = merovingian::database;
namespace ipc = merovingian::ipc;

constexpr auto room_id = "!room:local.example";
// Bytes that are not UTF-8, as a remote server may put in an event the store keeps verbatim.
auto const not_utf8 = std::string{"\xff\xfe raw"};
constexpr auto past_2_53 = std::uint64_t{9'223'372'036'854'775'000ULL};

[[nodiscard]] auto event(std::string event_id, std::uint64_t ordering) -> db::PersistentEvent
{
    auto row = db::PersistentEvent{};
    row.event_id = std::move(event_id);
    row.room_id = room_id;
    row.sender_user_id = "@alice:local.example";
    row.json = R"({"type":"m.room.message","content":{"body":"hello"}})";
    row.depth = ordering;
    row.stream_ordering = ordering;
    return row;
}

// One row of every kind, with the awkward values: bytes that are not UTF-8, an integer past 2^53, a group with and
// without a parent.
[[nodiscard]] auto full_snapshot() -> db::RoomReloadSnapshot
{
    auto snapshot = db::RoomReloadSnapshot{};
    snapshot.room_id = room_id;
    snapshot.room = db::PersistentRoom{room_id, "@alice:local.example", true};
    snapshot.memberships.push_back({room_id, "@bob:remote.example", "join", 7U});
    snapshot.invites.push_back({room_id, "@carol:local.example", "@alice:local.example", "$invite",
                                R"({"type":"m.room.member"})", std::vector<std::string>{R"({"type":"m.room.name"})"},
                                8U, "remote.example"});
    auto first = event("$first", 1U);
    first.json = R"({"body":")" + not_utf8 + R"("})";
    first.depth = past_2_53;
    first.prev_event_ids = {"$zero", not_utf8};
    first.auth_event_ids = {"$create"};
    first.signatures.push_back({"remote.example", "ed25519:a", "c2lnbmF0dXJl"});
    first.status = "soft_failed";
    snapshot.events.push_back(std::move(first));
    snapshot.events.push_back(event("$second", 2U));
    snapshot.state.push_back({room_id, "m.room.member", "@bob:remote.example", "$first"});
    snapshot.state_groups.push_back({"sg:1", room_id, std::nullopt, 0U});
    snapshot.state_groups.push_back({"sg:2", room_id, std::optional<std::string>{"sg:1"}, 1U});
    snapshot.state_group_state.push_back({"sg:2", "m.room.member", "@bob:remote.example", "$first"});
    snapshot.event_state_groups.push_back({"$first", "sg:2"});
    snapshot.forward_extremities.push_back({room_id, "$second"});
    return snapshot;
}

// Parses each page and feeds it to an assembler for (room, generation); nullopt as soon as anything is refused.
[[nodiscard]] auto assemble(std::vector<std::string> const& pages, std::uint64_t generation)
    -> std::optional<db::RoomReloadSnapshot>
{
    auto assembler = ipc::RoomSnapshotAssembler{room_id, generation};
    for (auto const& body : pages)
    {
        auto page = ipc::deserialize_room_snapshot_page(body);
        if (!page.has_value() || !assembler.add_page(std::move(*page)))
        {
            return std::nullopt;
        }
    }
    return assembler.take();
}

[[nodiscard]] auto largest(std::vector<std::string> const& pages) -> std::size_t
{
    auto size = std::size_t{0U};
    for (auto const& page : pages)
    {
        size = std::max(size, page.size());
    }
    return size;
}

} // namespace

SCENARIO("A room snapshot crosses the IPC channel exactly", "[ipc][c44][worker-store-frames]")
{
    GIVEN("a snapshot with one row of every kind, bytes that are not UTF-8 and an integer past 2^53")
    {
        auto const snapshot = full_snapshot();

        WHEN("main paginates it under a 24 MiB frame and the worker assembles the pages")
        {
            auto const pagination =
                ipc::paginate_room_snapshot(snapshot, 42U, ipc::worker_store_page_budget(24U << 20U));
            auto const assembled = assemble(pagination.pages, 42U);

            THEN("it is one page and every row arrives with every field as it was")
            {
                REQUIRE(pagination.refusal.empty());
                REQUIRE(pagination.pages.size() == 1U);
                REQUIRE(assembled.has_value());
                REQUIRE(assembled->room_id == room_id);
                REQUIRE(assembled->room.has_value());
                REQUIRE(assembled->room->creator_user_id == "@alice:local.example");
                REQUIRE(assembled->room->directory_public);
                REQUIRE(assembled->memberships.size() == 1U);
                REQUIRE(assembled->memberships.front().stream_ordering == 7U);
                REQUIRE(assembled->invites.size() == 1U);
                REQUIRE(assembled->invites.front().invite_state_events_json ==
                        snapshot.invites.front().invite_state_events_json);
                REQUIRE(assembled->invites.front().resident_server == "remote.example");
                REQUIRE(assembled->events.size() == 2U);
                auto const& first = assembled->events.front();
                REQUIRE(first.json == snapshot.events.front().json);
                REQUIRE(first.depth == past_2_53);
                REQUIRE(first.prev_event_ids == snapshot.events.front().prev_event_ids);
                REQUIRE(first.auth_event_ids == std::vector<std::string>{"$create"});
                REQUIRE(first.signatures.size() == 1U);
                REQUIRE(first.signatures.front().signature == "c2lnbmF0dXJl");
                REQUIRE(first.status == "soft_failed");
                REQUIRE(assembled->state.size() == 1U);
                REQUIRE(assembled->state_groups.size() == 2U);
                REQUIRE_FALSE(assembled->state_groups[0].parent_state_group_id.has_value());
                REQUIRE(assembled->state_groups[1].parent_state_group_id == std::optional<std::string>{"sg:1"});
                REQUIRE(assembled->state_groups[1].delta_depth == 1U);
                REQUIRE(assembled->state_group_state.size() == 1U);
                REQUIRE(assembled->event_state_groups.size() == 1U);
                REQUIRE(assembled->forward_extremities.size() == 1U);
                REQUIRE(assembled->forward_extremities.front().event_id == "$second");
            }
        }
    }
}

SCENARIO("Room snapshot pages fit the page budget, and a row too big for any page is refused",
         "[ipc][c44][worker-store-frames][boundary]")
{
    GIVEN("a room with 200 events")
    {
        auto snapshot = db::RoomReloadSnapshot{};
        snapshot.room_id = room_id;
        snapshot.room = db::PersistentRoom{room_id, "@alice:local.example", false};
        for (auto index = std::uint64_t{0U}; index < 200U; ++index)
        {
            snapshot.events.push_back(event("$event" + std::to_string(index), index));
        }
        auto const single = ipc::paginate_room_snapshot(snapshot, 1U, 1U << 20U);
        REQUIRE(single.pages.size() == 1U);

        WHEN("the budget is a tenth of the single page")
        {
            auto const budget = single.pages.front().size() / 10U;
            auto const pagination = ipc::paginate_room_snapshot(snapshot, 1U, budget);
            auto const assembled = assemble(pagination.pages, 1U);

            THEN("no page is over the budget, there are more than ten, and all 200 events arrive in order")
            {
                REQUIRE(pagination.refusal.empty());
                REQUIRE(pagination.pages.size() > 10U);
                REQUIRE(largest(pagination.pages) <= budget);
                REQUIRE(assembled.has_value());
                REQUIRE(assembled->events.size() == 200U);
                REQUIRE(assembled->events.front().event_id == "$event0");
                REQUIRE(assembled->events.back().event_id == "$event199");
            }
        }

        WHEN("the budget is exactly what one page needs, and then one byte less")
        {
            // Packing reserves 20 digits for each of generation, page and pages, so a page built with its real
            // numbers is never over the budget; here each is one digit.
            auto const needed = single.pages.front().size() + 3U * 19U;
            auto const exact = ipc::paginate_room_snapshot(snapshot, 1U, needed);
            auto const under = ipc::paginate_room_snapshot(snapshot, 1U, needed - 1U);

            THEN("exactly that is one page; one byte less is two, each within the budget")
            {
                REQUIRE(exact.pages.size() == 1U);
                REQUIRE(under.pages.size() == 2U);
                REQUIRE(largest(under.pages) <= needed - 1U);
                REQUIRE(assemble(under.pages, 1U).has_value());
            }
        }

        WHEN("one event is bigger than any page can hold")
        {
            auto const budget = single.pages.front().size() / 10U;
            snapshot.events[100].json = std::string(budget, 'x');
            auto const pagination = ipc::paginate_room_snapshot(snapshot, 1U, budget);

            THEN("the room is refused, with no pages and nothing cut short")
            {
                REQUIRE(pagination.pages.empty());
                REQUIRE(pagination.refusal == "row_over_page_budget");
            }
        }
    }

    GIVEN("a room with no rows, and a room that no longer exists")
    {
        auto empty = db::RoomReloadSnapshot{};
        empty.room_id = room_id;
        empty.room = db::PersistentRoom{room_id, "@alice:local.example", false};
        auto gone = db::RoomReloadSnapshot{};
        gone.room_id = room_id;

        WHEN("each is paginated and assembled")
        {
            auto const empty_pages = ipc::paginate_room_snapshot(empty, 3U, 4096U);
            auto const gone_pages = ipc::paginate_room_snapshot(gone, 3U, 4096U);

            THEN("each is one page; the first carries its room, the second none")
            {
                REQUIRE(empty_pages.pages.size() == 1U);
                REQUIRE(gone_pages.pages.size() == 1U);
                REQUIRE(assemble(empty_pages.pages, 3U)->room.has_value());
                REQUIRE_FALSE(assemble(gone_pages.pages, 3U)->room.has_value());
            }
        }
    }

    GIVEN("a store with no database to read")
    {
        auto snapshot = db::RoomReloadSnapshot{};
        snapshot.room_id = room_id;
        snapshot.nothing_to_apply = true;

        WHEN("it is paginated")
        {
            auto const pagination = ipc::paginate_room_snapshot(snapshot, 1U, 4096U);

            THEN("it is refused")
            {
                REQUIRE(pagination.pages.empty());
                REQUIRE(pagination.refusal == "no_database");
            }
        }
    }
}

SCENARIO("The worker's assembler refuses pages that do not follow the rules", "[ipc][c44][worker-store-frames]")
{
    GIVEN("a snapshot of 200 events cut into many pages for generation 5")
    {
        auto snapshot = full_snapshot();
        for (auto index = std::uint64_t{10U}; index < 210U; ++index)
        {
            snapshot.events.push_back(event("$event" + std::to_string(index), index));
        }
        auto const pages = ipc::paginate_room_snapshot(snapshot, 5U, 2048U).pages;
        REQUIRE(pages.size() > 3U);

        WHEN("the pages arrive in order")
        {
            auto assembler = ipc::RoomSnapshotAssembler{room_id, 5U};
            for (auto const& body : pages)
            {
                REQUIRE(assembler.add_page(*ipc::deserialize_room_snapshot_page(body)));
            }

            THEN("the snapshot is complete, handed out once, and then never again")
            {
                REQUIRE(assembler.complete());
                REQUIRE(assembler.take().has_value());
                REQUIRE_FALSE(assembler.take().has_value());
            }
        }

        WHEN("page 2 arrives before page 1")
        {
            auto assembler = ipc::RoomSnapshotAssembler{room_id, 5U};
            REQUIRE(assembler.add_page(*ipc::deserialize_room_snapshot_page(pages[0])));
            auto const skipped = assembler.add_page(*ipc::deserialize_room_snapshot_page(pages[2]));
            auto const late = assembler.add_page(*ipc::deserialize_room_snapshot_page(pages[1]));

            THEN("it is refused and the assembly stays spoiled")
            {
                REQUIRE_FALSE(skipped);
                REQUIRE_FALSE(late);
                REQUIRE(assembler.spoiled());
                REQUIRE_FALSE(assembler.take().has_value());
            }
        }

        WHEN("the pages are for another generation or another room")
        {
            auto other_generation = ipc::RoomSnapshotAssembler{room_id, 6U};
            auto other_room = ipc::RoomSnapshotAssembler{"!other:local.example", 5U};

            THEN("page 0 is refused by both")
            {
                REQUIRE_FALSE(other_generation.add_page(*ipc::deserialize_room_snapshot_page(pages[0])));
                REQUIRE_FALSE(other_room.add_page(*ipc::deserialize_room_snapshot_page(pages[0])));
            }
        }
    }

    GIVEN("pages holding a row of another room, or a group entry naming no group of the snapshot")
    {
        auto foreign = full_snapshot();
        foreign.memberships.push_back({"!other:local.example", "@mallory:remote.example", "join", 9U});
        auto orphan = full_snapshot();
        orphan.state_group_state.push_back({"sg:other", "m.room.name", "", "$first"});

        WHEN("each is assembled")
        {
            THEN("each is refused")
            {
                REQUIRE_FALSE(assemble(ipc::paginate_room_snapshot(foreign, 1U, 1U << 20U).pages, 1U).has_value());
                REQUIRE_FALSE(assemble(ipc::paginate_room_snapshot(orphan, 1U, 1U << 20U).pages, 1U).has_value());
            }
        }
    }
}

SCENARIO("The room list, the requests and the key lookup cross the IPC channel exactly",
         "[ipc][c44][worker-store-frames]")
{
    GIVEN("a thousand room IDs, one of them not UTF-8")
    {
        auto room_ids = std::vector<std::string>{};
        for (auto index = 0; index < 1000; ++index)
        {
            room_ids.push_back("!room" + std::to_string(index) + ":local.example");
        }
        room_ids[500] = "!" + not_utf8 + ":local.example";

        WHEN("main paginates them under a 4 KiB budget and the worker reads every page")
        {
            auto const pages = ipc::paginate_room_list(room_ids, 4096U);
            auto received = std::vector<std::string>{};
            auto all_parsed = true;
            for (auto index = std::size_t{0U}; index < pages.size(); ++index)
            {
                auto const page = ipc::deserialize_room_list_page(pages[index]);
                all_parsed = all_parsed && page.has_value() && page->page == index && page->pages == pages.size();
                if (page.has_value())
                {
                    received.insert(received.end(), page->room_ids.begin(), page->room_ids.end());
                }
            }

            THEN("every page fits and the list arrives exactly, in order")
            {
                REQUIRE(pages.size() > 1U);
                REQUIRE(largest(pages) <= 4096U);
                REQUIRE(all_parsed);
                REQUIRE(received == room_ids);
            }
        }

        WHEN("the list is empty, or an ID does not fit a page")
        {
            THEN("an empty list is one page with no IDs, and an ID too big gives no pages")
            {
                auto const empty = ipc::paginate_room_list({}, 4096U);
                REQUIRE(empty.size() == 1U);
                REQUIRE(ipc::deserialize_room_list_page(empty.front())->room_ids.empty());
                REQUIRE(ipc::paginate_room_list({std::string(5000U, 'r')}, 4096U).empty());
            }
        }
    }

    GIVEN("the worker's requests")
    {
        WHEN("each is serialised and read back by main")
        {
            auto const snapshot_request =
                ipc::deserialize_room_snapshot_request(ipc::serialize_room_snapshot_request({room_id, past_2_53, 3U}));
            auto const list_request = ipc::deserialize_room_list_request(ipc::serialize_room_list_request(4U));
            auto const keys_request =
                ipc::deserialize_server_keys_request(ipc::serialize_server_keys_request("remote.example"));

            THEN("each arrives as sent")
            {
                REQUIRE(snapshot_request.has_value());
                REQUIRE(snapshot_request->room_id == room_id);
                REQUIRE(snapshot_request->generation == past_2_53);
                REQUIRE(snapshot_request->page == 3U);
                REQUIRE(list_request == std::optional<std::uint64_t>{4U});
                REQUIRE(keys_request == std::optional<std::string>{"remote.example"});
            }
        }

        WHEN("a request names an empty identifier, or one over 255 bytes")
        {
            THEN("main refuses it; 255 bytes is still read")
            {
                REQUIRE_FALSE(ipc::deserialize_room_snapshot_request(ipc::serialize_room_snapshot_request({"", 1U, 0U}))
                                  .has_value());
                REQUIRE_FALSE(ipc::deserialize_room_snapshot_request(
                                  ipc::serialize_room_snapshot_request({std::string(256U, 'r'), 1U, 0U}))
                                  .has_value());
                REQUIRE(ipc::deserialize_room_snapshot_request(
                            ipc::serialize_room_snapshot_request({std::string(255U, 'r'), 1U, 0U}))
                            .has_value());
                REQUIRE_FALSE(
                    ipc::deserialize_server_keys_request(ipc::serialize_server_keys_request(std::string(256U, 's')))
                        .has_value());
            }
        }

        WHEN("a frame is malformed, of another type, or a refusal")
        {
            THEN("nothing is read from it")
            {
                REQUIRE_FALSE(
                    ipc::deserialize_room_list_request(R"({"type":"room_list_request","page":4})").has_value());
                REQUIRE_FALSE(
                    ipc::deserialize_room_list_request(R"({"type":"room_list_request","page":"-1"})").has_value());
                REQUIRE_FALSE(
                    ipc::deserialize_room_list_request(R"({"type":"room_snapshot_request","page":"1"})").has_value());
                REQUIRE_FALSE(ipc::deserialize_room_snapshot_page(
                                  ipc::serialize_worker_store_refusal("room_snapshot_page", "not_permitted"))
                                  .has_value());
                REQUIRE_FALSE(ipc::deserialize_room_list_page(
                                  ipc::serialize_worker_store_refusal("room_list_page", "read_failed"))
                                  .has_value());
                REQUIRE_FALSE(ipc::deserialize_server_keys_result(
                                  ipc::serialize_worker_store_refusal("server_keys_result", "not_permitted"))
                                  .has_value());
            }
        }
    }

    GIVEN("a key row that holds a secret beside a public one")
    {
        auto keys = std::vector<db::PersistentServerSigningKey>{};
        keys.emplace_back("remote.example", "ed25519:a", "public-a", past_2_53, "secretbox:v1:U0VDUkVU");
        auto retired = db::PersistentServerSigningKey{"remote.example", "ed25519:b", "public-b", 400U};
        retired.expired_ts = 400U;
        keys.push_back(std::move(retired));

        WHEN("main serialises them and the worker reads them back")
        {
            auto const body = ipc::serialize_server_keys_result(keys);
            auto const received = ipc::deserialize_server_keys_result(body);

            THEN("the public columns arrive exactly and the secret is never written")
            {
                REQUIRE(body.find("U0VDUkVU") == std::string::npos);
                REQUIRE(received.has_value());
                REQUIRE(received->size() == 2U);
                REQUIRE((*received)[0].valid_until_ts == past_2_53);
                REQUIRE((*received)[0].secret_key.empty());
                REQUIRE((*received)[1].expired_ts == 400U);
            }
        }

        WHEN("there are no keys")
        {
            THEN("an empty list is a real answer")
            {
                auto const received = ipc::deserialize_server_keys_result(ipc::serialize_server_keys_result({}));
                REQUIRE(received.has_value());
                REQUIRE(received->empty());
            }
        }
    }

    GIVEN("frame caps either side of the header room")
    {
        WHEN("the page budget is taken from each")
        {
            THEN("it is the cap less 1024 bytes, and 0 at or below that")
            {
                REQUIRE(ipc::worker_store_page_budget(24U << 20U) == (24U << 20U) - 1024U);
                REQUIRE(ipc::worker_store_page_budget(1025U) == 1U);
                REQUIRE(ipc::worker_store_page_budget(1024U) == 0U);
            }
        }
    }
}
