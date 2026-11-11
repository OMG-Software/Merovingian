// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PersistentAdminAction.hpp"
#include "merovingian/database/PersistentAuditEvent.hpp"
#include "merovingian/database/PersistentBlobReferenceCount.hpp"
#include "merovingian/database/PersistentLocalMedia.hpp"
#include "merovingian/database/PersistentMediaBlob.hpp"
#include "merovingian/database/PersistentRemoteMedia.hpp"
#include "merovingian/database/PersistentRemoteMediaRelease.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{

namespace database = merovingian::database;

[[nodiscard]] auto digest_of(char fill) -> std::string
{
    return std::string(64U, fill);
}

[[nodiscard]] auto storage_of(char fill) -> std::string
{
    return "blob_" + digest_of(fill) + "_5";
}

[[nodiscard]] auto media_row(std::string media_id, char fill) -> database::PersistentLocalMedia
{
    return {std::move(media_id), "@alice:example.org", "text/plain", 5U, "blake2b", digest_of(fill),
            false,               false,                false,        {}};
}

[[nodiscard]] auto blob_row(char fill, std::uint64_t references) -> database::PersistentMediaBlob
{
    return {storage_of(fill), "blake2b", digest_of(fill), 5U, "hello", references};
}

[[nodiscard]] auto statement_count(database::PersistentStore const& store, std::string const& name) -> std::size_t
{
    return static_cast<std::size_t>(std::ranges::count_if(store.captured_statements, [&name](auto const& statement) {
        return statement.name == name;
    }));
}

[[nodiscard]] auto remove_media(database::PersistentStore& store, std::string const& media_id) -> bool
{
    return database::commit_local_media_moderation(
        store, media_id, false, true, {"@admin:example.org", "media.remove", media_id},
        {"admin", "media.removed", "@admin:example.org", media_id, "test", 0U});
}

} // namespace

SCENARIO("Removing the last reference to a blob deletes its row in the same transaction",
         "[media][database][zero-ref][gate-l]")
{
    GIVEN("a store holding one upload, and two uploads that share a second blob")
    {
        auto store = database::PersistentStore{};
        database::enable_statement_capture(store, 256U);
        REQUIRE(database::commit_local_media_upload(store, media_row("m1", 'a'), blob_row('a', 1U), true, {}));
        REQUIRE(database::commit_local_media_upload(store, media_row("m2", 'b'), blob_row('b', 1U), true, {}));
        REQUIRE(database::commit_local_media_upload(store, media_row("m3", 'b'), blob_row('b', 2U), false, {}));

        WHEN("the only holder of the first blob is removed")
        {
            REQUIRE(remove_media(store, "m1"));

            THEN("the blob row is gone, with a DELETE and no zero-reference update")
            {
                CHECK(store.media_blobs.size() == 1U);
                CHECK(store.media_blobs.front().storage_id == storage_of('b'));
                CHECK(statement_count(store, "delete_media_blob") == 1U);
                CHECK(statement_count(store, "moderate_media_blob") == 0U);
            }
        }

        WHEN("one of two holders of the second blob is removed")
        {
            REQUIRE(remove_media(store, "m2"));

            THEN("the row stays with one reference, and the first bytes can be uploaded again after removal")
            {
                REQUIRE(store.media_blobs.size() == 2U);
                auto const shared = std::ranges::find_if(store.media_blobs, [](auto const& row) {
                    return row.storage_id == storage_of('b');
                });
                REQUIRE(shared != store.media_blobs.end());
                CHECK(shared->ref_count == 1U);
                CHECK(statement_count(store, "delete_media_blob") == 0U);
                REQUIRE(remove_media(store, "m1"));
                REQUIRE(database::commit_local_media_upload(store, media_row("m4", 'a'), blob_row('a', 1U), true, {}));
                CHECK(store.media_blobs.size() == 2U);
            }
        }
    }
}

SCENARIO("A remote media admission deletes the rows of blobs it releases to zero",
         "[media][database][zero-ref][gate-l]")
{
    GIVEN("a store holding a cached remote file and a local file")
    {
        auto store = database::PersistentStore{};
        database::enable_statement_capture(store, 256U);
        REQUIRE(database::commit_local_media_upload(store, media_row("local", 'z'), blob_row('z', 1U), true, {}));
        REQUIRE(database::commit_remote_media_admission(
            store, media_row("r1", 'a'), blob_row('a', 1U), true,
            {"remote.example.org", "one", "text/plain", 5U, false, "r1", 1U}, {}, {}));

        WHEN("the next admission displaces the first and releases its blob")
        {
            REQUIRE(database::commit_remote_media_admission(
                store, media_row("r2", 'b'), blob_row('b', 1U), true,
                {"remote.example.org", "two", "text/plain", 5U, false, "r2", 2U},
                {
                    {"r1", "remote.example.org", "one"}
            },
                {
                    {storage_of('a'), 0U}
            }));

            THEN("the released blob's row is deleted and the new one is held")
            {
                REQUIRE(store.media_blobs.size() == 2U);
                CHECK(std::ranges::none_of(store.media_blobs, [](auto const& row) {
                    return row.storage_id == storage_of('a');
                }));
                CHECK(statement_count(store, "delete_media_blob") == 1U);
                CHECK(store.local_media.size() == 2U);
                CHECK(store.remote_media.size() == 1U);
                CHECK(store.remote_media.front().media_id == "two");
            }
        }
    }
}

SCENARIO("A media commit visits a bounded number of rows however many the store holds",
         "[media][database][eviction-cost][gate-l]")
{
    auto const cost_with = [](std::size_t extra_rows) {
        auto store = database::PersistentStore{};
        for (auto index = std::size_t{0U}; index < extra_rows; ++index)
        {
            auto const name = "bulk" + std::to_string(index);
            REQUIRE(database::store_local_media(store, media_row(name, 'c')));
            REQUIRE(database::store_media_blob(store, {"blob_" + name, "blake2b", digest_of('c'), 5U, "hello", 1U}));
            REQUIRE(database::store_remote_media(
                store, {"remote.example.org", name, "text/plain", 5U, false, name, 1U}));
        }
        REQUIRE(database::commit_remote_media_admission(
            store, media_row("r1", 'a'), blob_row('a', 1U), true,
            {"remote.example.org", "one", "text/plain", 5U, false, "r1", 1U}, {}, {}));
        auto const before = store.media_rows_examined.value();
        REQUIRE(database::commit_remote_media_admission(
            store, media_row("r2", 'b'), blob_row('b', 1U), true,
            {"remote.example.org", "two", "text/plain", 5U, false, "r2", 2U},
            {
                {"r1", "remote.example.org", "one"}
        },
            {
                {storage_of('a'), 0U}
        }));
        return store.media_rows_examined.value() - before;
    };

    GIVEN("stores holding 10 and 400 other media rows")
    {
        WHEN("an admission releases one cached file")
        {
            auto const small = cost_with(10U);
            auto const large = cost_with(400U);

            THEN("the work is the same small number for both")
            {
                CHECK(small <= 16U);
                CHECK(large <= 16U);
            }
        }
    }
}
