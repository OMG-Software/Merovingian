// SPDX-License-Identifier: GPL-3.0-or-later

// MED-4 (29 Sep 2026 audit): generated thumbnails are cached, bounded by bytes
// and evicted least recently used first, so a repeated request does not fork
// the decoder again.

#include "merovingian/config/config.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/media/thumbnail_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

using merovingian::media::CachedThumbnail;
using merovingian::media::ThumbnailCache;
using merovingian::media::ThumbnailCacheKey;
using merovingian::media::ThumbnailMethod;

[[nodiscard]] auto key(std::string media_id, std::uint32_t size, ThumbnailMethod method = ThumbnailMethod::scale)
    -> ThumbnailCacheKey
{
    return {std::move(media_id), "storage-" + std::to_string(size), size, size, method};
}

[[nodiscard]] auto thumbnail(std::size_t bytes) -> CachedThumbnail
{
    return {"image/png", std::string(bytes, 'x')};
}

} // namespace

SCENARIO("generated thumbnails are cached within a byte budget, least recently used first out", "[media][med4]")
{
    GIVEN("a cache holding three 100-byte thumbnails (about 130 bytes each with key and type) under a 450-byte budget")
    {
        auto cache = ThumbnailCache{};
        auto constexpr budget = std::uint64_t{450U};
        cache.insert(key("a", 1U), thumbnail(100U), budget);
        cache.insert(key("b", 1U), thumbnail(100U), budget);
        cache.insert(key("c", 1U), thumbnail(100U), budget);
        REQUIRE(cache.entry_count() == 3U);
        REQUIRE(cache.size_bytes() <= budget);

        WHEN("a is used again and a fourth thumbnail is added")
        {
            REQUIRE(cache.find(key("a", 1U)).has_value());
            cache.insert(key("d", 1U), thumbnail(100U), budget);

            THEN("b, the least recently used, is evicted and the rest stay within budget")
            {
                CHECK(cache.find(key("a", 1U)).has_value());
                CHECK_FALSE(cache.find(key("b", 1U)).has_value());
                CHECK(cache.find(key("c", 1U)).has_value());
                CHECK(cache.find(key("d", 1U)).has_value());
                CHECK(cache.size_bytes() <= budget);
            }
        }

        WHEN("a thumbnail larger than the whole budget is added")
        {
            cache.insert(key("huge", 1U), thumbnail(1000U), budget);

            THEN("it is not stored and nothing else is evicted for it")
            {
                CHECK_FALSE(cache.find(key("huge", 1U)).has_value());
                CHECK(cache.entry_count() == 3U);
            }
        }

        WHEN("the budget is zero")
        {
            cache.insert(key("e", 1U), thumbnail(10U), 0U);

            THEN("caching is off")
            {
                CHECK_FALSE(cache.find(key("e", 1U)).has_value());
            }
        }
    }

    GIVEN("one source with thumbnails at two sizes, two methods and two storage identities")
    {
        auto cache = ThumbnailCache{};
        cache.insert(key("a", 4U), thumbnail(10U), 1000U);

        WHEN("a different size, method or storage of the same media is looked up")
        {
            auto other_storage = key("a", 4U);
            other_storage.storage_id = "replaced";

            THEN("none of them is the cached thumbnail")
            {
                CHECK(cache.find(key("a", 4U)).has_value());
                CHECK_FALSE(cache.find(key("a", 3U)).has_value());
                CHECK_FALSE(cache.find(key("a", 4U, ThumbnailMethod::crop)).has_value());
                CHECK_FALSE(cache.find(other_storage).has_value());
            }
        }
    }
}

SCENARIO("the runtime media config does not hand the thumbnailer a stray worker descriptor", "[media][med4]")
{
    GIVEN("a default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the runtime media config is built from it")
        {
            auto const runtime = merovingian::media::make_runtime_media_config(config);

            THEN("no worker descriptor is set, the decode timeout is 10 s and the thumbnail limits default")
            {
                CHECK(runtime.thumbnail_worker_fd == -1);
                CHECK(runtime.thumbnail_timeout_seconds == 10U);
                CHECK(runtime.thumbnail_cache_max_bytes == 64U * 1024U * 1024U);
                CHECK(runtime.thumbnail_max_concurrent_per_user == 2U);
            }
        }
    }
}
