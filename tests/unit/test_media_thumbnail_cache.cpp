// SPDX-License-Identifier: GPL-3.0-or-later

// MED-4 (29 Sep 2026 audit): generated thumbnails are cached, bounded by bytes
// and evicted least recently used first, so a repeated request does not fork
// the decoder again.

#include "merovingian/config/config.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/media/thumbnail_cache.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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

SCENARIO("a thumbnail cache size of empty or 0 disables the cache, as documented", "[media][med4]")
{
    // PR #509 review: the manual and ADR-0152 say empty or `0` disables the
    // cache, but `0` failed validation because a size limit rejects zero.
    for (auto const* value : {"0", ""})
    {
        GIVEN(std::string{"security.media.thumbnail_cache_size = '"} + value + "'")
        {
            auto config = merovingian::config::Config{};
            config.security().media.thumbnail_cache_size = value;

            WHEN("the configuration is validated and the runtime media config built")
            {
                auto const findings = merovingian::config::validate(config);
                auto const runtime = merovingian::media::make_runtime_media_config(config);

                THEN("the value is accepted and no thumbnail bytes are cached")
                {
                    CHECK(std::ranges::none_of(findings, [](auto const& finding) {
                        return finding.field == "security.media.thumbnail_cache_size";
                    }));
                    CHECK(runtime.thumbnail_cache_max_bytes == 0U);
                }
            }
        }
    }
}

SCENARIO("thumbnail requests beyond the decoder's largest dimension share one cache entry", "[media][med4]")
{
    // PR #509 review: the worker clamps each axis to 4096, so width=5000,
    // 5001, ... produce the same bytes. Keying on the raw request let one
    // client fill the cache with copies and evict everyone else's thumbnails.
    GIVEN("a cached thumbnail requested at 9000x9000")
    {
        auto cache = ThumbnailCache{};
        auto constexpr budget = std::uint64_t{1U} << 20U;
        auto const huge = ThumbnailCacheKey{"a", "storage-a", 9000U, 9000U, ThumbnailMethod::scale};
        cache.insert(huge, thumbnail(100U), budget);

        WHEN("other sizes past the largest dimension are inserted and looked up")
        {
            cache.insert({"a", "storage-a", 5000U, 4097U, ThumbnailMethod::scale}, thumbnail(100U), budget);
            cache.insert({"a", "storage-a", 4294967295U, 70000U, ThumbnailMethod::scale}, thumbnail(100U), budget);
            auto const at_limit = cache.find({"a", "storage-a", merovingian::media::max_thumbnail_dimension,
                                              merovingian::media::max_thumbnail_dimension, ThumbnailMethod::scale});

            THEN("they are one entry, which the largest real size also finds")
            {
                CHECK(cache.entry_count() == 1U);
                CHECK(at_limit.has_value());
            }
        }

        WHEN("a size within the limit is inserted")
        {
            cache.insert({"a", "storage-a", 4096U, 4095U, ThumbnailMethod::scale}, thumbnail(100U), budget);

            THEN("it is a distinct entry")
            {
                CHECK(cache.entry_count() == 2U);
            }
        }
    }
}
