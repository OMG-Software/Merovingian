// SPDX-License-Identifier: GPL-3.0-or-later
//
// Integration coverage for the out-of-process image thumbnail worker. These
// scenarios spawn the real sandboxed worker binary and verify that an image is
// genuinely decoded, resampled, and re-encoded — not passed through unchanged.

#include "merovingian/media/thumbnailer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <utility>

namespace
{

// An 8x8 RGBA PNG (red/blue checkerboard), generated offline. Embedded so the
// test does not depend on an encoder being available to the test process.
constexpr std::array<unsigned char, 81U> sample_png_8x8{
    137, 80,  78,  71,  13,  10, 26, 10,  0,   0,   0,   13,  73, 72,  68,  82,  0,  0,  0,  8,   0,
    0,   0,   8,   8,   6,   0,  0,  0,   196, 15,  190, 139, 0,  0,   0,   24,  73, 68, 65, 84,  120,
    156, 99,  248, 207, 192, 0,  66, 255, 113, 209, 12,  248, 36, 193, 244, 176, 48, 1,  0,  131, 23,
    127, 129, 6,   228, 109, 45, 0,  0,   0,   0,   73,  69,  78, 68,  174, 66,  96, 130};

[[nodiscard]] auto sample_png() -> std::string
{
    return std::string{reinterpret_cast<char const*>(sample_png_8x8.data()), sample_png_8x8.size()};
}

// Reads the width/height from a PNG's IHDR chunk (bytes 16..23, big-endian).
// [[maybe_unused]]: only referenced by the worker scenarios, which are compiled
// out when the image codecs (and thus the worker) are unavailable.
[[maybe_unused]] [[nodiscard]] auto png_dimensions(std::string const& png) -> std::pair<std::uint32_t, std::uint32_t>
{
    auto read_be = [&png](std::size_t offset) {
        return (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset])) << 24) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 1U])) << 16) |
               (static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 2U])) << 8) |
               static_cast<std::uint32_t>(static_cast<unsigned char>(png[offset + 3U]));
    };
    return {read_be(16U), read_be(20U)};
}

[[maybe_unused]] [[nodiscard]] auto is_png(std::string const& bytes) -> bool
{
    return bytes.size() > 8U && static_cast<unsigned char>(bytes[0]) == 137U && bytes[1] == 'P' && bytes[2] == 'N' &&
           bytes[3] == 'G';
}

} // namespace

#ifdef MEROVINGIAN_TEST_THUMBNAIL_WORKER

SCENARIO("the sandboxed worker resamples a PNG to the requested size", "[media][thumbnail][integration]")
{
    GIVEN("an 8x8 PNG and the built thumbnail worker")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.worker_path = MEROVINGIAN_TEST_THUMBNAIL_WORKER;
        config.timeout_seconds = 60U;

        WHEN("a 4x4 scale thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::scale;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("a real, smaller PNG of the requested dimensions is produced")
            {
                REQUIRE(result.ok);
                REQUIRE(result.status == 200U);
                REQUIRE(result.content_type == "image/png");
                REQUIRE(is_png(result.bytes));
                // The output must differ from the original bytes — proving a
                // genuine decode/resample/encode, not a pass-through.
                REQUIRE(result.bytes != sample_png());
                auto const [w, h] = png_dimensions(result.bytes);
                REQUIRE(w == 4U);
                REQUIRE(h == 4U);
                REQUIRE(result.width == 4U);
                REQUIRE(result.height == 4U);
            }
        }

        WHEN("a 4x4 crop thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::crop;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the crop result fills the requested box exactly")
            {
                REQUIRE(result.ok);
                auto const [w, h] = png_dimensions(result.bytes);
                REQUIRE(w == 4U);
                REQUIRE(h == 4U);
            }
        }

        WHEN("an unsupported content type is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/gif";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the worker is never spawned and an unsupported status is returned")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 415U);
            }
        }

        WHEN("garbage is supplied as PNG bytes")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = "this is not a png";
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the worker reports a decode failure rather than crashing the host")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 400U);
            }
        }
    }
}

#endif // MEROVINGIAN_TEST_THUMBNAIL_WORKER

SCENARIO("a failed worker surfaces how it died in the result reason", "[media][thumbnail][integration][diagnostics]")
{
    GIVEN("a thumbnailer configured with a worker path that cannot be executed")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        // No such file: execv fails in the child, which then _exit(127)s. This
        // exercises the failure path without depending on the image codecs.
        config.worker_path = "/nonexistent/merovingian-thumbnail-worker";
        config.timeout_seconds = 5U;

        WHEN("a thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            request.method = merovingian::media::ThumbnailMethod::scale;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("the request fails and the reason reports the worker's exit status")
            {
                REQUIRE_FALSE(result.ok);
                // The reason must describe the worker outcome (exit code/signal),
                // not just a bare timeout, so CI logs pinpoint the cause.
                REQUIRE(result.reason.find("worker") != std::string::npos);
                REQUIRE((result.reason.find("exited with code") != std::string::npos ||
                         result.reason.find("killed by signal") != std::string::npos ||
                         result.reason.find("still running") != std::string::npos));
            }
        }
    }
}

SCENARIO("thumbnail generation degrades safely when no worker is configured", "[media][thumbnail][integration]")
{
    GIVEN("a thumbnailer config with an empty worker path")
    {
        auto config = merovingian::media::ThumbnailerConfig{};

        WHEN("a thumbnail is requested")
        {
            auto request = merovingian::media::ThumbnailRequest{};
            request.source_bytes = sample_png();
            request.source_content_type = "image/png";
            request.width = 4U;
            request.height = 4U;
            auto const result = merovingian::media::generate_thumbnail(config, request);

            THEN("it reports the worker is unavailable instead of failing hard")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.status == 503U);
            }
        }
    }
}
