// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit coverage for the thumbnail wire protocol and request normalisation.
// These exercise pure functions only — no process is spawned here (that is the
// integration test's job).

#include "merovingian/media/thumbnailer.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("thumbnail request frames round-trip", "[media][thumbnail]")
{
    GIVEN("a worker request with binary payload")
    {
        auto request = merovingian::media::ThumbnailWorkerRequest{};
        request.format = merovingian::media::ThumbnailSourceFormat::jpeg;
        request.method = merovingian::media::ThumbnailMethod::crop;
        request.target_width = 320U;
        request.target_height = 240U;
        request.max_pixels = 4096000U;
        request.source_bytes = std::string{"\x00\x01\x02\xFF\x10", 5U};

        WHEN("the request is framed and parsed back")
        {
            auto const frame = merovingian::media::frame_thumbnail_request(request);
            auto const parsed = merovingian::media::parse_thumbnail_request(frame);

            THEN("every field is preserved exactly")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->format == merovingian::media::ThumbnailSourceFormat::jpeg);
                REQUIRE(parsed->method == merovingian::media::ThumbnailMethod::crop);
                REQUIRE(parsed->target_width == 320U);
                REQUIRE(parsed->target_height == 240U);
                REQUIRE(parsed->max_pixels == 4096000U);
                REQUIRE(parsed->source_bytes == request.source_bytes);
            }
        }
    }
}

SCENARIO("thumbnail response frames round-trip", "[media][thumbnail]")
{
    GIVEN("an ok worker response carrying PNG bytes")
    {
        auto response = merovingian::media::ThumbnailWorkerResponse{};
        response.status = merovingian::media::ThumbnailWorkerStatus::ok;
        response.width = 64U;
        response.height = 48U;
        response.png_bytes = std::string{"\x89PNG\r\n", 6U};

        WHEN("the response is framed and parsed back")
        {
            auto const frame = merovingian::media::frame_thumbnail_response(response);
            auto const parsed = merovingian::media::parse_thumbnail_response(frame);

            THEN("the status, dimensions, and bytes survive")
            {
                REQUIRE(parsed.has_value());
                REQUIRE(parsed->status == merovingian::media::ThumbnailWorkerStatus::ok);
                REQUIRE(parsed->width == 64U);
                REQUIRE(parsed->height == 48U);
                REQUIRE(parsed->png_bytes == response.png_bytes);
            }
        }
    }
}

SCENARIO("malformed frames are rejected", "[media][thumbnail]")
{
    GIVEN("a frame with the wrong magic")
    {
        WHEN("it is parsed as a request")
        {
            auto const parsed = merovingian::media::parse_thumbnail_request("XXXXnonsense");
            THEN("parsing fails")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }

    GIVEN("a request frame whose declared length does not match the payload")
    {
        auto request = merovingian::media::ThumbnailWorkerRequest{};
        request.format = merovingian::media::ThumbnailSourceFormat::png;
        request.source_bytes = "abcd";
        auto frame = merovingian::media::frame_thumbnail_request(request);

        WHEN("a trailing byte is appended")
        {
            frame.push_back('!');
            auto const parsed = merovingian::media::parse_thumbnail_request(frame);

            THEN("the length mismatch is detected")
            {
                REQUIRE_FALSE(parsed.has_value());
            }
        }
    }
}

SCENARIO("content type maps to a supported source format", "[media][thumbnail]")
{
    GIVEN("the supported and unsupported content types")
    {
        THEN("png and jpeg map; others do not")
        {
            REQUIRE(merovingian::media::map_content_type_to_source_format("image/png").has_value());
            REQUIRE(merovingian::media::map_content_type_to_source_format("image/jpeg").has_value());
            REQUIRE_FALSE(merovingian::media::map_content_type_to_source_format("image/gif").has_value());
            REQUIRE_FALSE(merovingian::media::map_content_type_to_source_format("text/plain").has_value());
        }
    }
}

SCENARIO("thumbnail dimensions are validated against policy", "[media][thumbnail]")
{
    GIVEN("a config capping dimensions at 512")
    {
        auto config = merovingian::media::ThumbnailerConfig{};
        config.max_target_dimension = 512U;

        WHEN("a valid box is requested")
        {
            auto const dims = merovingian::media::normalise_thumbnail_dimensions(config, 96U, 96U);
            THEN("it is accepted")
            {
                REQUIRE(dims.has_value());
                REQUIRE(dims->first == 96U);
                REQUIRE(dims->second == 96U);
            }
        }

        WHEN("a zero dimension is requested")
        {
            THEN("it is rejected")
            {
                REQUIRE_FALSE(merovingian::media::normalise_thumbnail_dimensions(config, 0U, 64U).has_value());
            }
        }

        WHEN("a dimension above the cap is requested")
        {
            THEN("it is rejected")
            {
                REQUIRE_FALSE(merovingian::media::normalise_thumbnail_dimensions(config, 1024U, 64U).has_value());
            }
        }
    }
}
