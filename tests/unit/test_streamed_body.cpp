// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// ADR-0574: a response body produced in chunks. The writer holds at most one chunk and stops at the first failure.

#include "merovingian/homeserver/StreamedBodyResult.hpp"
#include "merovingian/homeserver/StreamedBody.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using merovingian::homeserver::StreamedBodyResult;
using merovingian::homeserver::write_streamed_body;

[[nodiscard]] auto pattern_bytes(std::size_t size) -> std::string
{
    auto bytes = std::string(size, '\0');
    for (auto index = std::size_t{0U}; index < size; ++index)
    {
        bytes[index] = static_cast<char>((index * 31U + 7U) % 251U);
    }
    return bytes;
}

} // namespace

SCENARIO("A streamed body is written in bounded chunks", "[p15b][streamed-body][http]")
{
    GIVEN("a body of several chunks and a source that serves ranges of it")
    {
        auto constexpr chunk_bytes = std::size_t{1000U};
        auto const body = pattern_bytes(3500U);
        auto source_calls = std::size_t{0U};
        auto const source = [&body, &source_calls](std::uint64_t offset, std::size_t length) {
            ++source_calls;
            return std::optional<std::string>{body.substr(static_cast<std::size_t>(offset), length)};
        };

        WHEN("it is streamed to a sink that collects the chunks")
        {
            auto received = std::string{};
            auto largest_write = std::size_t{0U};
            auto peak = std::size_t{0U};
            auto const result = write_streamed_body(
                body.size(), chunk_bytes, source,
                [&received, &largest_write](std::string_view chunk) {
                    received.append(chunk);
                    largest_write = std::max(largest_write, chunk.size());
                    return true;
                },
                &peak);

            THEN("the bytes arrive identical and no chunk was larger than the chunk size")
            {
                REQUIRE(result == StreamedBodyResult::complete);
                REQUIRE(received == body);
                REQUIRE(source_calls == 4U);
                REQUIRE(largest_write == chunk_bytes);
                REQUIRE(peak == chunk_bytes);
            }
        }

        WHEN("the source fails on the second chunk")
        {
            auto written = std::size_t{0U};
            auto reads = std::size_t{0U};
            auto const result = write_streamed_body(
                body.size(), chunk_bytes,
                [&reads, &source](std::uint64_t offset, std::size_t length) {
                    ++reads;
                    return reads == 2U ? std::optional<std::string>{} : source(offset, length);
                },
                [&written](std::string_view chunk) {
                    written += chunk.size();
                    return true;
                });

            THEN("it reports a read failure and writes and reads nothing more")
            {
                REQUIRE(result == StreamedBodyResult::read_failed);
                REQUIRE(written == chunk_bytes);
                REQUIRE(reads == 2U);
            }
        }

        WHEN("the source answers with fewer bytes than asked")
        {
            auto const result = write_streamed_body(
                body.size(), chunk_bytes,
                [](std::uint64_t, std::size_t length) {
                    return std::optional<std::string>{std::string(length - 1U, 'x')};
                },
                [](std::string_view) {
                    return true;
                });

            THEN("it is a read failure, so the response is never padded or truncated silently")
            {
                REQUIRE(result == StreamedBodyResult::read_failed);
            }
        }

        WHEN("the client stops accepting bytes after the first chunk")
        {
            auto writes = std::size_t{0U};
            auto const result = write_streamed_body(body.size(), chunk_bytes, source, [&writes](std::string_view) {
                ++writes;
                return false;
            });

            THEN("it reports a write failure and does not read ahead")
            {
                REQUIRE(result == StreamedBodyResult::write_failed);
                REQUIRE(writes == 1U);
                REQUIRE(source_calls == 1U);
            }
        }
    }
}
