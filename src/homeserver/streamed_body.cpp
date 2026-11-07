// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/streamed_body.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace merovingian::homeserver
{

auto write_streamed_body(std::uint64_t total_bytes, std::size_t chunk_bytes, StreamChunkSource const& source,
                         StreamChunkSink const& sink, std::size_t* peak_chunk_bytes) -> StreamedBodyResult
{
    if (chunk_bytes == 0U)
    {
        return StreamedBodyResult::read_failed;
    }
    auto offset = std::uint64_t{0U};
    while (offset < total_bytes)
    {
        auto const length = static_cast<std::size_t>(
            std::min<std::uint64_t>(static_cast<std::uint64_t>(chunk_bytes), total_bytes - offset));
        auto chunk = source(offset, length);
        if (!chunk.has_value() || chunk->size() != length)
        {
            return StreamedBodyResult::read_failed;
        }
        if (peak_chunk_bytes != nullptr)
        {
            *peak_chunk_bytes = std::max(*peak_chunk_bytes, chunk->size());
        }
        if (!sink(*chunk))
        {
            return StreamedBodyResult::write_failed;
        }
        offset += length;
    }
    return StreamedBodyResult::complete;
}

} // namespace merovingian::homeserver
