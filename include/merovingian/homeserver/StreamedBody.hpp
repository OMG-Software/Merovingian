// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/StreamedBodyResult.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Returns exactly `length` bytes of the body from `offset`, or nullopt on any failure.
using StreamChunkSource = std::function<std::optional<std::string>(std::uint64_t offset, std::size_t length)>;
// Writes the whole chunk to the client, false when the client is gone or too slow.
using StreamChunkSink = std::function<bool(std::string_view chunk)>;

// ADR-0574: sends `total_bytes` bytes as chunks of at most `chunk_bytes`, reading one chunk and then writing it
// before reading the next, so at most one chunk is held. A source answer of the wrong length counts as a read
// failure. Stops at the first failure and reads and writes nothing more. `peak_chunk_bytes`, when given, is
// raised to the largest chunk held, for tests.
[[nodiscard]] auto write_streamed_body(std::uint64_t total_bytes, std::size_t chunk_bytes,
                                       StreamChunkSource const& source, StreamChunkSink const& sink,
                                       std::size_t* peak_chunk_bytes = nullptr) -> StreamedBodyResult;

} // namespace merovingian::homeserver
