// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/sync/StreamToken.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::sync
{

// A sliding sync `pos` (MSC4186): a stream token and, when not 0, a page written after it as `.<decimal>`
// (ADR-0862). The page tells apart two responses at one stream position whose connection state differs: a response
// that delivers MSC4354 sticky events while no stream advanced carries the request's page plus one, so the next
// request can acknowledge it rather than read as a retry. The page says nothing about the streams; every stream
// comparison reads `token` alone. Classic `/sync` tokens never carry a page.
struct SlidingSyncPos final
{
    StreamToken token{};
    std::uint64_t page{0U};
};

// The text of `pos`: the stream token, then `.` and the page when the page is not 0.
[[nodiscard]] auto encode_sliding_sync_pos(SlidingSyncPos const& pos) -> std::string;

// Reads a `pos`: a stream token `decode_stream_token` accepts, optionally followed by `.` and 1 to 20 ASCII digits that
// fit 64 bits with no leading zero. Anything else, an explicit `.0` included, is nullopt: one position has one
// spelling.
[[nodiscard]] auto decode_sliding_sync_pos(std::string_view encoded) -> std::optional<SlidingSyncPos>;

// The stream token a pagination `from` / `to` names when it is a /sync `next_batch` or a sliding sync `pos` as the
// server sends it (`<pos>-<64 hex digits>`, ADR-0866). MSC4186: "A `pos` token can be used in `/messages` and
// `/relations` APIs, in the same way as a `next_batch` from `/v3/sync`". The binding is not checked: a pagination token
// only names where to read from, and every event read is still judged for the caller. nullopt for anything else.
[[nodiscard]] auto decode_sync_position_token(std::string_view text) -> std::optional<StreamToken>;

} // namespace merovingian::sync
