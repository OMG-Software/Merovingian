// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// The `next_batch` token of `GET /mutual_rooms`: the offset, a dot, and a keyed hash over the caller, the target user
// and the offset. The token is opaque to the client and tamper-evident, and carries the offset so that checking one
// costs a single hash (a token that did not would have to be searched for). `nullopt` when `key` is empty.
[[nodiscard]] auto encode_mutual_rooms_token(std::string_view caller, std::string_view target_user, std::size_t offset,
                                             std::span<std::uint8_t const> key) -> std::optional<std::string>;

// The offset `token` was issued for to `caller` about `target_user`, or `nullopt` for a token that is malformed, was
// issued for another pair, or was altered. One hash and one constant-time comparison, whatever the token.
[[nodiscard]] auto decode_mutual_rooms_token(std::string_view caller, std::string_view target_user,
                                             std::string_view token, std::span<std::uint8_t const> key)
    -> std::optional<std::size_t>;

} // namespace merovingian::homeserver
