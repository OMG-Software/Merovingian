// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::crypto
{

// Compute a libsodium generichash over the supplied pieces and return the digest
// as lowercase hex. Returns std::nullopt on libsodium failure. The optional key
// argument enables domain-separated hashes; pass an empty span for an unkeyed hash.
[[nodiscard]] auto generic_hash(std::span<std::string_view const> pieces, std::span<std::uint8_t const> key = {})
    -> std::optional<std::string>;

// Compute a libsodium generichash over the supplied pieces and return the raw
// digest bytes. Returns std::nullopt on libsodium failure. The optional key
// argument enables domain-separated hashes; pass an empty span for an unkeyed hash.
[[nodiscard]] auto generic_hash_bytes(std::span<std::string_view const> pieces, std::span<std::uint8_t const> key = {})
    -> std::optional<std::vector<std::uint8_t>>;

// Compute a single libsodium generichash over one contiguous input and return the
// digest as lowercase hex. Returns std::nullopt on libsodium failure.
[[nodiscard]] auto hash_bytes_to_hex(std::string_view input) -> std::optional<std::string>;

} // namespace merovingian::crypto
