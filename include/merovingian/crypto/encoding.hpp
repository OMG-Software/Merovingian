// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

// Hex-encode bytes into lowercase hex. Returns std::nullopt on libsodium failure.
[[nodiscard]] auto to_hex(std::span<unsigned char const> bytes) -> std::optional<std::string>;

// Encode bytes with URL-safe base64 (no padding), as used by Matrix identifiers.
// Returns std::nullopt on libsodium failure.
[[nodiscard]] auto base64_urlsafe_encode(std::string_view input) -> std::optional<std::string>;

// Decode URL-safe base64 (no padding) into bytes. Returns std::nullopt on invalid input
// or libsodium failure.
[[nodiscard]] auto base64_urlsafe_decode(std::string_view input) -> std::optional<std::string>;

// Encode bytes with standard base64 (with padding), as used by some legacy
// Matrix wire formats. Returns std::nullopt on libsodium failure.
[[nodiscard]] auto base64_original_encode(std::string_view input) -> std::optional<std::string>;

// Decode standard base64 (with padding) into bytes. Returns std::nullopt on invalid
// input or libsodium failure.
[[nodiscard]] auto base64_original_decode(std::string_view input) -> std::optional<std::string>;

} // namespace merovingian::crypto
