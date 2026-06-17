// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::crypto
{

// Fixed-size secret comparison (token hashes, signatures, HMACs). The caller
// must ensure both inputs have the same, public length; any length mismatch
// returns false immediately. For variable-length plaintext secrets use
// constant_time_equal_variable_length to avoid leaking the secret's size.
[[nodiscard]] auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool;

// Variable-length secret comparison. Both inputs are hashed with a domain-
// separated libsodium generichash into fixed-size digests; the digests are then
// compared in constant time. This avoids the timing side-channel that a
// plain length check would leak for secrets whose length is itself sensitive.
[[nodiscard]] auto constant_time_equal_variable_length(std::string_view left, std::string_view right) noexcept -> bool;

} // namespace merovingian::crypto
