// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace merovingian::crypto
{

inline constexpr auto hmac_sha1_bytes = std::size_t{20U};

// HMAC-SHA1 (RFC 2104) of `message` under `key`, by OpenSSL's `HMAC`. It exists for one reason: the coturn REST API
// (`use-auth-secret`) defines a TURN password as the base64 of this MAC, and libsodium has no SHA-1 (ADR-0480).
// It is not a general-purpose primitive: nothing else may use SHA-1 for a new purpose. nullopt for an empty key (no
// secret is no credential) or if OpenSSL fails. The result is a MAC, not a secret to compare: a caller that checks
// one against a presented value uses constant_time_equal.
[[nodiscard]] auto hmac_sha1(std::span<std::uint8_t const> key, std::span<std::uint8_t const> message)
    -> std::optional<std::array<std::uint8_t, hmac_sha1_bytes>>;

} // namespace merovingian::crypto
