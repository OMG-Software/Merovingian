// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/LiveKitParticipantGrant.hpp"
#include "merovingian/crypto/VerifiedHs256Token.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::crypto
{

// LiveKit's tokens are JWTs signed with HMAC-SHA256 under the API secret (ADR-0828). The MAC is libsodium's
// `crypto_auth_hmacsha256` and is not exposed: this file signs exactly two kinds of token, each built here from typed
// claims, and verifies one. There is no function that signs bytes a caller chose.

// The shortest API secret accepted. LiveKit refuses shorter secrets itself.
inline constexpr auto livekit_api_secret_min_bytes = std::size_t{32U};
// The longest API key and token accepted.
inline constexpr auto livekit_api_key_max_bytes = std::size_t{128U};
inline constexpr auto hs256_token_max_bytes = std::size_t{4096U};

// Whether `api_key` can be a LiveKit API key here: 1 to `livekit_api_key_max_bytes` of ASCII letters, digits, `_`, `-`
// and `.`. The key is a token's `iss`; this alphabet needs no JSON escaping.
[[nodiscard]] auto livekit_api_key_is_valid(std::string_view api_key) noexcept -> bool;

// Whether `value` is an MSC4195 identity or room name: 43 characters of the standard base64 alphabet, no padding.
[[nodiscard]] auto livekit_name_is_valid(std::string_view value) noexcept -> bool;

// The participant token for `grant`, signed with `api_secret`:
// `{"alg":"HS256","typ":"JWT"}` and the claims `exp`, `iss` (`api_key`), `nbf`, `sub` (the identity) and `video`
// (`room`, `roomJoin` true, `canSubscribe` true, `canPublish` and `canPublishData` from the grant). nullopt when the
// key, a name, the times (`expires` not after `not_before`, or negative) or the secret (shorter than
// `livekit_api_secret_min_bytes`) is not valid, or libsodium fails. Every character of its payload segment comes from
// the standard and URL-safe base64 alphabets alike (no `-` or `_`), which Element Call's decoder needs.
[[nodiscard]] auto sign_livekit_participant_token(std::string_view api_key, std::span<std::uint8_t const> api_secret,
                                                  LiveKitParticipantGrant const& grant) -> std::optional<std::string>;

// The service token for one call of LiveKit's room service: `video` holds `roomCreate` true and nothing else, `sub` and
// `room` are absent. For `CreateRoom` only. nullopt on the same refusals as above.
[[nodiscard]] auto sign_livekit_room_create_token(std::string_view api_key, std::span<std::uint8_t const> api_secret,
                                                  std::int64_t not_before, std::int64_t expires)
    -> std::optional<std::string>;

// Verifies that `token` is three unpadded URL-safe base64 segments whose third is the HMAC-SHA256 under `secret` of the
// first two joined by `.`, compared in constant time, and returns the decoded header and payload. The header's `alg`
// is never consulted: only HMAC-SHA256 is ever checked. nullopt for a token longer than `hs256_token_max_bytes`, a
// malformed segment, a short secret or a MAC that does not match.
[[nodiscard]] auto verify_hs256_token(std::string_view token, std::span<std::uint8_t const> secret)
    -> std::optional<VerifiedHs256Token>;

} // namespace merovingian::crypto
