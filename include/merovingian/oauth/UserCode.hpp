// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::oauth
{

// The user code of the device authorization grant (RFC 8628 section 6.1; plan P11; ADR-0805): eight characters drawn
// uniformly from twenty consonants, with no vowel (no word can be spelt) and no digit (nothing to confuse with a
// letter). 20^8 is about 2^34.5 codes; the server lets an address try five wrong ones in ten minutes.
inline constexpr auto user_code_alphabet = std::string_view{"BCDFGHJKLMNPQRSTVWXZ"};
inline constexpr auto user_code_length = std::size_t{8U};
// The longest text read as a typed user code: the eight characters shown as `XXXX-XXXX`, with room for spaces and
// dashes a user adds. Anything longer is refused, never shortened.
inline constexpr auto max_typed_user_code_bytes = std::size_t{32U};

// A user code from `random_bytes` by rejection sampling: a byte below 240 (twelve times twenty) gives the character
// at its value modulo twenty, so every character is equally likely; a byte of 240 or more is skipped. nullopt when the
// bytes run out before eight characters were drawn (the caller draws again).
[[nodiscard]] auto user_code_from_bytes(std::span<std::uint8_t const> random_bytes) -> std::optional<std::string>;

// The user code a person typed, in the stored form (eight upper-case alphabet characters), or nullopt. RFC 8628
// section 6.1 asks the server to accept the code however the user types it, so this is the one reader in this module
// that normalises (ADR-0805): a lower-case letter is read as its capital, and a dash, space, dot or underscore is
// skipped. Every other byte (a digit, a vowel, any letter outside the alphabet, a control or non-ASCII byte) refuses
// the whole text, as does text over max_typed_user_code_bytes or with other than eight characters left.
[[nodiscard]] auto normalise_user_code(std::string_view typed) -> std::optional<std::string>;

// `code` as it is shown to the user: the first four characters, a dash, the last four (`XXXX-XXXX`). `code` must be a
// stored user code; anything else is returned unchanged.
[[nodiscard]] auto display_user_code(std::string_view code) -> std::string;

} // namespace merovingian::oauth
