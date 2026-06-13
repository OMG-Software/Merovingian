// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/ed25519.hpp"

#include <algorithm>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto is_printable_without_space(char value) noexcept -> bool
    {
        auto const byte = static_cast<unsigned char>(value);
        return byte > 0x20U && byte < 0x7FU;
    }

} // namespace

auto ed25519_public_key_shape_is_valid(Ed25519PublicKey const& public_key) noexcept -> bool
{
    return public_key.bytes.size() == 32U;
}

auto ed25519_signature_shape_is_valid(Ed25519Signature const& signature) noexcept -> bool
{
    return signature.bytes.size() == 64U;
}

auto ed25519_key_id_is_valid(std::string_view key_id) noexcept -> bool
{
    auto constexpr prefix = std::string_view{"ed25519:"};
    return key_id.size() > prefix.size() && key_id.size() <= 255U && key_id.starts_with(prefix) &&
           std::ranges::all_of(key_id.substr(prefix.size()), is_printable_without_space);
}

} // namespace merovingian::crypto
