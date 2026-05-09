// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>

namespace merovingian::crypto
{

struct Ed25519PublicKey final
{
    std::string bytes{};
};

struct Ed25519SecretKeyHandle final
{
    std::string key_id{};
};

struct Ed25519Signature final
{
    std::string bytes{};
};

struct SignatureResult final
{
    Ed25519Signature signature{};
    std::string error{};
};

struct VerificationResult final
{
    bool valid{false};
    std::string error{};
};

class Ed25519Provider
{
public:
    Ed25519Provider() = default;
    Ed25519Provider(Ed25519Provider const& other) = delete;
    auto operator=(Ed25519Provider const& other) -> Ed25519Provider& = delete;
    Ed25519Provider(Ed25519Provider&& other) noexcept = delete;
    auto operator=(Ed25519Provider&& other) noexcept -> Ed25519Provider& = delete;
    virtual ~Ed25519Provider() = default;

    [[nodiscard]] virtual auto sign(Ed25519SecretKeyHandle const& key, std::string_view message) -> SignatureResult = 0;
    [[nodiscard]] virtual auto verify(
        Ed25519PublicKey const& public_key,
        std::string_view message,
        Ed25519Signature const& signature
    ) -> VerificationResult = 0;
};

[[nodiscard]] auto ed25519_public_key_shape_is_valid(Ed25519PublicKey const& public_key) noexcept -> bool;
[[nodiscard]] auto ed25519_signature_shape_is_valid(Ed25519Signature const& signature) noexcept -> bool;
[[nodiscard]] auto ed25519_key_id_is_valid(std::string_view key_id) noexcept -> bool;

} // namespace merovingian::crypto
