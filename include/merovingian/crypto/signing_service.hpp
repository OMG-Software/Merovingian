// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/crypto/ed25519.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::crypto
{

struct SigningKeyRecord final
{
    std::string server_name{};
    std::string key_id{};
    Ed25519PublicKey public_key{};
    bool active{false};
};

struct SigningKeyLookupResult final
{
    SigningKeyRecord key{};
    std::string error{};
};

class SigningKeyStore
{
public:
    SigningKeyStore() = default;
    SigningKeyStore(SigningKeyStore const& other) = delete;
    auto operator=(SigningKeyStore const& other) -> SigningKeyStore& = delete;
    SigningKeyStore(SigningKeyStore&& other) noexcept = delete;
    auto operator=(SigningKeyStore&& other) noexcept -> SigningKeyStore& = delete;
    virtual ~SigningKeyStore() = default;

    [[nodiscard]] virtual auto active_key_for_server(std::string_view server_name) -> SigningKeyLookupResult = 0;
};

struct ServerSignatureResult final
{
    std::string server_name{};
    std::string key_id{};
    Ed25519Signature signature{};
    std::string error{};
};

[[nodiscard]] auto signing_key_record_is_usable(SigningKeyRecord const& key) noexcept -> bool;
[[nodiscard]] auto sign_for_server(
    SigningKeyStore& key_store,
    Ed25519Provider& provider,
    std::string_view server_name,
    std::string_view message
) -> ServerSignatureResult;

} // namespace merovingian::crypto
