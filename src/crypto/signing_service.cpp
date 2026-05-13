// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/signing_service.hpp"

namespace merovingian::crypto
{

auto signing_key_record_is_usable(SigningKeyRecord const& key) noexcept -> bool
{
    return key.active && !key.server_name.empty() && ed25519_key_id_is_valid(key.key_id) &&
           ed25519_public_key_shape_is_valid(key.public_key);
}

auto sign_for_server(SigningKeyStore& key_store, Ed25519Provider& provider, std::string_view server_name,
                     std::string_view message) -> ServerSignatureResult
{
    if (server_name.empty())
    {
        return {{}, {}, {}, "server name is empty"};
    }

    auto key = key_store.active_key_for_server(server_name);
    if (!key.error.empty())
    {
        return {{}, {}, {}, key.error};
    }
    if (!signing_key_record_is_usable(key.key))
    {
        return {{}, {}, {}, "active signing key is not usable"};
    }
    if (key.key.server_name != server_name)
    {
        return {{}, {}, {}, "active signing key server mismatch"};
    }

    auto signature = provider.sign(Ed25519SecretKeyHandle{key.key.key_id}, message);
    if (!signature.error.empty())
    {
        return {key.key.server_name, key.key.key_id, {}, signature.error};
    }
    if (!ed25519_signature_shape_is_valid(signature.signature))
    {
        return {key.key.server_name, key.key.key_id, {}, "provider returned invalid Ed25519 signature shape"};
    }

    return {key.key.server_name, key.key.key_id, signature.signature, {}};
}

} // namespace merovingian::crypto
