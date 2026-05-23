// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/signing_service.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <string>
#include <vector>

namespace merovingian::crypto
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields) -> void
    {
        LOG_DEBUG(observability::diagnostic_log_summary("signing_service", event, std::move(fields)));
    }

} // namespace

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
        log_diagnostic("sign.rejected", {{"reason", "server name is empty", false}});
        return {{}, {}, {}, "server name is empty"};
    }

    auto key = key_store.active_key_for_server(server_name);
    if (!key.error.empty())
    {
        log_diagnostic("sign.rejected",
                       {{"server_name", std::string{server_name}, false}, {"reason", key.error, false}});
        return {{}, {}, {}, key.error};
    }
    if (!signing_key_record_is_usable(key.key))
    {
        log_diagnostic("sign.rejected",
                       {{"server_name", std::string{server_name}, false},
                        {"reason",      "active signing key is not usable", false}});
        return {{}, {}, {}, "active signing key is not usable"};
    }
    if (key.key.server_name != server_name)
    {
        log_diagnostic("sign.rejected",
                       {{"server_name", std::string{server_name}, false},
                        {"reason",      "active signing key server mismatch", false}});
        return {{}, {}, {}, "active signing key server mismatch"};
    }

    auto signature = provider.sign(Ed25519SecretKeyHandle{key.key.key_id}, message);
    if (!signature.error.empty())
    {
        log_diagnostic("sign.failed",
                       {{"server_name", key.key.server_name, false},
                        {"key_id",      key.key.key_id,       false},
                        {"reason",      signature.error,       false}});
        return {key.key.server_name, key.key.key_id, {}, signature.error};
    }
    if (!ed25519_signature_shape_is_valid(signature.signature))
    {
        log_diagnostic("sign.failed",
                       {{"server_name", key.key.server_name,                                     false},
                        {"key_id",      key.key.key_id,                                           false},
                        {"reason",      "provider returned invalid Ed25519 signature shape", false}});
        return {key.key.server_name, key.key.key_id, {}, "provider returned invalid Ed25519 signature shape"};
    }

    log_diagnostic("sign.accepted",
                   {{"server_name", key.key.server_name, false}, {"key_id", key.key.key_id, false}});
    return {key.key.server_name, key.key.key_id, signature.signature, {}};
}

} // namespace merovingian::crypto
