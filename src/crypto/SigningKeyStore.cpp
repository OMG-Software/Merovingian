// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/SigningKeyStore.hpp"

#include "merovingian/crypto/SigningKeyRecord.hpp"
#include "merovingian/crypto/signing_service.hpp"

#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::crypto
{

auto SigningKeyStore::active_keys_for_server(std::string_view server_name) -> std::vector<SigningKeyRecord>
{
    auto result = active_key_for_server(server_name);
    if (!result.error.empty() || !signing_key_record_is_usable(result.key))
    {
        return {};
    }
    return {std::move(result.key)};
}

} // namespace merovingian::crypto
