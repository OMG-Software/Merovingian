// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ServerSignatureResult.hpp"
#include "merovingian/crypto/SigningKeyLookupResult.hpp"
#include "merovingian/crypto/SigningKeyRecord.hpp"
#include "merovingian/crypto/SigningKeyStore.hpp"
#include "merovingian/crypto/ed25519.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::crypto
{

[[nodiscard]] auto signing_key_record_is_usable(SigningKeyRecord const& key) noexcept -> bool;
[[nodiscard]] auto sign_for_server(SigningKeyStore& key_store, Ed25519Provider& provider, std::string_view server_name,
                                   std::string_view message) -> ServerSignatureResult;

} // namespace merovingian::crypto
