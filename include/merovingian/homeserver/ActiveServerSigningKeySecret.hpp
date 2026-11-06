// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"

#include <string>

namespace merovingian::homeserver
{

// Decrypted material for one currently-active server signing key, returned by
// active_server_signing_key_secrets and consumed by reset_runtime_crypto_provider.
struct ActiveServerSigningKeySecret final
{
    std::string key_id{};
    core::SecretBuffer secret{};
};

} // namespace merovingian::homeserver
