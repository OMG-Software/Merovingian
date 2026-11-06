// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::config
{

// At-rest protection for high-value server secrets. The master key file
// contains raw secret material that is hashed with domain separation to
// derive the key used to encrypt the Ed25519 signing secret before it is
// written to the database. When empty, fresh signing keys cannot be created
// (legacy plaintext keys may still be loaded for migration).
struct SecretsSecurityConfig final
{
    std::string master_key_file{};
};

} // namespace merovingian::config
