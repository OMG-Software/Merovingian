// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

struct EncryptionSecurityConfig final
{
    bool default_for_new_rooms{true};
    bool require_for_direct_messages{true};
    bool require_for_private_rooms{true};
    bool allow_unencrypted_public_rooms{true};
    bool block_unencrypted_federated_private_rooms{true};
};

} // namespace merovingian::config
