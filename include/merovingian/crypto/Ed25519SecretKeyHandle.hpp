// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::crypto
{

struct Ed25519SecretKeyHandle final
{
    std::string key_id{};
};

} // namespace merovingian::crypto
