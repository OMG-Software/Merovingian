// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/SigningKeyRecord.hpp"

#include <string>

namespace merovingian::crypto
{

struct SigningKeyLookupResult final
{
    SigningKeyRecord key{};
    std::string error{};
};

} // namespace merovingian::crypto
