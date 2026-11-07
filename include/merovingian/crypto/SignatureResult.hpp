// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/Ed25519Signature.hpp"

#include <string>

namespace merovingian::crypto
{

struct SignatureResult final
{
    Ed25519Signature signature{};
    std::string error{};
};

} // namespace merovingian::crypto
