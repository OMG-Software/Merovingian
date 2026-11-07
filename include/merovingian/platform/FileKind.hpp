// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::platform
{

enum class FileKind : std::uint8_t
{
    missing,
    regular,
    directory,
    symlink,
    other,
};

} // namespace merovingian::platform
