// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/FileKind.hpp"
#include "merovingian/platform/PosixFileMode.hpp"

namespace merovingian::platform
{

struct FileMetadata final
{
    FileKind kind{FileKind::missing};
    PosixFileMode mode{};
};

} // namespace merovingian::platform
