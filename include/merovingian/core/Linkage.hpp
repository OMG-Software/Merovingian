// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::core
{

// How a library reached the running process.
enum class Linkage : std::uint8_t
{
    static_linked, // compiled into this executable: changes only with a rebuild
    dynamic,       // a shared object the loader opened: an OS update can replace it under the binary
};

} // namespace merovingian::core
