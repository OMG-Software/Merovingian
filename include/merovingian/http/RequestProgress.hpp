// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

struct RequestProgress final
{
    std::uint64_t bytes_received{0U};
    std::uint32_t elapsed_seconds{0U};
};

} // namespace merovingian::http
