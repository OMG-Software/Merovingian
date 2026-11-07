// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct MediaDeduplicationKey final
{
    std::string hash_algorithm{};
    std::string digest{};
    std::uint64_t byte_size{0U};
};

} // namespace merovingian::media
