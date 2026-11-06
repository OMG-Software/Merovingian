// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/LocalMediaState.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct LocalMediaAdminResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string media_id{};
    LocalMediaState state{LocalMediaState::available};
    std::string reason{};
};

} // namespace merovingian::media
