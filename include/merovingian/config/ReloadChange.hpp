// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/ReloadPolicy.hpp"

#include <string>

namespace merovingian::config
{

struct ReloadChange final
{
    std::string key{};
    ReloadPolicy policy{ReloadPolicy::reloadable};
};

} // namespace merovingian::config
