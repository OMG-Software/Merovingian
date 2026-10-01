// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/receipt_visibility.hpp"

namespace merovingian::sync
{

auto receipt_visible_to(std::string_view receipt_type, std::string_view receipt_owner,
                        std::string_view viewer) noexcept -> bool
{
    if (receipt_type == "m.read")
    {
        return true;
    }
    if (receipt_type == "m.read.private")
    {
        return !viewer.empty() && receipt_owner == viewer;
    }
    return false;
}

} // namespace merovingian::sync
