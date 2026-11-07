// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::federation
{

enum class EduType : std::uint8_t
{
    unknown,
    typing,
    receipt,
    presence,
    direct_to_device,
    device_list_update,
    signing_key_update,
};

} // namespace merovingian::federation
