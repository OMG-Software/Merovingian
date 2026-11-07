// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::platform
{

struct PosixFileMode final
{
    bool owner_read{false};
    bool owner_write{false};
    bool owner_execute{false};
    bool group_read{false};
    bool group_write{false};
    bool group_execute{false};
    bool other_read{false};
    bool other_write{false};
    bool other_execute{false};
};

} // namespace merovingian::platform
