// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::platform
{

struct FilesystemRestrictionPlan final
{
    std::vector<std::string> read_only_paths{};
    std::vector<std::string> writable_paths{};
    bool deny_home{true};
    bool deny_proc_write{true};
    bool private_tmp{true};
};

} // namespace merovingian::platform
