// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/AdminQuarantineAction.hpp"

#include <string>

namespace merovingian::media
{

struct AdminQuarantineRequest final
{
    AdminQuarantineAction action{AdminQuarantineAction::quarantine};
    std::string admin_user_id{};
    std::string media_id{};
    std::string reason{};
};

} // namespace merovingian::media
