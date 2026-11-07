// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PostgresqlConnectionDeleter.hpp"

namespace merovingian::database
{

struct PostgresqlConnectionHandle final
{
    PostgresqlConnectionPtr connection{};
};

} // namespace merovingian::database
