// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/PostgresqlResultDeleter.hpp"

#include <libpq-fe.h>

namespace merovingian::database
{

auto PostgresqlResultDeleter::operator()(pg_result* result) const noexcept -> void
{
    PQclear(result);
}

} // namespace merovingian::database
