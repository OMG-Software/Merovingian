// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <memory>

struct pg_result;

namespace merovingian::database
{

// Frees a libpq result with PQclear.
struct PostgresqlResultDeleter final
{
    auto operator()(pg_result* result) const noexcept -> void;
};

using PostgresqlResultPtr = std::unique_ptr<pg_result, PostgresqlResultDeleter>;

} // namespace merovingian::database
