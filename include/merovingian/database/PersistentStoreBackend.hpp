// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

enum class PersistentStoreBackend
{
    memory,
    postgresql,
    sqlite,
};

} // namespace merovingian::database
