// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::database
{

struct BoundValue final
{
    std::string value{};
    bool sensitive{false};
    // True when `value` is raw binary (the payload of a `BLOB` column, such as
    // media_blobs.bytes or server_signing_keys.secret_key) rather than text.
    // Every write to a `BLOB` column must set it. The PostgreSQL backend binds
    // such a parameter in libpq's binary format with an explicit length (see
    // postgresql_store.hpp), so an embedded NUL or invalid UTF-8 cannot
    // truncate or corrupt it; SQLite already binds every parameter by explicit
    // length, so it is unaffected and ignores the flag.
    bool binary{false};
};

} // namespace merovingian::database
