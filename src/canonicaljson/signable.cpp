// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/signable.hpp"

namespace merovingian::canonicaljson
{

auto make_signable_object_view(Value const& value) -> SerializeResult
{
    return serialize_canonical(value);
}

} // namespace merovingian::canonicaljson
