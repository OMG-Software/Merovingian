// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/signable.hpp"

namespace merovingian::canonicaljson
{

auto make_signable_object_view(Value const& value) -> SerializeResult
{
    // Signing-scoped: canonical JSON MUST NOT contain floats in signed/hashed
    // data, so this fails closed on a Value tree containing a double rather
    // than serializing it (see serializer.hpp's serialize_canonical_strict).
    return serialize_canonical_strict(value);
}

} // namespace merovingian::canonicaljson
