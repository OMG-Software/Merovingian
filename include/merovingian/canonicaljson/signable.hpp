// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/canonicaljson/serializer.hpp>
#include <merovingian/canonicaljson/value.hpp>

namespace merovingian::canonicaljson
{

[[nodiscard]] auto make_signable_object_view(Value const& value) -> SerializeResult;

} // namespace merovingian::canonicaljson
