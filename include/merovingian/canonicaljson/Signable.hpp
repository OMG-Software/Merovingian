// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/SerializeResult.hpp"
#include "merovingian/canonicaljson/Value.hpp"

namespace merovingian::canonicaljson
{

[[nodiscard]] auto make_signable_object_view(Value const& value) -> SerializeResult;

} // namespace merovingian::canonicaljson
