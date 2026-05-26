// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/runtime.hpp"

namespace merovingian::homeserver
{

[[nodiscard]] auto run_local_smoke_flow(config::Config const& config) -> OperationResult;

} // namespace merovingian::homeserver
