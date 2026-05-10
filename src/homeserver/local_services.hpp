// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/homeserver/vertical_slice.hpp>
#include <merovingian/observability/observability.hpp>

#include <string>
#include <string_view>

namespace merovingian::homeserver
{

[[nodiscard]] auto make_operation_result(bool ok, std::string value, std::string reason = {}) -> OperationResult;

auto append_local_audit(
    LocalDatabase& database,
    observability::AuditCategory category,
    std::string_view event_type,
    std::string_view actor,
    std::string_view target,
    std::string_view reason
) -> void;

} // namespace merovingian::homeserver
