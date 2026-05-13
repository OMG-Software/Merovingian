// SPDX-License-Identifier: GPL-3.0-or-later

#include "local_services.hpp"

#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{

[[nodiscard]] auto make_operation_result(bool ok, std::string value, std::string reason,
                                         std::uint16_t status) -> OperationResult
{
    auto const resolved_status =
        status == 0U ? static_cast<std::uint16_t>(ok ? 200U : 400U) : status;
    return {ok, resolved_status, std::move(value), std::move(reason)};
}

auto append_local_audit(LocalDatabase& database, observability::AuditCategory category,
                        std::string_view event_type, std::string_view actor,
                        std::string_view target, std::string_view reason) -> void
{
    database.audit_events.push_back(observability::make_audit_event(
        category, event_type, actor, target, reason, "local-vertical-slice"));
    (void)database::append_audit_event(database.persistent_store,
                                       {observability::audit_category_name(category),
                                        std::string{event_type}, std::string{actor},
                                        std::string{target}, std::string{reason}});
}

} // namespace merovingian::homeserver
