// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/homeserver/vertical_slice.hpp>

#include "local_services.hpp"

namespace merovingian::homeserver
{

auto run_local_vertical_slice(config::Config const& config) -> OperationResult
{
    auto started = start_runtime(config);
    if (!started.started)
    {
        return make_operation_result(false, {}, started.reason);
    }

    return make_operation_result(true, admin_health_summary(started.runtime));
}

} // namespace merovingian::homeserver
