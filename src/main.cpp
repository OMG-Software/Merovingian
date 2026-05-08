// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/observability/logger.hpp>

#include <string>

auto main() -> int
{
    LOG_INFO("Starting The Merovingian bootstrap server");

    auto const config = merovingian::config::Config{};
    auto const findings = merovingian::config::validate(config);
    if (!findings.empty())
    {
        for (auto const& finding : findings)
        {
            LOG_CRITICAL("Configuration rejected: " + finding.field + ": " + finding.message);
        }

        return 1;
    }

    LOG_INFO("Configuration validation passed");

    return 0;
}
