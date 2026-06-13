// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/runtime_config.hpp"

#include <utility>

namespace merovingian::config
{

RuntimeConfigSnapshot::RuntimeConfigSnapshot(Config config)
    : m_current{std::move(config)}
{
}

auto RuntimeConfigSnapshot::current() const noexcept -> Config const&
{
    return m_current;
}

auto RuntimeConfigSnapshot::plan_reload(Config const& next) const -> ReloadPlan
{
    return build_reload_plan(m_current, next);
}

auto RuntimeConfigSnapshot::apply_reload(Config next) -> RuntimeConfigApplyResult
{
    auto const plan = plan_reload(next);
    if (!plan.has_changes())
    {
        return RuntimeConfigApplyResult::unchanged;
    }

    if (plan.has_restart_required_changes())
    {
        return RuntimeConfigApplyResult::restart_required;
    }

    m_current = std::move(next);
    return RuntimeConfigApplyResult::applied;
}

auto runtime_config_apply_result_name(RuntimeConfigApplyResult result) noexcept -> char const*
{
    switch (result)
    {
    case RuntimeConfigApplyResult::applied:
        return "applied";
    case RuntimeConfigApplyResult::unchanged:
        return "unchanged";
    case RuntimeConfigApplyResult::restart_required:
        return "restart_required";
    }

    return "restart_required";
}

} // namespace merovingian::config
