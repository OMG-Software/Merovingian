// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/runtime_config.hpp"

#include <memory>
#include <mutex>
#include <utility>

namespace merovingian::config
{

// SHARED_PTR: reviewed — immutable Config snapshot; see runtime_config.hpp (#422).
RuntimeConfigSnapshot::RuntimeConfigSnapshot()
    : m_current{std::make_shared<Config const>()} // SHARED_PTR: reviewed (#422)
{
}

RuntimeConfigSnapshot::RuntimeConfigSnapshot(Config config)
    : m_current{std::make_shared<Config const>(std::move(config))} // SHARED_PTR: reviewed (#422)
{
}

auto RuntimeConfigSnapshot::current() const -> std::shared_ptr<Config const> // SHARED_PTR: reviewed (#422)
{
    auto lock = std::scoped_lock{m_mutex};
    return m_current;
}

auto RuntimeConfigSnapshot::plan_reload(Config const& next) const -> ReloadPlan
{
    auto const snapshot = current();
    return build_reload_plan(*snapshot, next);
}

auto RuntimeConfigSnapshot::apply_reload(Config next) -> RuntimeConfigApplyResult
{
    // Plan and swap under one lock so two concurrent reloads cannot
    // interleave their diff and their swap (#422).
    auto lock = std::scoped_lock{m_mutex};
    auto const plan = build_reload_plan(*m_current, next);
    if (!plan.has_changes())
    {
        return RuntimeConfigApplyResult::unchanged;
    }

    if (plan.has_restart_required_changes())
    {
        return RuntimeConfigApplyResult::restart_required;
    }

    m_current = std::make_shared<Config const>(std::move(next)); // SHARED_PTR: reviewed (#422)
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
