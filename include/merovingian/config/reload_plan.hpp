// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/config/reload_policy.hpp"

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::config
{

struct ReloadChange final
{
    std::string key{};
    ReloadPolicy policy{ReloadPolicy::reloadable};
};

class ReloadPlan final
{
public:
    [[nodiscard]] auto changes() const noexcept -> std::vector<ReloadChange> const&;
    [[nodiscard]] auto has_changes() const noexcept -> bool;
    [[nodiscard]] auto has_restart_required_changes() const noexcept -> bool;
    [[nodiscard]] auto reloadable_change_count() const noexcept -> std::size_t;
    [[nodiscard]] auto restart_required_change_count() const noexcept -> std::size_t;

    auto add_change(ReloadChange change) -> void;

private:
    std::vector<ReloadChange> m_changes{};
};

[[nodiscard]] auto build_reload_plan(Config const& current, Config const& next) -> ReloadPlan;
[[nodiscard]] auto reload_plan_summary(ReloadPlan const& plan) -> std::string;

} // namespace merovingian::config
