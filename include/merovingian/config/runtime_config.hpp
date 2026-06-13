// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/config/reload_plan.hpp"

namespace merovingian::config
{

enum class RuntimeConfigApplyResult : unsigned char
{
    applied,
    unchanged,
    restart_required,
};

class RuntimeConfigSnapshot final
{
public:
    RuntimeConfigSnapshot() = default;
    explicit RuntimeConfigSnapshot(Config config);

    [[nodiscard]] auto current() const noexcept -> Config const&;
    [[nodiscard]] auto plan_reload(Config const& next) const -> ReloadPlan;
    [[nodiscard]] auto apply_reload(Config next) -> RuntimeConfigApplyResult;

private:
    Config m_current{};
};

[[nodiscard]] auto runtime_config_apply_result_name(RuntimeConfigApplyResult result) noexcept -> char const*;

} // namespace merovingian::config
