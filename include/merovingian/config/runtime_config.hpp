// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/config/reload_plan.hpp"

#include <memory>
#include <mutex>

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
    RuntimeConfigSnapshot();
    explicit RuntimeConfigSnapshot(Config config);

    // Returns an immutable snapshot of the live config. Safe to call
    // concurrently with apply_reload (#422): the snapshot is swapped
    // atomically under m_mutex, so a reader never observes a torn Config.
    // Callers keep the returned pointer alive for as long as they read it.
    [[nodiscard]] auto current() const
        -> std::shared_ptr<Config const>; // SHARED_PTR: reviewed — immutable snapshot handed to callers, replaced whole
                                          // under m_mutex (#422)
    [[nodiscard]] auto plan_reload(Config const& next) const -> ReloadPlan;
    [[nodiscard]] auto apply_reload(Config next) -> RuntimeConfigApplyResult;

private:
    mutable std::mutex m_mutex{};
    std::shared_ptr<Config const> m_current{}; // SHARED_PTR: reviewed — immutable snapshot; replaced whole under
                                               // m_mutex so concurrent readers keep a consistent view (#422)
};

[[nodiscard]] auto runtime_config_apply_result_name(RuntimeConfigApplyResult result) noexcept -> char const*;

} // namespace merovingian::config
