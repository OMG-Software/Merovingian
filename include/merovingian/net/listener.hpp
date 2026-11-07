// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"
#include "merovingian/net/ListenerPlan.hpp" // split-shim
#include "merovingian/net/ListenerRole.hpp" // split-shim

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::net
{

class RuntimeListeners final
{
public:
    RuntimeListeners() = default;
    explicit RuntimeListeners(std::vector<ListenerPlan> plans);

    [[nodiscard]] auto plans() const noexcept -> std::vector<ListenerPlan> const&;
    [[nodiscard]] auto count() const noexcept -> std::size_t;
    [[nodiscard]] auto empty() const noexcept -> bool;

private:
    std::vector<ListenerPlan> m_plans{};
};

[[nodiscard]] auto make_runtime_listeners(config::Config const& config) -> RuntimeListeners;
[[nodiscard]] auto listener_role_name(ListenerRole role) noexcept -> char const*;

} // namespace merovingian::net
