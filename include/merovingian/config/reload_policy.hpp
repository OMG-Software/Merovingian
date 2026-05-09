// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace merovingian::config
{

enum class ReloadPolicy : std::uint8_t
{
    reloadable,
    restart_required,
};

[[nodiscard]] auto reload_policy_for_key(std::string_view key) noexcept -> ReloadPolicy;
[[nodiscard]] auto reload_policy_name(ReloadPolicy policy) noexcept -> char const*;

} // namespace merovingian::config
