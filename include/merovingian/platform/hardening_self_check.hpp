// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::platform
{

enum class HardeningStatus : std::uint8_t
{
    enabled,
    disabled,
    unknown,
};

struct HardeningCheck final
{
    std::string name{};
    HardeningStatus status{HardeningStatus::unknown};
};

class HardeningSelfCheck final
{
public:
    HardeningSelfCheck() = default;
    explicit HardeningSelfCheck(std::vector<HardeningCheck> checks);

    [[nodiscard]] auto checks() const noexcept -> std::vector<HardeningCheck> const&;
    [[nodiscard]] auto count() const noexcept -> std::size_t;

private:
    std::vector<HardeningCheck> m_checks{};
};

[[nodiscard]] auto run_startup_hardening_self_check() -> HardeningSelfCheck;
[[nodiscard]] auto hardening_status_name(HardeningStatus status) noexcept -> char const*;

} // namespace merovingian::platform
