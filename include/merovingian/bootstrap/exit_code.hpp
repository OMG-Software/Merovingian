// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::bootstrap
{

enum class ExitCode : int
{
    success = 0,
    usage_error = 64,
    config_io_error = 66,
    config_parse_error = 78,
    config_validation_error = 79,
    runtime_start_error = 80,
    listener_error = 81,
};

[[nodiscard]] constexpr auto to_int(ExitCode code) noexcept -> int
{
    return static_cast<int>(code);
}

} // namespace merovingian::bootstrap
