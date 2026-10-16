// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/observability/logger.hpp"

#include <string>
#include <string_view>

namespace
{
auto emit_macro_messages() -> void
{
    LOG_DEBUG("macro debug");
    LOG_INFO("macro info");
}
} // namespace

auto main(int argc, char** argv) -> int
{
    if (argc != 3)
    {
        return 2;
    }
    using merovingian::observability::LogLevel;
    auto const mode = std::string_view{argv[2]};
    auto& logger = merovingian::observability::SingleLog::instance();
    logger.set_console_log_level(LogLevel::trace);
    logger.set_file_log_level(LogLevel::trace);
    if (!logger.set_log_file_path(std::string{argv[1]}))
    {
        return 3;
    }

    if (mode == "explicit")
    {
        logger.set_default_log_level(LogLevel::trace);
        logger.set_module_log_level("fixture", LogLevel::info);
        logger.set_module_log_level("emit_macro_messages", LogLevel::info);
    }
    else if (mode == "off")
    {
        logger.set_default_log_level(LogLevel::off);
        logger.set_module_log_level("fixture", LogLevel::off);
        logger.set_module_log_level("enabled", LogLevel::warning);
        logger.warning("enabled", "enabled warning");
    }
    else if (mode == "override")
    {
        logger.set_default_log_level(LogLevel::info);
        logger.set_module_log_level("fixture", LogLevel::debug);
        logger.set_module_log_level("emit_macro_messages", LogLevel::debug);
    }
    else if (mode == "sink-floor")
    {
        logger.set_default_log_level(LogLevel::trace);
        logger.set_console_log_level(LogLevel::info);
        logger.set_file_log_level(LogLevel::warning);
    }
    else if (mode != "defaults")
    {
        return 2;
    }

    // The process destructor drains both queues before the parent checks output.
    logger.trace("fixture", "direct trace");
    logger.debug("fixture", "direct debug");
    logger.info("fixture", "direct info");
    logger.notice("fixture", "direct notice");
    logger.warning("fixture", "direct warning");
    logger.error("fixture", "direct error");
    logger.critical("fixture", "direct critical");
    merovingian::observability::log_diagnostic("fixture", "diagnostic_debug");
    emit_macro_messages();
    return 0;
}
