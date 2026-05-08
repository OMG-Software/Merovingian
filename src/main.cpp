// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/config/config_parser.hpp>
#include <merovingian/observability/logger.hpp>

#include <fstream>
#include <sstream>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto load_config_from_file(std::string const& path) -> merovingian::config::ConfigParseResult
{
    auto input = std::ifstream{path};
    if (!input.is_open())
    {
        auto result = merovingian::config::ConfigParseResult{};
        result.findings.push_back({"config.path", "unable to open configuration file"});
        return result;
    }

    auto buffer = std::ostringstream{};
    buffer << input.rdbuf();
    return merovingian::config::parse_key_value_config(buffer.str());
}

[[nodiscard]] auto build_config(int argc, char const* const* argv) -> merovingian::config::ConfigParseResult
{
    if (argc == 1)
    {
        auto const config = merovingian::config::Config{};
        return {config, merovingian::config::validate(config)};
    }

    if (argc == 3 && std::string_view{argv[1]} == "--config")
    {
        return load_config_from_file(argv[2]);
    }

    auto result = merovingian::config::ConfigParseResult{};
    result.findings.push_back({"arguments", "usage: merovingian-server [--config <path>]"});
    return result;
}

} // namespace

auto main(int argc, char const* const* argv) -> int
{
    LOG_INFO("Starting The Merovingian bootstrap server");

    auto const parsed = build_config(argc, argv);
    if (!parsed.findings.empty())
    {
        for (auto const& finding : parsed.findings)
        {
            LOG_CRITICAL("Configuration rejected: " + finding.field + ": " + finding.message);
        }

        return 1;
    }

    LOG_INFO("Configuration validation passed");

    return 0;
}
