// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/config/config_parser.hpp>
#include <merovingian/observability/logger.hpp>

#include <fstream>
#include <string>
#include <string_view>

namespace
{

[[nodiscard]] auto reject_config_file(std::string field, std::string message)
    -> merovingian::config::ConfigParseResult
{
    auto result = merovingian::config::ConfigParseResult{};
    result.findings.push_back({std::move(field), std::move(message)});
    return result;
}

[[nodiscard]] auto load_config_from_file(std::string const& path) -> merovingian::config::ConfigParseResult
{
    auto input = std::ifstream{path, std::ios::binary};
    if (!input.is_open())
    {
        return reject_config_file("config.path", "unable to open configuration file");
    }

    auto contents = std::string{};
    contents.reserve(4096U);

    auto chunk = std::string(4096U, '\0');
    while (input)
    {
        input.read(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        auto const bytes_read = input.gcount();
        if (bytes_read > 0)
        {
            if (contents.size() + static_cast<std::size_t>(bytes_read) > merovingian::config::max_config_bytes)
            {
                return reject_config_file("config", "configuration file is too large");
            }

            contents.append(chunk.data(), static_cast<std::size_t>(bytes_read));
        }
    }

    if (input.bad())
    {
        return reject_config_file("config.path", "error while reading configuration file");
    }

    return merovingian::config::parse_key_value_config(contents);
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

    return reject_config_file("arguments", "usage: merovingian-server [--config <path>]");
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
