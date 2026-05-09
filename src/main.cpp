// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/bootstrap/exit_code.hpp>
#include <merovingian/config/config.hpp>
#include <merovingian/config/config_parser.hpp>
#include <merovingian/core/file_metadata.hpp>
#include <merovingian/net/listener.hpp>
#include <merovingian/observability/logger.hpp>

#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace
{

constexpr auto version = std::string_view{"0.1.0"};

struct BootstrapConfigResult final
{
    merovingian::config::ConfigParseResult parsed{};
    merovingian::bootstrap::ExitCode failure_code{merovingian::bootstrap::ExitCode::success};
    std::string source{"defaults"};
};

[[nodiscard]] auto reject_config(
    merovingian::bootstrap::ExitCode code,
    std::string field,
    std::string message
) -> BootstrapConfigResult
{
    auto result = BootstrapConfigResult{};
    result.failure_code = code;
    result.parsed.findings.push_back({std::move(field), std::move(message)});
    return result;
}

[[nodiscard]] auto classify_config_findings(
    merovingian::config::ConfigParseResult parsed,
    std::string source
) -> BootstrapConfigResult
{
    if (parsed.findings.empty())
    {
        return {std::move(parsed), merovingian::bootstrap::ExitCode::success, std::move(source)};
    }

    auto has_parse_finding = false;
    for (auto const& finding : parsed.findings)
    {
        has_parse_finding = has_parse_finding || finding.field == "config" || finding.field == "arguments"
            || finding.field.starts_with("line ") || finding.message == "unknown configuration key"
            || finding.message == "duplicate configuration key" || finding.message == "expected boolean value"
            || finding.message == "expected unsigned integer value";
    }

    return {
        std::move(parsed),
        has_parse_finding ? merovingian::bootstrap::ExitCode::config_parse_error
                          : merovingian::bootstrap::ExitCode::config_validation_error,
        std::move(source),
    };
}

[[nodiscard]] auto validate_config_file_metadata(std::string const& path) -> BootstrapConfigResult
{
    auto const metadata_result = merovingian::core::read_posix_file_metadata(path);
    if (!metadata_result.metadata.has_value())
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_io_error,
            "config.path",
            "unable to inspect configuration file metadata: " + metadata_result.error
        );
    }

    if (metadata_result.metadata->kind == merovingian::core::FileKind::missing)
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_io_error,
            "config.path",
            "configuration file does not exist"
        );
    }

    if (!merovingian::core::is_secure_config_file(*metadata_result.metadata))
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_validation_error,
            "config.path",
            "configuration file must be a regular file without group/other write or execute permissions"
        );
    }

    return {};
}

[[nodiscard]] auto validate_existing_secret_file_metadata(std::string const& path) -> BootstrapConfigResult
{
    auto const metadata_result = merovingian::core::read_posix_file_metadata(path);
    if (!metadata_result.metadata.has_value())
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_io_error,
            "database.uri_file",
            "unable to inspect database URI file metadata: " + metadata_result.error
        );
    }

    if (metadata_result.metadata->kind == merovingian::core::FileKind::missing)
    {
        return {};
    }

    if (!merovingian::core::is_secure_secret_file(*metadata_result.metadata))
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_validation_error,
            "database.uri_file",
            "database URI file must be a regular owner-only non-executable secret file"
        );
    }

    return {};
}

[[nodiscard]] auto validate_existing_secret_files(
    merovingian::config::Config const& config
) -> BootstrapConfigResult
{
    return validate_existing_secret_file_metadata(config.database().uri_file);
}

[[nodiscard]] auto load_config_from_file(std::string const& path) -> BootstrapConfigResult
{
    auto const metadata_validation = validate_config_file_metadata(path);
    if (!metadata_validation.parsed.findings.empty())
    {
        return metadata_validation;
    }

    auto input = std::ifstream{path, std::ios::binary};
    if (!input.is_open())
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_io_error,
            "config.path",
            "unable to open configuration file"
        );
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
                return reject_config(
                    merovingian::bootstrap::ExitCode::config_parse_error,
                    "config",
                    "configuration file is too large"
                );
            }

            contents.append(chunk.data(), static_cast<std::size_t>(bytes_read));
        }
    }

    if (input.bad())
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_io_error,
            "config.path",
            "error while reading configuration file"
        );
    }

    auto result = classify_config_findings(merovingian::config::parse_key_value_config(contents), "file");
    if (!result.parsed.findings.empty())
    {
        return result;
    }

    auto const secret_validation = validate_existing_secret_files(result.parsed.config);
    if (!secret_validation.parsed.findings.empty())
    {
        return secret_validation;
    }

    return result;
}

[[nodiscard]] auto build_config(int argc, char const* const* argv) -> BootstrapConfigResult
{
    if (argc == 1)
    {
        auto const config = merovingian::config::Config{};
        return classify_config_findings({config, merovingian::config::validate(config)}, "defaults");
    }

    if (argc == 3 && std::string_view{argv[1]} == "--config")
    {
        return load_config_from_file(argv[2]);
    }

    return reject_config(
        merovingian::bootstrap::ExitCode::usage_error,
        "arguments",
        "usage: merovingian-server [--config <path>] [--help] [--version]"
    );
}

[[nodiscard]] auto is_help_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 2 && (std::string_view{argv[1]} == "--help" || std::string_view{argv[1]} == "-h");
}

[[nodiscard]] auto is_version_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 2 && std::string_view{argv[1]} == "--version";
}

auto print_help() -> void
{
    std::cout << "The Merovingian bootstrap server\n"
              << "\n"
              << "Usage:\n"
              << "  merovingian-server\n"
              << "  merovingian-server --config <path>\n"
              << "  merovingian-server --help\n"
              << "  merovingian-server --version\n"
              << "\n"
              << "Configuration is validated before startup continues.\n";
}

auto print_version() -> void
{
    std::cout << "merovingian-server " << version << '\n';
}

auto log_startup_summary(BootstrapConfigResult const& result) -> void
{
    auto const& config = result.parsed.config;
    auto const runtime_listeners = merovingian::net::make_runtime_listeners(config);

    LOG_INFO("Configuration validation passed");
    LOG_INFO("Configuration source: " + result.source);
    LOG_INFO("Server name: " + config.server().server_name);
    LOG_INFO("Public base URL: " + config.server().public_baseurl);
    LOG_INFO("Client listener: " + config.listeners().client.bind);
    LOG_INFO("Federation listener: " + config.listeners().federation.bind);
    LOG_INFO("Planned runtime listeners: " + std::to_string(runtime_listeners.count()));
    for (auto const& listener : runtime_listeners.plans())
    {
        LOG_INFO(
            "Runtime listener planned: " + std::string{merovingian::net::listener_role_name(listener.role)}
            + " " + listener.bind + " tls=" + std::string{listener.tls ? "true" : "false"}
        );
    }
    LOG_INFO("Registration enabled: " + std::string{config.security().registration.enabled ? "true" : "false"});
    LOG_INFO("Federation enabled: " + std::string{config.security().federation.enabled ? "true" : "false"});
    LOG_INFO("Media upload limit: " + config.security().media.max_upload_size);
}

} // namespace

auto main(int argc, char const* const* argv) -> int
{
    if (is_help_request(argc, argv))
    {
        print_help();
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
    }

    if (is_version_request(argc, argv))
    {
        print_version();
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
    }

    LOG_INFO("Starting The Merovingian bootstrap server");

    auto const result = build_config(argc, argv);
    if (!result.parsed.findings.empty())
    {
        for (auto const& finding : result.parsed.findings)
        {
            LOG_CRITICAL("Configuration rejected: " + finding.field + ": " + finding.message);
        }

        return merovingian::bootstrap::to_int(result.failure_code);
    }

    log_startup_summary(result);

    return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
}
