// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/bootstrap/exit_code.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"
#include "merovingian/config/reload_policy.hpp"
#include "merovingian/database/runtime_database.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/media/runtime_media.hpp"
#include "merovingian/net/listener.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/platform/file_metadata.hpp"
#include "merovingian/platform/hardening_self_check.hpp"

#include <cerrno>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <poll.h>

namespace
{

constexpr auto version = std::string_view{"0.5.34"};

struct BootstrapConfigResult final
{
    merovingian::config::ConfigParseResult parsed{};
    merovingian::bootstrap::ExitCode failure_code{merovingian::bootstrap::ExitCode::success};
    std::string source{"defaults"};
};

[[nodiscard]] auto reject_config(merovingian::bootstrap::ExitCode code, std::string field, std::string message)
    -> BootstrapConfigResult
{
    auto result = BootstrapConfigResult{};
    result.failure_code = code;
    result.parsed.findings.push_back({std::move(field), std::move(message)});
    return result;
}

[[nodiscard]] auto classify_config_findings(merovingian::config::ConfigParseResult parsed, std::string source)
    -> BootstrapConfigResult
{
    if (parsed.findings.empty())
    {
        return {std::move(parsed), merovingian::bootstrap::ExitCode::success, std::move(source)};
    }

    auto has_parse_finding = false;
    for (auto const& finding : parsed.findings)
    {
        has_parse_finding = has_parse_finding || finding.field == "config" || finding.field == "arguments" ||
                            finding.field.starts_with("line ") || finding.message == "unknown configuration key" ||
                            finding.message == "duplicate configuration key" ||
                            finding.message == "expected boolean value" ||
                            finding.message == "expected unsigned integer value" ||
                            finding.message == "expected database role runtime or migration";
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
    auto const metadata_result = merovingian::platform::read_posix_file_metadata(path);
    if (!metadata_result.metadata.has_value())
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, "config.path",
                             "unable to inspect configuration file metadata: " + metadata_result.error);
    }

    if (metadata_result.metadata->kind == merovingian::platform::FileKind::missing)
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, "config.path",
                             "configuration file does not exist");
    }

    if (!merovingian::platform::is_secure_config_file(*metadata_result.metadata))
    {
        return reject_config(
            merovingian::bootstrap::ExitCode::config_validation_error, "config.path",
            "configuration file must be a regular file without group/other write or execute permissions");
    }

    return {};
}

[[nodiscard]] auto validate_existing_secret_file_metadata(std::string const& path, std::string const& field,
                                                          bool allow_missing) -> BootstrapConfigResult
{
    auto const metadata_result = merovingian::platform::read_posix_file_metadata(path);
    if (!metadata_result.metadata.has_value())
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, field,
                             "unable to inspect secret file metadata: " + metadata_result.error);
    }

    if (metadata_result.metadata->kind == merovingian::platform::FileKind::missing)
    {
        if (allow_missing)
        {
            return {};
        }
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, field, "secret file does not exist");
    }

    if (!merovingian::platform::is_secure_secret_file(*metadata_result.metadata))
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_validation_error, field,
                             "secret file must be a regular owner-only non-executable file");
    }

    return {};
}

[[nodiscard]] auto validate_existing_certificate_file_metadata(std::string const& path, std::string const& field)
    -> BootstrapConfigResult
{
    auto const metadata_result = merovingian::platform::read_posix_file_metadata(path);
    if (!metadata_result.metadata.has_value())
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, field,
                             "unable to inspect TLS certificate file metadata: " + metadata_result.error);
    }

    if (metadata_result.metadata->kind == merovingian::platform::FileKind::missing)
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, field,
                             "TLS certificate file does not exist");
    }

    if (!merovingian::platform::is_secure_config_file(*metadata_result.metadata))
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_validation_error, field,
                             "TLS certificate file must be a regular non-executable file without group/other write");
    }

    return {};
}

[[nodiscard]] auto validate_existing_listener_tls_files(merovingian::config::ListenerConfig const& listener,
                                                        std::string const& prefix) -> BootstrapConfigResult
{
    if (!listener.tls)
    {
        return {};
    }

    auto certificate_validation =
        validate_existing_certificate_file_metadata(listener.tls_certificate_file, prefix + ".tls_certificate_file");
    if (!certificate_validation.parsed.findings.empty())
    {
        return certificate_validation;
    }

    return validate_existing_secret_file_metadata(listener.tls_private_key_file, prefix + ".tls_private_key_file",
                                                  false);
}

[[nodiscard]] auto validate_existing_secret_files(merovingian::config::Config const& config) -> BootstrapConfigResult
{
    auto database_validation =
        validate_existing_secret_file_metadata(config.database().uri_file, "database.uri_file", true);
    if (!database_validation.parsed.findings.empty())
    {
        return database_validation;
    }

    auto client_tls_validation = validate_existing_listener_tls_files(config.listeners().client, "listeners.client");
    if (!client_tls_validation.parsed.findings.empty())
    {
        return client_tls_validation;
    }

    auto federation_tls_validation =
        validate_existing_listener_tls_files(config.listeners().federation, "listeners.federation");
    if (!federation_tls_validation.parsed.findings.empty())
    {
        return federation_tls_validation;
    }

    if (!config.security().registration.token_file.empty())
    {
        auto const token_required =
            config.security().registration.enabled && config.security().registration.require_token;
        return validate_existing_secret_file_metadata(config.security().registration.token_file,
                                                      "security.registration.token_file", !token_required);
    }

    return {};
}

[[nodiscard]] auto load_config_from_file(std::string const& path) -> BootstrapConfigResult
{
    auto metadata_validation = validate_config_file_metadata(path);
    if (!metadata_validation.parsed.findings.empty())
    {
        return metadata_validation;
    }

    auto input = std::ifstream{path, std::ios::binary};
    if (!input.is_open())
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, "config.path",
                             "unable to open configuration file");
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
                return reject_config(merovingian::bootstrap::ExitCode::config_parse_error, "config",
                                     "configuration file is too large");
            }

            contents.append(chunk.data(), static_cast<std::size_t>(bytes_read));
        }
    }

    if (input.bad())
    {
        return reject_config(merovingian::bootstrap::ExitCode::config_io_error, "config.path",
                             "error while reading configuration file");
    }

    auto result = classify_config_findings(merovingian::config::parse_key_value_config(contents), "file");
    if (!result.parsed.findings.empty())
    {
        return result;
    }

    auto secret_validation = validate_existing_secret_files(result.parsed.config);
    if (!secret_validation.parsed.findings.empty())
    {
        return secret_validation;
    }

    return result;
}

struct ParsedArgs final
{
    bool dry_run{false};
    bool debug_logging{false};
    std::optional<std::string> log_file{};
    std::optional<std::string> bootstrap_admin_localpart{};
    std::optional<std::string> bootstrap_admin_password_file{};
    std::optional<std::string> error{};
    std::vector<std::string_view> positional{};
};

[[nodiscard]] auto parse_args(int argc, char const* const* argv) -> ParsedArgs
{
    auto parsed = ParsedArgs{};
    parsed.positional.reserve(static_cast<std::size_t>(argc));
    for (auto index = 1; index < argc; ++index)
    {
        auto const argument = std::string_view{argv[index]};
        if (argument == "--dry-run")
        {
            parsed.dry_run = true;
            continue;
        }
        if (argument == "--debug")
        {
            parsed.debug_logging = true;
            continue;
        }
        if (argument == "--log-file")
        {
            if (parsed.log_file.has_value())
            {
                parsed.error = "--log-file specified more than once";
                return parsed;
            }
            if (index + 1 >= argc)
            {
                parsed.error = "--log-file requires a path";
                return parsed;
            }
            parsed.log_file = argv[++index];
            continue;
        }
        if (argument == "--bootstrap-admin")
        {
            if (parsed.bootstrap_admin_localpart.has_value())
            {
                parsed.error = "--bootstrap-admin specified more than once";
                return parsed;
            }
            if (index + 1 >= argc)
            {
                parsed.error = "--bootstrap-admin requires a localpart";
                return parsed;
            }
            parsed.bootstrap_admin_localpart = argv[++index];
            continue;
        }
        if (argument == "--bootstrap-admin-password-file")
        {
            if (parsed.bootstrap_admin_password_file.has_value())
            {
                parsed.error = "--bootstrap-admin-password-file specified more than once";
                return parsed;
            }
            if (index + 1 >= argc)
            {
                parsed.error = "--bootstrap-admin-password-file requires a path";
                return parsed;
            }
            parsed.bootstrap_admin_password_file = argv[++index];
            continue;
        }
        parsed.positional.push_back(argument);
    }
    if (parsed.bootstrap_admin_localpart.has_value() != parsed.bootstrap_admin_password_file.has_value())
    {
        parsed.error = "--bootstrap-admin and --bootstrap-admin-password-file must be used together";
    }
    return parsed;
}

[[nodiscard]] auto usage_error(std::string message) -> BootstrapConfigResult
{
    return reject_config(merovingian::bootstrap::ExitCode::usage_error, "arguments", std::move(message));
}

[[nodiscard]] auto build_config_from_positional(std::vector<std::string_view> const& positional)
    -> BootstrapConfigResult
{
    if (positional.empty())
    {
        // Try the system config file installed by the package manager before
        // falling back to compiled-in defaults (which fail validation and are
        // only useful for --dry-run inspection during development).
        auto constexpr system_config = std::string_view{MEROVINGIAN_SYSCONFDIR "/merovingian/merovingian.conf"};
        if (std::filesystem::exists(system_config))
        {
            return load_config_from_file(std::string{system_config});
        }
        auto const config = merovingian::config::Config{};
        return classify_config_findings({config, merovingian::config::validate(config)}, "defaults");
    }

    if (positional.size() == 2U && positional[0] == "--config")
    {
        return load_config_from_file(std::string{positional[1]});
    }

    return usage_error("usage: merovingian-server [--dry-run] [--debug] [--log-file <path>] [--config <path>] "
                       "[--bootstrap-admin <localpart> --bootstrap-admin-password-file <path>] "
                       "[--check-config <path>] [--plan-config-reload <current> <next>] [--help] [--version]");
}

[[nodiscard]] auto is_help_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 2 && (std::string_view{argv[1]} == "--help" || std::string_view{argv[1]} == "-h");
}

[[nodiscard]] auto is_version_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 2 && std::string_view{argv[1]} == "--version";
}

[[nodiscard]] auto is_check_config_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 3 && std::string_view{argv[1]} == "--check-config";
}

[[nodiscard]] auto is_plan_config_reload_request(int argc, char const* const* argv) noexcept -> bool
{
    return argc == 4 && std::string_view{argv[1]} == "--plan-config-reload";
}

auto print_help() -> void
{
    std::cout << "The Merovingian Matrix homeserver\n"
              << "\n"
              << "Usage:\n"
              << "  merovingian-server [--dry-run]\n"
              << "  merovingian-server [--dry-run] --config <path>\n"
              << "  merovingian-server [--config <path>] --bootstrap-admin <localpart> "
                 "--bootstrap-admin-password-file <path>\n"
              << "  merovingian-server --check-config <path>\n"
              << "  merovingian-server --plan-config-reload <current> <next>\n"
              << "  merovingian-server --help\n"
              << "  merovingian-server --version\n"
              << "\n"
              << "Configuration is validated before startup continues.\n"
              << "--dry-run validates and prints the startup summary without binding listeners.\n"
              << "--debug enables debug-level console diagnostics for request and room-flow triage.\n"
              << "--log-file <path> writes trace/debug diagnostics to the selected file.\n";
}

auto configure_logging(ParsedArgs const& args) -> void
{
    if (args.debug_logging)
    {
        merovingian::observability::SingleLog::instance().set_console_log_level(
            merovingian::observability::LogLevel::debug);
    }
    if (args.log_file.has_value())
    {
        merovingian::observability::SingleLog::instance().set_log_file_path(*args.log_file);
    }
}

auto trim_line_ending(std::string& value) -> void
{
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r'))
    {
        value.pop_back();
    }
}

[[nodiscard]] auto read_bootstrap_admin_password(std::string const& path) -> std::optional<std::string>
{
    auto input = std::ifstream{path};
    if (!input)
    {
        return std::nullopt;
    }

    auto password = std::string{};
    std::getline(input, password);
    trim_line_ending(password);
    return password.empty() ? std::optional<std::string>{} : std::optional<std::string>{std::move(password)};
}

auto print_version() -> void
{
    std::cout << "merovingian-server " << version << '\n';
}

auto log_config_findings(BootstrapConfigResult const& result) -> void
{
    for (auto const& finding : result.parsed.findings)
    {
        LOG_CRITICAL("Configuration rejected: " + finding.field + ": " + finding.message);
    }
}

auto check_config_file(std::string const& path) -> int
{
    auto const result = load_config_from_file(path);
    if (!result.parsed.findings.empty())
    {
        log_config_findings(result);
        return merovingian::bootstrap::to_int(result.failure_code);
    }

    std::cout << "Configuration check passed: " << path << '\n';
    return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
}

auto plan_config_reload(std::string const& current_path, std::string const& next_path) -> int
{
    auto const current = load_config_from_file(current_path);
    if (!current.parsed.findings.empty())
    {
        log_config_findings(current);
        return merovingian::bootstrap::to_int(current.failure_code);
    }

    auto const next = load_config_from_file(next_path);
    if (!next.parsed.findings.empty())
    {
        log_config_findings(next);
        return merovingian::bootstrap::to_int(next.failure_code);
    }

    auto const plan = merovingian::config::build_reload_plan(current.parsed.config, next.parsed.config);
    std::cout << merovingian::config::reload_plan_summary(plan) << '\n';
    if (!plan.has_changes())
    {
        std::cout << "Reload action: no changes" << '\n';
    }
    else if (plan.has_restart_required_changes())
    {
        std::cout << "Reload action: restart required" << '\n';
    }
    else
    {
        std::cout << "Reload action: reloadable" << '\n';
    }

    for (auto const& change : plan.changes())
    {
        std::cout << change.key << '=' << merovingian::config::reload_policy_name(change.policy) << '\n';
    }

    return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
}

auto log_startup_summary(BootstrapConfigResult const& result) -> void
{
    auto const& config = result.parsed.config;
    auto const hardening_self_check = merovingian::platform::run_startup_hardening_self_check();
    auto const runtime_database = merovingian::database::make_runtime_database_config(config);
    auto const runtime_federation = merovingian::federation::make_runtime_federation_config(config);
    auto const runtime_listeners = merovingian::net::make_runtime_listeners(config);
    auto const runtime_media = merovingian::media::make_runtime_media_config(config);

    LOG_INFO("Configuration validation passed");
    LOG_INFO("Configuration source: " + result.source);
    LOG_INFO("Server name: " + config.server().server_name);
    LOG_INFO("Public base URL: " + config.server().public_baseurl);
    LOG_INFO("Startup hardening checks: " + std::to_string(hardening_self_check.count()));
    for (auto const& check : hardening_self_check.checks())
    {
        auto const status_name = std::string{merovingian::platform::hardening_status_name(check.status)};
        auto const suffix = check.note.empty() ? std::string{} : (" note=" + check.note);
        if (check.status == merovingian::platform::HardeningStatus::alpha_exception)
        {
            LOG_WARNING("Hardening self-check: " + check.name + "=" + status_name + suffix);
        }
        else
        {
            LOG_INFO("Hardening self-check: " + check.name + "=" + status_name + suffix);
        }
    }
    LOG_INFO("Hardening readiness: production_ready=" +
             std::string{hardening_self_check.is_production_ready() ? "true" : "false"} +
             " alpha_ready=" + std::string{hardening_self_check.is_alpha_ready() ? "true" : "false"} +
             " production_blockers=" + std::to_string(hardening_self_check.production_blocker_count()));
    LOG_INFO(merovingian::database::database_summary(runtime_database));
    LOG_INFO(merovingian::federation::federation_summary(runtime_federation));
    LOG_INFO(merovingian::media::media_summary(runtime_media));
    LOG_INFO("Client listener: " + config.listeners().client.bind);
    LOG_INFO("Federation listener: " + config.listeners().federation.bind);
    LOG_INFO("Planned runtime listeners: " + std::to_string(runtime_listeners.count()));
    for (auto const& listener : runtime_listeners.plans())
    {
        LOG_INFO("Runtime listener planned: " + std::string{merovingian::net::listener_role_name(listener.role)} + " " +
                 listener.bind + " tls=" + std::string{listener.tls ? "true" : "false"});
    }
    LOG_INFO("Registration enabled: " + std::string{config.security().registration.enabled ? "true" : "false"});
    LOG_INFO("Federation enabled: " + std::string{config.security().federation.enabled ? "true" : "false"});
    LOG_INFO("Media upload limit: " + config.security().media.max_upload_size);
}

struct BindEndpoint final
{
    bool ok{false};
    std::string host{};
    std::uint16_t port{0U};
    std::string error{};
};

[[nodiscard]] auto parse_bind(std::string_view bind) -> BindEndpoint
{
    auto const separator = bind.rfind(':');
    if (separator == std::string_view::npos || separator == 0U || separator + 1U >= bind.size())
    {
        return {false, {}, 0U, "listener bind must be host:port"};
    }
    auto host = bind.substr(0U, separator);
    if (!host.empty() && host.front() == '[' && host.back() == ']')
    {
        host.remove_prefix(1U);
        host.remove_suffix(1U);
    }
    auto port = std::uint32_t{0U};
    for (auto const character : bind.substr(separator + 1U))
    {
        if (character < '0' || character > '9')
        {
            return {false, {}, 0U, "listener port must be numeric"};
        }
        auto const digit = static_cast<std::uint32_t>(character - '0');
        port = (port * 10U) + digit;
        if (port > 65535U)
        {
            return {false, {}, 0U, "listener port is out of range"};
        }
    }
    if (port == 0U)
    {
        return {false, {}, 0U, "listener port must be non-zero"};
    }
    return {true, std::string{host}, static_cast<std::uint16_t>(port), {}};
}

struct ListenerBinding final
{
    merovingian::net::ListenerRole role{merovingian::net::ListenerRole::client};
    merovingian::net::TcpAcceptor acceptor{};
    std::optional<merovingian::homeserver::TlsServerContext> tls_context{};
};

[[nodiscard]] auto open_listeners(merovingian::net::RuntimeListeners const& plans,
                                  std::vector<ListenerBinding>& bindings, std::string& error) -> bool
{
    for (auto const& plan : plans.plans())
    {
        auto tls_context = std::optional<merovingian::homeserver::TlsServerContext>{};
        if (plan.tls)
        {
            auto context_result =
                merovingian::homeserver::make_tls_server_context(plan.tls_certificate_file, plan.tls_private_key_file);
            if (!context_result.ok())
            {
                error = "Listener " + std::string{merovingian::net::listener_role_name(plan.role)} +
                        " failed to configure TLS: " + context_result.error;
                return false;
            }
            tls_context = std::move(context_result.context);
        }

        auto const endpoint = parse_bind(plan.bind);
        if (!endpoint.ok)
        {
            error = "Listener " + std::string{merovingian::net::listener_role_name(plan.role)} + " has invalid bind '" +
                    plan.bind + "': " + endpoint.error;
            return false;
        }

        auto binding = ListenerBinding{};
        binding.role = plan.role;
        binding.tls_context = std::move(tls_context);
        auto const bind_result = binding.acceptor.bind(endpoint.host, endpoint.port);
        if (!bind_result.ok)
        {
            error = "Listener " + std::string{merovingian::net::listener_role_name(plan.role)} + " failed to bind " +
                    plan.bind + ": " + bind_result.error;
            return false;
        }

        LOG_INFO("Listening: " + std::string{merovingian::net::listener_role_name(plan.role)} +
                 " bound=" + endpoint.host + ":" + std::to_string(binding.acceptor.bound_port()) +
                 " tls=" + std::string{plan.tls ? "true" : "false"});
        bindings.push_back(std::move(binding));
    }
    return true;
}

[[nodiscard]] auto serve_until_shutdown(merovingian::homeserver::ClientServerRuntime& runtime,
                                        std::vector<ListenerBinding>& bindings,
                                        merovingian::net::ShutdownSignal& shutdown)
    -> merovingian::homeserver::HttpServeStats
{
    auto stats = merovingian::homeserver::HttpServeStats{};
    // Main pool handles all non-sync request types. Keep this modest so that
    // threads aren't wasted â€” sync long-polls are offloaded to sync_pool below.
    auto pool = merovingian::net::ThreadPool{8U};
    // Dedicated pool for /sync long-polls. Each waiting sync client occupies one
    // thread here rather than in the main pool, so regular requests (join, send,
    // login, federation) are always serviced without delay.
    auto sync_pool = merovingian::net::ThreadPool{32U};
    auto threads = std::vector<std::thread>{};
    threads.reserve(bindings.size());

    for (auto& binding : bindings)
    {
        // Explicit init-capture binds `target` to bindings[i] directly rather
        // than to the per-iteration alias `binding`, which would dangle once
        // the loop advances.
        threads.emplace_back([&runtime, &shutdown, &stats, &pool, &sync_pool, &target = binding]() {
            auto const mode = target.role == merovingian::net::ListenerRole::client
                                  ? merovingian::homeserver::HttpDispatchMode::client_server
                                  : merovingian::homeserver::HttpDispatchMode::federation;
            if (target.tls_context.has_value())
            {
                merovingian::homeserver::serve_tls_http(*target.tls_context, target.acceptor, runtime, shutdown, stats,
                                                        mode, pool, &sync_pool);
            }
            else
            {
                merovingian::homeserver::serve_http(target.acceptor, runtime, shutdown, stats, mode, pool, &sync_pool);
            }
        });
    }

    // Block the main thread until shutdown fires. We do not poll a queue -
    // the signal handler writes to the self-pipe and any blocked poll(2) call
    // in the listener threads returns immediately.
    auto entry = pollfd{};
    entry.fd = shutdown.read_fd();
    entry.events = POLLIN;
    while (!shutdown.fired())
    {
        auto const poll_result = ::poll(&entry, 1U, -1);
        if (poll_result < 0 && errno != EINTR)
        {
            break;
        }
    }

    pool.request_stop();
    // Drain the sync pool after the main pool stops so no new long-polls can be
    // submitted, but in-flight waits finish before the runtime is torn down.
    sync_pool.request_stop();

    for (auto& worker : threads)
    {
        if (worker.joinable())
        {
            worker.join();
        }
    }

    return stats;
}

[[nodiscard]] auto run_server(BootstrapConfigResult const& result, ParsedArgs const& args) -> int
{
    // Fail closed when a hardening control is explicitly disabled. Documented
    // alpha exceptions are still permitted; production gating happens at
    // release-readiness time. See docs/hardening-alpha-exceptions.md.
    auto const hardening_self_check = merovingian::platform::run_startup_hardening_self_check();
    if (!hardening_self_check.is_alpha_ready())
    {
        LOG_CRITICAL("Startup refused: hardening self-check reports a disabled control");
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::runtime_start_error);
    }

    auto runtime_result = merovingian::homeserver::start_client_server(result.parsed.config);
    if (!runtime_result.started)
    {
        LOG_CRITICAL("Runtime failed to start: " + runtime_result.reason);
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::runtime_start_error);
    }

    if (args.bootstrap_admin_localpart.has_value() && args.bootstrap_admin_password_file.has_value())
    {
        auto password = read_bootstrap_admin_password(*args.bootstrap_admin_password_file);
        if (!password.has_value())
        {
            LOG_CRITICAL("Bootstrap admin password file is missing or empty");
            return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::runtime_start_error);
        }

        auto admin = merovingian::homeserver::bootstrap_admin_user(runtime_result.runtime.homeserver,
                                                                   *args.bootstrap_admin_localpart, *password);
        if (!admin.ok)
        {
            LOG_CRITICAL("Bootstrap admin creation failed: " + admin.reason);
            return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::runtime_start_error);
        }
        LOG_INFO("Bootstrap admin user created: " + admin.value);
    }

    auto const plans = merovingian::net::make_runtime_listeners(result.parsed.config);
    auto bindings = std::vector<ListenerBinding>{};
    auto bind_error = std::string{};
    if (!open_listeners(plans, bindings, bind_error))
    {
        LOG_CRITICAL("Listener setup failed: " + bind_error);
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::listener_error);
    }

    auto shutdown = merovingian::net::ShutdownSignal{};
    if (!shutdown.valid() || !merovingian::net::install_shutdown_signal_handlers(shutdown))
    {
        LOG_CRITICAL("Failed to install shutdown signal handlers");
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::listener_error);
    }

    LOG_INFO("Listeners active; awaiting traffic. Send SIGINT or SIGTERM to stop.");
    auto runtime = std::move(runtime_result.runtime);
    auto const stats = serve_until_shutdown(runtime, bindings, shutdown);

    merovingian::net::uninstall_shutdown_signal_handlers();
    LOG_INFO("Server stopped. accepted=" + std::to_string(stats.accepted_connections) + " completed=" +
             std::to_string(stats.completed_requests) + " rejected=" + std::to_string(stats.rejected_requests));
    return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
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

    if (is_check_config_request(argc, argv))
    {
        return check_config_file(argv[2]);
    }

    if (is_plan_config_reload_request(argc, argv))
    {
        return plan_config_reload(argv[2], argv[3]);
    }

    auto const args = parse_args(argc, argv);
    if (args.error.has_value())
    {
        auto const result = usage_error(*args.error);
        log_config_findings(result);
        return merovingian::bootstrap::to_int(result.failure_code);
    }

    configure_logging(args);
    LOG_INFO("Starting merovingian-server " + std::string{version});

    auto const result = build_config_from_positional(args.positional);
    if (!result.parsed.findings.empty())
    {
        log_config_findings(result);
        return merovingian::bootstrap::to_int(result.failure_code);
    }

    log_startup_summary(result);

    if (args.dry_run)
    {
        LOG_INFO("Dry run requested; skipping listener bind");
        return merovingian::bootstrap::to_int(merovingian::bootstrap::ExitCode::success);
    }

    return run_server(result, args);
}
