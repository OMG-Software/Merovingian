// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/temp_directory.hpp"
#include "merovingian/database/postgresql_store.hpp"
#include "merovingian/observability/logger.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <vector>

#include <sodium.h>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/un.h>
#endif

namespace
{

constexpr auto redacted_identity = std::string_view{"PostgreSQL [connection details redacted]"};
constexpr auto parser_reason = std::string_view{"invalid PostgreSQL connection options (details redacted)"};
constexpr auto backend_reason = std::string_view{"PostgreSQL connection failed (connection details redacted)"};

[[nodiscard]] auto random_component() -> std::string
{
    auto bytes = std::array<unsigned char, 16>{};
    randombytes_buf(bytes.data(), bytes.size());
    constexpr auto digits = std::string_view{"0123456789abcdef"};
    auto result = std::string{};
    result.reserve(bytes.size() * 2U);
    for (auto const byte : bytes)
    {
        result.push_back(digits[byte >> 4U]);
        result.push_back(digits[byte & 0x0fU]);
    }
    return result;
}

[[nodiscard]] auto percent_encode(std::string_view value) -> std::string
{
    constexpr auto digits = std::string_view{"0123456789ABCDEF"};
    auto result = std::string{};
    for (auto const character : value)
    {
        auto const byte = static_cast<unsigned char>(character);
        if ((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') || (byte >= '0' && byte <= '9') ||
            byte == '-' || byte == '_' || byte == '.' || byte == '~')
        {
            result.push_back(character);
        }
        else
        {
            result.push_back('%');
            result.push_back(digits[byte >> 4U]);
            result.push_back(digits[byte & 0x0fU]);
        }
    }
    return result;
}

[[nodiscard]] auto escape_conninfo_value(std::string_view value, bool quoted) -> std::string
{
    auto result = std::string{};
    for (auto const character : value)
    {
        if (character == '\\' || character == '\'' ||
            (!quoted && (character == ' ' || character == '\t' || character == '\r' || character == '\n')))
        {
            result.push_back('\\');
        }
        result.push_back(character);
    }
    return result;
}

[[nodiscard]] auto quote_conninfo_value(std::string_view value) -> std::string
{
    return "'" + escape_conninfo_value(value, true) + "'";
}

struct RuntimeMarker final
{
    // Independent, whitespace-separated components also catch partial leaks
    // after token-based log redaction. Nothing in this object is ever printed.
    std::string first{random_component()};
    std::string second{random_component()};
    std::string complete{first + " " + second + " ' \\"};
    std::string encoded{percent_encode(complete)};
    std::string quoted{quote_conninfo_value(complete)};
    std::string escaped{escape_conninfo_value(complete, false)};

    [[nodiscard]] auto absent_from(std::string_view text) const -> bool
    {
        return text.find(first) == std::string_view::npos && text.find(second) == std::string_view::npos &&
               text.find(complete) == std::string_view::npos && text.find(encoded) == std::string_view::npos &&
               text.find(quoted) == std::string_view::npos && text.find(escaped) == std::string_view::npos;
    }
};

// Process-global environment and stdout require the default serialized Catch2
// execution model. These scenarios start no threads and no singleton writers.
// Clear destination, service, credential, transport/security and session defaults
// before validating or opening; explicit conninfo supplies the missing socket,
// password, user, database, passfile and a bounded connect timeout.
constexpr auto libpq_environment_names = std::array{std::string_view{"PGSERVICE"},
                                                    std::string_view{"PGSERVICEFILE"},
                                                    std::string_view{"PGSYSCONFDIR"},
                                                    std::string_view{"PGHOST"},
                                                    std::string_view{"PGHOSTADDR"},
                                                    std::string_view{"PGPORT"},
                                                    std::string_view{"PGDATABASE"},
                                                    std::string_view{"PGUSER"},
                                                    std::string_view{"PGPASSWORD"},
                                                    std::string_view{"PGPASSFILE"},
                                                    std::string_view{"PGCONNECT_TIMEOUT"},
                                                    std::string_view{"PGOPTIONS"},
                                                    std::string_view{"PGAPPNAME"},
                                                    std::string_view{"PGCLIENTENCODING"},
                                                    std::string_view{"PGSSLMODE"},
                                                    std::string_view{"PGREQUIRESSL"},
                                                    std::string_view{"PGSSLCERT"},
                                                    std::string_view{"PGSSLKEY"},
                                                    std::string_view{"PGSSLPASSWORD"},
                                                    std::string_view{"PGSSLROOTCERT"},
                                                    std::string_view{"PGSSLCRL"},
                                                    std::string_view{"PGSSLCRLDIR"},
                                                    std::string_view{"PGSSLSNI"},
                                                    std::string_view{"PGSSLCERTMODE"},
                                                    std::string_view{"PGSSLNEGOTIATION"},
                                                    std::string_view{"PGSSL_MIN_PROTOCOL_VERSION"},
                                                    std::string_view{"PGSSL_MAX_PROTOCOL_VERSION"},
                                                    std::string_view{"PGGSSENCMODE"},
                                                    std::string_view{"PGKRBSRVNAME"},
                                                    std::string_view{"PGGSSLIB"},
                                                    std::string_view{"PGCHANNELBINDING"},
                                                    std::string_view{"PGREQUIREPEER"},
                                                    std::string_view{"PGREQUIREAUTH"},
                                                    std::string_view{"PGTARGETSESSIONATTRS"},
                                                    std::string_view{"PGLOADBALANCEHOSTS"},
                                                    std::string_view{"PGKEEPALIVES"},
                                                    std::string_view{"PGKEEPALIVES_IDLE"},
                                                    std::string_view{"PGKEEPALIVES_INTERVAL"},
                                                    std::string_view{"PGKEEPALIVES_COUNT"},
                                                    std::string_view{"PGTCPUSER_TIMEOUT"}};
using EnvironmentSnapshot = std::array<std::optional<std::string>, libpq_environment_names.size()>;

[[nodiscard]] auto snapshot_environment() -> EnvironmentSnapshot
{
    auto result = EnvironmentSnapshot{};
    for (auto index = std::size_t{0U}; index < libpq_environment_names.size(); ++index)
    {
        // Names are complete string literals; copy getenv's borrowed storage
        // before any mutation. Never report inherited values or keep borrowed storage.
        if (auto const* value = std::getenv(libpq_environment_names[index].data()); value != nullptr)
        {
            result[index] = std::string{value};
        }
    }
    return result;
}

[[nodiscard]] auto set_environment(std::string_view name, std::optional<std::string> const& value) noexcept -> bool
{
#ifdef _WIN32
    return ::_putenv_s(name.data(), value.has_value() ? value->c_str() : "") == 0;
#else
    return value.has_value() ? ::setenv(name.data(), value->c_str(), 1) == 0 : ::unsetenv(name.data()) == 0;
#endif
}

class ScopedLibpqEnvironment final
{
public:
    ScopedLibpqEnvironment()
        : previous_{snapshot_environment()}
    {
        // All allocations/copies finish before the first process-global change.
        for (auto index = std::size_t{0U}; index < libpq_environment_names.size(); ++index)
        {
#ifdef _WIN32
            // The CRT cannot recreate present-but-empty entries with _putenv_s:
            // its empty value removes the entry. Leave such neutral defaults
            // untouched so their exact presence is preserved on restoration.
            if (previous_[index].has_value() && previous_[index]->empty())
            {
                continue;
            }
#endif
            auto const changed = set_environment(libpq_environment_names[index], std::nullopt);
            applied_ = changed && applied_;
        }
    }
    ~ScopedLibpqEnvironment() noexcept
    {
        for (auto index = std::size_t{0U}; index < libpq_environment_names.size(); ++index)
        {
#ifdef _WIN32
            if (previous_[index].has_value() && previous_[index]->empty())
            {
                continue;
            }
#endif
            std::ignore = set_environment(libpq_environment_names[index], previous_[index]);
        }
    }
    ScopedLibpqEnvironment(ScopedLibpqEnvironment const&) = delete;
    auto operator=(ScopedLibpqEnvironment const&) -> ScopedLibpqEnvironment& = delete;
    ScopedLibpqEnvironment(ScopedLibpqEnvironment&&) = delete;
    auto operator=(ScopedLibpqEnvironment&&) -> ScopedLibpqEnvironment& = delete;

    [[nodiscard]] auto applied() const noexcept -> bool
    {
        return applied_;
    }

private:
    EnvironmentSnapshot previous_;
    bool applied_{true};
};

class PostgresqlDebugCapture final
{
public:
    PostgresqlDebugCapture()
        : logger_{merovingian::observability::SingleLog::instance()}
    {
        auto& logger = logger_.get();
        auto const synchronous = !logger.writers_started();
        auto const buffer_available = std::cout.rdbuf() != nullptr;
        REQUIRE(synchronous);
        REQUIRE(buffer_available);
        // The allocating module exchange precedes the no-throw threshold and
        // buffer exchanges. Restore absent overrides as absent, not as defaults.
        previous_module_level_ = logger.exchange_module_log_level(module_, merovingian::observability::LogLevel::debug);
        previous_console_level_ = logger.exchange_console_log_level(merovingian::observability::LogLevel::debug);
        previous_buffer_ = std::ref(*std::cout.rdbuf(output_.rdbuf()));
    }
    ~PostgresqlDebugCapture()
    {
        std::cout.rdbuf(&previous_buffer_->get());
        auto& logger = logger_.get();
        std::ignore = logger.exchange_console_log_level(previous_console_level_);
        std::ignore = logger.exchange_module_log_level(module_, previous_module_level_);
    }
    PostgresqlDebugCapture(PostgresqlDebugCapture const&) = delete;
    auto operator=(PostgresqlDebugCapture const&) -> PostgresqlDebugCapture& = delete;
    PostgresqlDebugCapture(PostgresqlDebugCapture&&) = delete;
    auto operator=(PostgresqlDebugCapture&&) -> PostgresqlDebugCapture& = delete;

    [[nodiscard]] auto text() const -> std::string
    {
        return output_.str();
    }

private:
    std::reference_wrapper<merovingian::observability::SingleLog> logger_;
    std::ostringstream output_{};
    std::string module_{"postgresql_store"};
    std::optional<std::reference_wrapper<std::streambuf>> previous_buffer_{};
    std::optional<merovingian::observability::LogLevel> previous_module_level_{};
    merovingian::observability::LogLevel previous_console_level_{};
};

struct DiagnosticObservation final
{
    bool failed{false};
    bool closed{false};
    bool expected_reason{false};
    bool expected_identity{false};
    bool opening_emitted{false};
    bool rejection_emitted{false};
    bool ready_not_emitted{false};
    bool reason_confidential{false};
    bool identity_confidential{false};
    bool records_confidential{false};
};

[[nodiscard]] auto observe_open(std::string_view conninfo, RuntimeMarker const& marker,
                                std::string_view expected_reason) -> DiagnosticObservation
{
    auto opened = merovingian::database::PostgresqlConnectionOpenResult{};
    auto records = std::string{};
    {
        // Capture only the real opener's synchronous console output. There are
        // no callbacks, replacement parsers, fabricated records or assertions
        // while stdout is redirected (constructor preconditions precede it).
        auto const capture = PostgresqlDebugCapture{};
        opened = merovingian::database::open_postgresql_connection(conninfo);
        records = capture.text();
    }
    // Buffer and exact logger policy are restored before evaluating results.
    return {!opened.ok,
            !opened.connection.open(),
            opened.reason == expected_reason,
            opened.redacted_conninfo == redacted_identity,
            records.find("<DEBUG>  postgresql_store:  event=connection.opening ") != std::string::npos,
            records.find("<DEBUG>  postgresql_store:  event=connection.rejected ") != std::string::npos,
            records.find("event=connection.ready") == std::string::npos,
            marker.absent_from(opened.reason),
            marker.absent_from(opened.redacted_conninfo),
            marker.absent_from(records)};
}

// Only booleans reach Catch2 expression decomposition, including failure paths.
auto check_observation(DiagnosticObservation const& observation) -> void
{
    CHECK(observation.failed);
    CHECK(observation.closed);
    CHECK(observation.expected_reason);
    CHECK(observation.expected_identity);
    CHECK(observation.opening_emitted);
    CHECK(observation.rejection_emitted);
    CHECK(observation.ready_not_emitted);
    CHECK(observation.reason_confidential);
    CHECK(observation.identity_confidential);
    CHECK(observation.records_confidential);
}

#ifndef _WIN32
[[nodiscard]] auto missing_path(std::filesystem::path const& path) -> bool
{
    auto error = std::error_code{};
    auto const status = std::filesystem::symlink_status(path, error);
    return status.type() == std::filesystem::file_type::not_found &&
           (!error || error == std::errc::no_such_file_or_directory);
}

class OwnedSocketParent final
{
public:
    OwnedSocketParent()
        : parent_{std::filesystem::absolute(merovingian::tests::temporary_directory()) /
                  ("m-db9-" + random_component().substr(0U, 16U))}
        , missing_child_{parent_ / "absent"}
    {
        // mkdir creates the parent private from its first instant, independent
        // of the ambient umask. A collision is not owned and is never removed.
        owned_ = ::mkdir(parent_.c_str(), S_IRWXU) == 0;
        if (!owned_)
        {
            return;
        }
        auto error = std::error_code{};
        std::filesystem::permissions(parent_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace,
                                     error);
        if (error)
        {
            return;
        }
        auto const permissions = std::filesystem::status(parent_, error).permissions();
        ready_ = !error && permissions == std::filesystem::perms::owner_all && missing_path(missing_child_);
        // The child is deliberately never created. No listener or SQL traffic
        // can be reached through a socket beneath this owned, private parent.
    }
    ~OwnedSocketParent() noexcept
    {
        if (owned_)
        {
            auto error = std::error_code{};
            std::ignore = std::filesystem::remove_all(parent_, error);
        }
    }
    OwnedSocketParent(OwnedSocketParent const&) = delete;
    auto operator=(OwnedSocketParent const&) -> OwnedSocketParent& = delete;
    OwnedSocketParent(OwnedSocketParent&&) = delete;
    auto operator=(OwnedSocketParent&&) -> OwnedSocketParent& = delete;

    [[nodiscard]] auto ready() const noexcept -> bool
    {
        return ready_;
    }
    [[nodiscard]] auto parent() const noexcept -> std::filesystem::path const&
    {
        return parent_;
    }
    [[nodiscard]] auto missing_child() const noexcept -> std::filesystem::path const&
    {
        return missing_child_;
    }

private:
    std::filesystem::path parent_;
    std::filesystem::path missing_child_;
    bool owned_{false};
    bool ready_{false};
};
#endif

} // namespace

SCENARIO("PostgreSQL malformed quoted options keep real DEBUG diagnostics confidential", "[database][db9-diagnostics]")
{
    GIVEN("runtime-only password components and malformed quoted options")
    {
        auto const sodium_ready = sodium_init() >= 0;
        REQUIRE(sodium_ready);
        auto const marker = RuntimeMarker{};
        auto const before = snapshot_environment();
        auto const buffer_available = std::cout.rdbuf() != nullptr;
        REQUIRE(buffer_available);
        auto const original_buffer = std::ref(*std::cout.rdbuf());

        WHEN("the real opener rejects options that the real libpq parser cannot parse")
        {
            auto observation = DiagnosticObservation{};
            {
                auto const environment = ScopedLibpqEnvironment{};
                auto const isolated = environment.applied();
                REQUIRE(isolated);
                // This healthy control is policy-only: it is never opened.
                auto const base = std::string{"host='/db9-policy-only' port=5432 user=db9_user dbname=db9_database "
                                              "sslmode=disable connect_timeout=2 password="} +
                                  marker.quoted;
                auto const healthy = merovingian::database::validate_postgresql_conninfo(
                    base + " options=" + quote_conninfo_value(marker.complete));
                auto const healthy_admitted = healthy.allowed && healthy.reason.empty();
                REQUIRE(healthy_admitted);
                auto const malformed = base + " options='" + escape_conninfo_value(marker.complete, true);
                auto const policy = merovingian::database::validate_postgresql_conninfo(malformed);
                auto const parser_rejected = !policy.allowed && policy.reason == parser_reason;
                // Fail before the opener if parser rejection is not established;
                // no valid connection string is opened in this scenario.
                REQUIRE(parser_rejected);
                observation = observe_open(malformed, marker, parser_reason);
            }
            auto const environment_restored = snapshot_environment() == before;
            auto const stdout_restored = std::cout.rdbuf() == &original_buffer.get();

            THEN("opening and parser rejection records are emitted without whole or partial credentials")
            {
                check_observation(observation);
                CHECK(environment_restored);
                CHECK(stdout_restored);
            }
        }
    }
}

SCENARIO("PostgreSQL admitted connection failures keep real DEBUG diagnostics confidential",
         "[database][db9-diagnostics]")
{
#ifdef _WIN32
    SKIP("This socket-only failure scenario requires a private UNIX socket parent and a never-created child; "
         "no TCP or ambient PostgreSQL fallback is permitted on Windows.");
#else
    GIVEN("a private owned temporary parent with a never-created socket child and isolated libpq defaults")
    {
        auto const sodium_ready = sodium_init() >= 0;
        REQUIRE(sodium_ready);
        auto const marker = RuntimeMarker{};
        auto const before = snapshot_environment();
        auto const buffer_available = std::cout.rdbuf() != nullptr;
        REQUIRE(buffer_available);
        auto const original_buffer = std::ref(*std::cout.rdbuf());

        WHEN("quoted escaped spaced and URI credentials reach the real libpq connection-status failure branch")
        {
            auto observations = std::vector<DiagnosticObservation>{};
            auto owned_parent = std::filesystem::path{};
            auto child_stayed_missing = true;
            {
                auto const socket_parent = OwnedSocketParent{};
                auto const private_parent_ready = socket_parent.ready();
                REQUIRE(private_parent_ready);
                owned_parent = socket_parent.parent();
                auto const socket_path = socket_parent.missing_child().generic_string();
                auto const passfile = (socket_parent.missing_child() / "passfile").generic_string();
                auto const unix_address = sockaddr_un{};
                auto const socket_path_fits = (socket_path + "/.s.PGSQL.5432").size() < sizeof(unix_address.sun_path);
                // A too-long TMPDIR must fail setup, not masquerade as the
                // intended missing-socket connect failure. The build wrapper
                // supplies Linux-native scratch through temporary_directory().
                REQUIRE(socket_path_fits);
                auto const environment = ScopedLibpqEnvironment{};
                auto const isolated = environment.applied();
                REQUIRE(isolated);
                auto const base = "host=" + quote_conninfo_value(socket_path) +
                                  " port=5432 user=db9_user dbname=db9_database connect_timeout=2 "
                                  "sslmode=disable gssencmode=disable channel_binding=disable target_session_attrs=any "
                                  "passfile=" +
                                  quote_conninfo_value(passfile) + " ";
                auto const samples = std::array{
                    base + "password=" + marker.quoted, base + "password = " + marker.quoted,
                    base + "password = " + marker.escaped,
                    "postgresql://db9_user:" + marker.encoded + "@/db9_database?host=" + percent_encode(socket_path) +
                        "&port=5432&connect_timeout=2&sslmode=disable&gssencmode=disable&channel_binding=disable"
                        "&target_session_attrs=any&passfile=" +
                        percent_encode(passfile)};
                observations.reserve(samples.size());
                // Admit every healthy form before any capture/open. This control
                // separates backend failures from policy/parser rejections.
                for (auto const& sample : samples)
                {
                    auto const policy = merovingian::database::validate_postgresql_conninfo(sample);
                    auto const healthy_admitted = policy.allowed && policy.reason.empty();
                    REQUIRE(healthy_admitted);
                }
                for (auto const& sample : samples)
                {
                    auto const missing_before_open = missing_path(socket_parent.missing_child());
                    REQUIRE(missing_before_open);
                    observations.push_back(observe_open(sample, marker, backend_reason));
                    child_stayed_missing = missing_path(socket_parent.missing_child()) && child_stayed_missing;
                }
            }
            // All global state and owned filesystem state are restored before
            // any result assertions can write Catch2 failure diagnostics.
            auto const environment_restored = snapshot_environment() == before;
            auto const stdout_restored = std::cout.rdbuf() == &original_buffer.get();
            auto const parent_removed = missing_path(owned_parent);
            auto const complete_matrix = observations.size() == 4U;

            THEN("all admitted forms emit opening and generic backend rejection without credential fragments")
            {
                REQUIRE(complete_matrix);
                for (auto const& observation : observations)
                {
                    check_observation(observation);
                }
                CHECK(child_stayed_missing);
                CHECK(parent_removed);
                CHECK(environment_restored);
                CHECK(stdout_restored);
            }
        }
    }
#endif
}
